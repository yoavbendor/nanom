// SPDX-License-Identifier: Apache-2.0
#pragma once

// nanom_shark/protocol.hpp — the ergonomics core (Phase 2).
//
// Adding a protocol to nanom_shark used to cost ~8 edit points across 5 library headers. It now
// costs ONE new file and ZERO edits to any library header:
//
//   struct FooProto {
//     using trigger = udp_port<1234>;                             // when does it fire? (see B)
//     using state   = no_state;                                   // per-decode mutable state
//     static constexpr auto tables = table_spec<table_decl<"foo", FooRow>>{};   // named outputs
//     static void parse(const decode_ctx& c, nanom::seg_input in, no_state&, auto& t, PacketJson* j);
//   };
//   using my_decoder = decoder<CoreL2L3, Someip, Gptp, Lldp, FooProto>;   // the type list IS the registry
//
// Everything here is COMPILE-TIME ONLY: no type erasure, no virtual calls, no runtime registry.
// `dispatch<L, Decoder>` is a fold over the protocol type list that the compiler unrolls into the
// same if-chain the hand-written code used to be, so the benchmarked hot path is unaffected.
//
// Four pieces:
//   A. decode_ctx  — everything a trigger can match on, INCLUDING byte offsets (which is what
//                    retires decode_pass.hpp's hand-recomputed `14 + 4*vlan_count` in five places).
//   B. triggers    — composable compile-time predicates; `udp_port_cfg<&DecodeOptions::x>` late-binds
//                    only the port VALUES to a runtime DecodeOptions, never the type list.
//   C. tables      — table_decl<"name", Row> / table_spec<...> / tables_of<decoder<...>>, with
//                    compile-time name lookup `t.get<"name">()` and generic `for_each_table`.
//   D. dispatch    — ONE fold, used by both the normal per-packet walk and the reassembled-datagram
//                    re-entry, so those two paths are structurally incapable of disagreeing.

#include <nanom_shark/decode_options.hpp>
#include <nanom_shark/json_tree.hpp>
#include <nanom_shark/node_row.hpp>

#include <nanom_shark/protocols.hpp>  // nmproto::{kIpProtoTcp,kIpProtoUdp}

#include <nanom/nanom.hpp>

#include <algorithm>
#include <concepts>
#include <cstdint>
#include <string_view>
#include <type_traits>

namespace nanom_shark {

// ---------------------------------------------------------------------------
// A. decode_ctx — the decoded context a trigger matches against
// ---------------------------------------------------------------------------

/// Where in the packet a dispatch is happening. Used to prune the protocol fold at COMPILE time:
/// a trigger that can only ever match after Ethernet (an ethertype) is not even instantiated at the
/// L4 dispatch point, and vice versa. See `trigger_applies` below.
enum class layer : std::uint8_t {
  eth_payload,  ///< right after Ethernet + any VLAN tags (gPTP, LLDP, ...)
  l4_payload,   ///< right after the TCP/UDP header (SOME/IP, ...)
};

/// Everything the walk has decoded about the packet at the point of a dispatch. Replaces
/// PacketVisitor's ad-hoc bookkeeping members: the byte OFFSETS are carried natively here rather
/// than each call site re-deriving `14` / `14 + 4*vlan_count` from decoded values.
struct decode_ctx {
  const DecodeOptions* opts = nullptr;  ///< the runtime config `udp_port_cfg<>` consults

  packet_id_t   packet_id      = kNoPacket;
  std::uint32_t datagram_id    = 0;      ///< non-zero only on the reassembled-datagram path
  bool          is_reassembled = false;

  std::uint16_t link_type  = 0;
  std::uint16_t ethertype  = 0;  ///< the INNERMOST ethertype (past every VLAN tag)
  std::uint8_t  ip_version = 0;  ///< 0 until an IP header is seen, then 4 or 6
  std::uint8_t  ip_proto   = 0;  ///< 0 until L3 is done, then the IP protocol number
  std::uint16_t src_port   = 0;  ///< valid once ip_proto is TCP/UDP
  std::uint16_t dst_port   = 0;

  /// The whole captured packet, and byte offsets INTO it. Empty (and the offsets meaningless) on
  /// the reassembled-datagram path, which has no single contiguous packet -- `is_reassembled` says
  /// which world you are in; anything matching at `layer::eth_payload` is always in this one.
  nanom::bytes  pkt{};
  std::uint32_t vlan_count = 0;
  std::size_t   l2_end     = 0;  ///< first byte after Ethernet + VLAN tags (== the L3 header offset)
  std::size_t   l3_end     = 0;  ///< first byte after IP (+ IPv6 ext headers) == the L4 header offset
  std::size_t   l4_end     = 0;  ///< first byte after the TCP/UDP header == the L4 payload offset

  /// The bytes a `layer::eth_payload` protocol was handed, as a contiguous span.
  [[nodiscard]] nanom::bytes eth_payload_bytes() const {
    return l2_end <= pkt.size() ? pkt.subspan(l2_end, pkt.size() - l2_end) : nanom::bytes{};
  }
};

// ---------------------------------------------------------------------------
// B. the trigger DSL — composable, compile-time predicates
// ---------------------------------------------------------------------------
//
// Every trigger exposes `static constexpr bool match(const decode_ctx&)`. Where the matched value
// is a compile-time constant this is literally the same `==` the old hand-written if-chain emitted
// -- no loop, no lookup, no indirection.
//
// A trigger MAY also expose `static constexpr bool applies(layer)`; when it does, `dispatch` uses
// it to drop the protocol from the fold entirely at that dispatch point (`if constexpr`). Omitting
// it means "could match anywhere", which is always correct, just not pruned.

/// Matches the innermost ethertype. gPTP is `ethertype<0x88F7>`, LLDP `ethertype<0x88CC>`.
template <std::uint16_t E>
struct ethertype {
  static constexpr bool match(const decode_ctx& c) noexcept { return c.ethertype == E; }
  static constexpr bool applies(layer l) noexcept { return l == layer::eth_payload; }
};

/// Matches the IP protocol number (17 = UDP, 6 = TCP, ...).
template <std::uint8_t P>
struct ip_proto {
  static constexpr bool match(const decode_ctx& c) noexcept { return c.ip_proto == P; }
  static constexpr bool applies(layer l) noexcept { return l == layer::l4_payload; }
};

/// Matches the pcap link type (1 = Ethernet).
template <std::uint16_t L>
struct link_type {
  static constexpr bool match(const decode_ctx& c) noexcept { return c.link_type == L; }
};

/// Matches if EITHER the UDP source or destination port is ANY of `Ports`. Compile-time constant
/// ports, so this collapses to a chain of `==`.
template <std::uint16_t... Ports>
struct udp_port {
  static_assert(sizeof...(Ports) > 0, "nanom_shark: udp_port<> needs at least one port");
  static constexpr bool match(const decode_ctx& c) noexcept {
    return c.ip_proto == nmproto::kIpProtoUdp &&
           (... || (c.src_port == Ports || c.dst_port == Ports));
  }
  static constexpr bool applies(layer l) noexcept { return l == layer::l4_payload; }
};

/// Same, for TCP.
template <std::uint16_t... Ports>
struct tcp_port {
  static_assert(sizeof...(Ports) > 0, "nanom_shark: tcp_port<> needs at least one port");
  static constexpr bool match(const decode_ctx& c) noexcept {
    return c.ip_proto == nmproto::kIpProtoTcp &&
           (... || (c.src_port == Ports || c.dst_port == Ports));
  }
  static constexpr bool applies(layer l) noexcept { return l == layer::l4_payload; }
};

/// True if `a` or `b` appears in the runtime port list `v`. The one place a configured port set is
/// tested, shared by `udp_port_cfg`'s trigger and by protocols that consult a second list for a
/// mode flag (SOME/IP's `someip_tlv_ports`).
inline bool port_in(const std::vector<std::uint16_t>& v, std::uint16_t a, std::uint16_t b) noexcept {
  return std::find(v.begin(), v.end(), a) != v.end() || std::find(v.begin(), v.end(), b) != v.end();
}

/// THE runtime-configurable-port trigger, and the reason it does not need a runtime registry.
///
/// SOME/IP has no ethertype and no magic number -- it is plain bytes on a UDP port agreed
/// out-of-band, so the port set is inherently runtime (`DecodeOptions::someip_ports`). `MemPtr` is
/// a COMPILE-TIME pointer-to-member naming *which* runtime vector to consult, so the protocol type
/// list stays fully unrolled with zero indirection; only the port VALUES are late-bound, read off
/// the `DecodeOptions` instance the decode pass was given. This is exactly the `std::find` the old
/// code copy-pasted into two call sites, written once.
template <auto MemPtr>
struct udp_port_cfg {
  static bool match(const decode_ctx& c) noexcept {
    if (c.ip_proto != nmproto::kIpProtoUdp || c.opts == nullptr) return false;
    return port_in(c.opts->*MemPtr, c.src_port, c.dst_port);
  }
  static constexpr bool applies(layer l) noexcept { return l == layer::l4_payload; }
};

/// Matches a `bool` member of DecodeOptions (`opt_enabled<&DecodeOptions::decode_defrag>`).
template <auto MemPtr>
struct opt_enabled {
  static bool match(const decode_ctx& c) noexcept { return c.opts != nullptr && c.opts->*MemPtr; }
};

/// Never fires. The trigger for a "protocol" that only exists to declare tables the core walk
/// fills in itself (see core_protocols.hpp's CoreL2L3).
struct never {
  static constexpr bool match(const decode_ctx&) noexcept { return false; }
  static constexpr bool applies(layer) noexcept { return false; }
};

/// Always fires (at every dispatch point). Useful for a tap/statistics protocol.
struct always {
  static constexpr bool match(const decode_ctx&) noexcept { return true; }
};

namespace detail {
// `applies` is optional on a user trigger; absent means "could match at any dispatch point".
template <class T>
constexpr bool trigger_applies(layer l) noexcept {
  if constexpr (requires {
                  { T::applies(l) } -> std::same_as<bool>;
                }) {
    return T::applies(l);
  } else {
    return true;
  }
}
}  // namespace detail

template <class... T>
struct all_of {
  static constexpr bool match(const decode_ctx& c) noexcept { return (... && T::match(c)); }
  static constexpr bool applies(layer l) noexcept { return (... && detail::trigger_applies<T>(l)); }
};

template <class... T>
struct any_of {
  static constexpr bool match(const decode_ctx& c) noexcept { return (... || T::match(c)); }
  static constexpr bool applies(layer l) noexcept { return (... || detail::trigger_applies<T>(l)); }
};

template <class T>
struct not_ {
  static constexpr bool match(const decode_ctx& c) noexcept { return !T::match(c); }
  // A negation can be true anywhere, so it deliberately does NOT narrow the dispatch points.
};

// ---------------------------------------------------------------------------
// C. tables derived from the type list
// ---------------------------------------------------------------------------

/// One named output table. `Chunk` is the soa chunk size (columnar block granularity); it only
/// matters for sinks that write one block per chunk, and defaults to node_table's own default.
template <nanom::fixed_string Name, class Row, std::size_t Chunk = 65536>
struct table_decl {
  using row_type = Row;
  static constexpr auto        table_name  = Name;
  static constexpr std::size_t chunk_rows  = Chunk;
};

/// A protocol's declared tables. Variadic, so one protocol can declare many (gPTP declares nine).
template <class... Decls>
struct table_spec {
  static constexpr std::size_t size = sizeof...(Decls);
};

namespace detail {

template <class T>            struct is_table_spec                    : std::false_type {};
template <class... D>         struct is_table_spec<table_spec<D...>>  : std::true_type {};

template <nanom::fixed_string A, nanom::fixed_string B>
inline constexpr bool same_name_v = (A.sv() == B.sv());

// concatenate every protocol's table_spec into one
template <class Acc, class... Rest>
struct cat_specs {
  using type = Acc;
};
template <class... A, class... B, class... Rest>
struct cat_specs<table_spec<A...>, table_spec<B...>, Rest...>
    : cat_specs<table_spec<A..., B...>, Rest...> {};

// compile-time name -> table_decl lookup
template <nanom::fixed_string N, class... Ds>
struct find_decl {
  using type = void;  // not found
};
template <nanom::fixed_string N, class D0, class... Rest>
struct find_decl<N, D0, Rest...> {
  using type = std::conditional_t<same_name_v<N, D0::table_name>, D0,
                                  typename find_decl<N, Rest...>::type>;
};

// one storage slot per declared table; the Decl type is the key, so two protocols declaring
// different tables of the SAME Row type get separate slots.
template <class Decl>
struct table_slot;
template <nanom::fixed_string Name, class Row, std::size_t Chunk>
struct table_slot<table_decl<Name, Row, Chunk>> {
  node_table<Row> slot_{Name.sv(), Chunk};
};

template <class... Ds>
inline constexpr bool names_unique_v = [] {
  // O(n^2) over a handful of names, at compile time.
  constexpr std::size_t n = sizeof...(Ds);
  if constexpr (n < 2) {
    return true;
  } else {
    const std::string_view names[n] = {Ds::table_name.sv()...};
    for (std::size_t i = 0; i < n; ++i)
      for (std::size_t j = i + 1; j < n; ++j)
        if (names[i] == names[j]) return false;
    return true;
  }
}();

}  // namespace detail

template <class T>
concept TableSpec = detail::is_table_spec<std::remove_cvref_t<T>>::value;

/// The aggregate of every table declared by every registered protocol. Replaces the hand-written
/// `AllTables` struct: `t.get<"eth">()` is a compile-time lookup, and `for_each_table` is the
/// generic iteration the old struct could not offer (which is what Phase 3's generic sinks need).
template <class Spec>
class table_set;

template <class... Decls>
class table_set<table_spec<Decls...>> : private detail::table_slot<Decls>... {
  static_assert(detail::names_unique_v<Decls...>,
                "nanom_shark: two protocols registered in the same decoder<...> declare tables with "
                "the same name -- table names must be unique across the whole decoder");

 public:
  using spec = table_spec<Decls...>;
  static constexpr std::size_t table_count = sizeof...(Decls);

  template <nanom::fixed_string Name>
  [[nodiscard]] constexpr auto& get() noexcept {
    using D = typename detail::find_decl<Name, Decls...>::type;
    static_assert(!std::is_void_v<D>,
                  "nanom_shark: table_set::get<\"...\">() -- no table with that name is declared by "
                  "any protocol registered in this decoder<...>");
    return static_cast<detail::table_slot<D>&>(*this).slot_;
  }
  template <nanom::fixed_string Name>
  [[nodiscard]] constexpr const auto& get() const noexcept {
    using D = typename detail::find_decl<Name, Decls...>::type;
    static_assert(!std::is_void_v<D>,
                  "nanom_shark: table_set::get<\"...\">() -- no table with that name is declared by "
                  "any protocol registered in this decoder<...>");
    return static_cast<const detail::table_slot<D>&>(*this).slot_;
  }

  /// Calls `f(std::string_view name, const nm::soa<Row>&)` once per declared table, in declaration
  /// order (i.e. decoder<> type-list order). This is what makes a sink generic.
  template <class F>
  void for_each_table(F&& f) const {
    (f(Decls::table_name.sv(),
       static_cast<const detail::table_slot<Decls>&>(*this).slot_.soa()),
     ...);
  }
};

// ---------------------------------------------------------------------------
// the Protocol concept
// ---------------------------------------------------------------------------

/// What a protocol type must declare. `state` is required because real protocols carry state (gPTP's
/// running message index); `no_state` is an empty tag so stateless protocols cost nothing.
struct no_state {};

template <class P>
concept Protocol = requires {
  typename P::trigger;                 // compile-time predicate (see B)
  typename P::state;                   // per-decode mutable state, or no_state
  { P::tables } -> TableSpec;          // one or more NAMED output tables (see C)
} && requires(const decode_ctx& c) {
  { P::trigger::match(c) } -> std::same_as<bool>;
};
// P::parse(const decode_ctx&, nanom::seg_input, P::state&, Tables&, PacketJson*) is checked at the
// dispatch site (see `ParsableProtocol` below) because the Tables type is only known there.

namespace detail {
/// Instantiated once per type in a decoder<...> so a malformed protocol reports THIS message,
/// rather than failing deep inside the dispatch fold.
template <class P>
struct assert_protocol {
  static_assert(Protocol<P>,
                "nanom_shark: a type registered in decoder<...> does not satisfy the Protocol "
                "concept. A protocol must declare:  using trigger = <a type with "
                "static constexpr bool match(const decode_ctx&)>;  using state = <a type, or "
                "nanom_shark::no_state>;  static constexpr auto tables = table_spec<table_decl<"
                "\"name\", Row>, ...>{};  and  static void parse(const decode_ctx&, "
                "nanom::seg_input, state&, auto& tables, PacketJson*).");
  static constexpr bool value = true;
};
}  // namespace detail

/// Checked at the dispatch site, where the concrete table-set type is known.
template <class P, class Tables>
concept ParsableProtocol =
    Protocol<P> && requires(const decode_ctx& c, nanom::seg_input in, typename P::state& st,
                            Tables& t, PacketJson* j) { P::parse(c, in, st, t, j); };

// ---------------------------------------------------------------------------
// D. the decoder type list — the registry
// ---------------------------------------------------------------------------

/// `decoder<Ethernet..., Someip, Gptp, Lldp, FooProto>` -- the type list IS the registry. Fully
/// unrolled by the compiler; nothing here survives to run time except the per-protocol predicates.
template <class... Ps>
struct decoder {
  static_assert(sizeof...(Ps) > 0, "nanom_shark: decoder<> needs at least one protocol");
  static_assert((detail::assert_protocol<Ps>::value && ...));

  static constexpr std::size_t protocol_count = sizeof...(Ps);
  using tables_spec = typename detail::cat_specs<table_spec<>,
                                                 std::remove_cvref_t<decltype(Ps::tables)>...>::type;
};

/// The aggregate of every registered protocol's tables. A class (not an alias) so that
/// `run_decode_pass(file, tables, ...)` can DEDUCE the decoder from the tables argument.
template <class Decoder>
class tables_of : public table_set<typename Decoder::tables_spec> {
 public:
  using decoder_type = Decoder;
};

namespace detail {
template <class P>
struct state_slot {
  typename P::state st{};
};
}  // namespace detail

/// Per-decode-pass mutable state, one slot per registered protocol.
template <class Decoder>
class states_of;

template <class... Ps>
class states_of<decoder<Ps...>> : private detail::state_slot<Ps>... {
 public:
  template <class P>
  [[nodiscard]] constexpr typename P::state& get() noexcept {
    return static_cast<detail::state_slot<P>&>(*this).st;
  }
};

// ---------------------------------------------------------------------------
// the ONE dispatch
// ---------------------------------------------------------------------------

namespace detail {

template <layer L, class P, class Tables, class States>
inline void dispatch_one(const decode_ctx& c, nanom::seg_input in, Tables& tables, States& states,
                         PacketJson* json) {
  // Compile-time pruning: a trigger that can never match at this dispatch point is not even
  // instantiated, so the fold really is the old hand-written if-chain and nothing more.
  if constexpr (trigger_applies<typename P::trigger>(L)) {
    static_assert(ParsableProtocol<P, Tables>,
                  "nanom_shark: protocol registered in decoder<...> has no usable  static void "
                  "parse(const decode_ctx&, nanom::seg_input, state&, auto& tables, PacketJson*)  "
                  "-- check the parameter list and that `tables` is a deduced `auto&`.");
    if (P::trigger::match(c)) P::parse(c, in, states.template get<P>(), tables, json);
  }
}

template <layer L, class... Ps, class Tables, class States>
inline void dispatch_list(decoder<Ps...>, const decode_ctx& c, nanom::seg_input in, Tables& tables,
                          States& states, PacketJson* json) {
  (dispatch_one<L, Ps>(c, in, tables, states, json), ...);
}

}  // namespace detail

/// THE dispatch. Folds over the decoder's protocol type list in declaration order and calls
/// `parse` on EVERY protocol whose trigger matches (not just the first -- triggers are predicates,
/// and two protocols may legitimately claim the same bytes; today's builtin triggers are mutually
/// exclusive, so this is behaviourally identical to the if/else-if chain it replaces).
///
/// Both the normal per-packet walk and the reassembled-datagram re-entry call THIS function, which
/// is why they can no longer drift apart on e.g. SOME/IP port matching.
template <layer L, class Decoder, class Tables, class States>
inline void dispatch(const decode_ctx& c, nanom::seg_input in, Tables& tables, States& states,
                     PacketJson* json) {
  detail::dispatch_list<L>(Decoder{}, c, in, tables, states, json);
}

}  // namespace nanom_shark
