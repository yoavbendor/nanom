// SPDX-License-Identifier: Apache-2.0
#pragma once

// nano_shark/core/node_row.hpp — the one per-protocol row envelope + table container.
//
// Every protocol layer's row reuses its EXISTING NANOM_DESCRIBE'd wire struct as a nested field
// (nanom::soa<T>'s dotted-flattening already knows how to turn a nested Described member into
// "body.<field>" columns) instead of hand-retyping every field into a parallel row struct — see
// nanom/include/nanom/soa.hpp's build_nested(). One
//   NANOM_DESCRIBE(Node<SomeWireStruct>, packet_id, datagram_id, is_reassembled, body);
// line per protocol (see l2l3_nodes.hpp) is the entire per-protocol registration; it never repeats
// a single field name that the wire struct's own NANOM_DESCRIBE already listed.

#include <nanom/nanom.hpp>

#include <cstdint>
#include <string>
#include <string_view>

namespace nano_shark {

namespace nm = nanom;

using packet_id_t = std::uint64_t;
inline constexpr packet_id_t kNoPacket = packet_id_t(-1);

// Body is an existing NANOM_DESCRIBE'd wire struct (nmproto::Ethernet, nmproto::Ipv4, ...).
// datagram_id/is_reassembled are 0/false for every packet except a UDP/TCP row built from a
// completed IPv4/IPv6 fragment reassembly (see core/defrag.hpp, added in a later phase).
template <class Body>
struct Node {
  packet_id_t   packet_id      = kNoPacket;
  std::uint32_t datagram_id    = 0;
  bool          is_reassembled = false;
  Body          body;
};

// One table per node "kind": a name (the JSON sink's layer key / a future Parquet+Lance file stem)
// plus the existing nm::soa<Row> columnar accumulator.
template <nm::Described Row>
class node_table {
 public:
  explicit node_table(std::string_view proto_name, std::size_t chunk_rows = 65536)
      : proto_name_(proto_name), table_(chunk_rows) {}

  void push(const Row& r) { table_.push(r); }
  const nm::soa<Row>& soa() const { return table_; }
  std::size_t rows() const { return table_.rows(); }
  std::string_view proto_name() const { return proto_name_; }

 private:
  std::string  proto_name_;
  nm::soa<Row> table_;
};

}  // namespace nano_shark

// Node<Body> is always exactly {packet_id, datagram_id, is_reassembled, body} regardless of Body,
// so one partial specialization registers every protocol's Node<...> at once — no per-protocol
// NANOM_DESCRIBE line needed (see l2l3_nodes.hpp / someip_rows.hpp, which used to each carry one).
//
// This is written as a plain partial specialization rather than through the NANOM_DESCRIBE macro
// on purpose: Node<Body> is a class TEMPLATE INSTANTIATION, which nanom::Reflectable categorically
// excludes (nanom26.hpp's `has_identifier` check treats template specializations like lambdas/
// anonymous structs — no reflectable identifier), so under NANOM_HAS_REFLECTION, NANOM_DESCRIBE's
// own reflection-mode branch (a static_assert that reflection covers the type) would always fail
// here. NANOM_DESCRIBE_FORCE_MACRO isn't the right escape hatch either — it's a whole-build compile
// flag (see describe_macro.hpp), not a per-type override. An explicit/partial specialization is
// nanom's documented, always-wins override mechanism regardless of build mode (see
// tests/test_reflect26.cpp's "override semantics" section), so it compiles identically whether
// nanom itself is built with the C++23 macro provider or the C++26 reflection provider.
template <class Body>
struct nanom::describe<nano_shark::Node<Body>> {
  static constexpr const char* name() { return "nano_shark::Node"; }
  static constexpr auto fields() {
    return std::make_tuple(
        nanom::detail::fld<"packet_id", &nano_shark::Node<Body>::packet_id>{},
        nanom::detail::fld<"datagram_id", &nano_shark::Node<Body>::datagram_id>{},
        nanom::detail::fld<"is_reassembled", &nano_shark::Node<Body>::is_reassembled>{},
        nanom::detail::fld<"body", &nano_shark::Node<Body>::body>{});
  }
};
