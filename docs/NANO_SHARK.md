# nanom_shark: a textbook network analyzer

`nanom_shark` (headers in `include/nanom_shark/`, CLI in `apps/nanom_shark_cli.cpp`) is nanom's flagship decoder library: a single pcap/pcapng decode pass — Ethernet,
VLAN 802.1Q/QinQ, IPv4/IPv6 (with fragment reassembly and the full IPv6 extension-header chain
incl. SRv6), TCP/UDP, SOME/IP (incl. Service Discovery), all 8 gPTP message types, and LLDP — that
drains into whichever sinks you ask for: a tshark-`-T json`-shaped NDJSON dump and a real Avro
Object Container File, both dependency-free. (Parquet and Lance sinks live in a companion repo,
[nanoshark](https://github.com/yoavbendor/nanoshark) — see [below](#the-heavier-sinks-nanoshark).)

This page walks the architecture end to end. If you just want to run it:

```sh
cmake -B build && cmake --build build --target nanom_shark_cli -j
./build/nanom_shark_cli capture.pcapng --json out.ndjson
```

## The core idea: reuse, don't re-type

Every other pcap-to-columns tool in this space hand-writes a parallel "row" struct per protocol,
duplicating every field name a wire struct already has. nanom_shark doesn't: `Node<Body>` wraps an
**existing** `NANOM_DESCRIBE`d wire struct as a nested field, and `nanom::soa<T>`'s dotted-name
flattening already knows how to turn that nesting into `body.<field>` columns with no extra code:

```cpp
// nanom_shark/node_row.hpp
template <class Body>
struct Node {
  packet_id_t   packet_id      = kNoPacket;
  std::uint32_t datagram_id    = 0;      // non-zero only for a fragment-reassembled row
  bool          is_reassembled = false;
  Body          body;                    // an EXISTING wire struct, reused verbatim
};
```

```cpp
// nanom_shark/l2l3_nodes.hpp — the entire per-protocol registration is one line:
using EthNode = Node<nmproto::Ethernet>;
```

A single shared partial specialization (`nanom::describe<Node<Body>>`, in `node_row.hpp`) registers
every `Node<...>` instantiation at once — `Node<Body>` is a class-template instantiation, and
nanom's C++26 reflection provider [categorically excludes those](P2996_COMPAT.md), so this is
written as a plain partial specialization rather than through `NANOM_DESCRIBE`, and it compiles
identically whether nanom itself is built in C++23 macro mode or C++26 reflection mode.

`node_table<Row>` is the columnar accumulator each protocol table uses — a name (the JSON layer
key) plus the existing `nanom::soa<Row>`:

The table SET is not hand-written — it is **derived from the registered protocol type list**. Each
protocol declares its own named tables, and `tables_of<decoder<...>>` concatenates them:

```cpp
struct CoreL2L3 {                       // the base Eth/VLAN/IP/UDP/TCP walk's own tables
  static constexpr auto tables = table_spec<
      table_decl<"packets", PacketRow>,  // one row per captured frame, decode-outcome-agnostic
      table_decl<"eth", EthNode>,
      table_decl<"vlan", VlanNode>,
      table_decl<"ipv4", Ipv4Node>,
      /* ipv6, udp, tcp, ipv4_frag, ipv6_frag, datagram */>{};
};

using default_decoder = decoder<CoreL2L3, Someip, Gptp, Lldp>;  // the type list IS the registry
using AllTables       = tables_of<default_decoder>;

AllTables t;
t.get<"eth">().push(row);                                    // compile-time name lookup
t.for_each_table([](std::string_view name, const auto& soa) { ... });  // generic iteration
```

`for_each_table` is what lets a sink be written once for every table that will ever exist —
`dump_all_tables_avro` is a five-line loop over it.

## The decode pass

`run_decode_pass()` (`nanom_shark/decode_pass.hpp`) is the one entry point every sink drains from:

1. `nmpcap::scan_blocks()` walks the pcap/pcapng container structure (SHB/IDB/EPB or legacy pcap
   records) — reused verbatim from `examples/nanotins_parity/`.
2. For each packet, `PacketRow{packet_id, file_offset, caplen, origlen}` is pushed unconditionally
   (regardless of decode outcome) — this is the table a byte-level sink anchors back to raw file
   bytes with (see [below](#the-heavier-sinks-nanoshark)).
3. `nmproto::walk_packet_ext()` — nanom's extended walk, which (unlike the base `walk_packet`)
   descends the full IPv6 extension-header chain (Hop-by-Hop, Routing/SRv6, Fragment, Destination
   Options, AH) — decodes Ethernet → VLAN → IPv4/IPv6 → TCP/UDP, zero-copy over the packet's own
   bytes throughout.
4. A fragment-eligible IPv4/IPv6 packet is diverted into `defrag::ReassemblyTable<Key>` instead of
   falling through to L4 (see [Fragment reassembly](#fragment-reassembly)).
5. `walk_packet_ext()` reports each layer's **byte offset** (`on_offset` / `on_l2_done`) alongside
   its decoded value, which is what fills in `decode_ctx` — the struct every trigger matches
   against (`packet_id`, `datagram_id`, `is_reassembled`, `ethertype`, `ip_proto`,
   `src_port`/`dst_port`, `link_type`, and the L2/L3/L4 offsets).
6. There are two **dispatch points**, both of them the same `dispatch<Layer, Decoder>` fold over the
   registered protocol type list: `layer::eth_payload` right after Ethernet + VLAN tags (gPTP
   `0x88F7`, LLDP `0x88CC` — both L2-terminal, no IP underneath) and `layer::l4_payload` right after
   the TCP/UDP header (SOME/IP). Every protocol whose trigger matches gets its `parse` called.
7. The reassembly-completion re-entry reaches `layer::l4_payload` through the *same*
   `dispatch_l4()`, over the reassembled datagram's zero-copy segment list — so the normal and
   reassembled paths cannot drift apart. SOME/IP port matching, for instance, exists in exactly one
   place: `Someip::trigger`.
8. Every row lands in the decoder's table set always; when a JSON sink is attached, each layer
   *additionally* renders straight into that packet's `PacketJson` at the same callback site.

A malformed layer stops **that packet's** walk only (nanom's existing `walk_packet` contract) —
`run_decode_pass()` itself returns `false` only when the pcap/pcapng container scan fails outright
(a corrupt file, not a corrupt packet).

## Fragment reassembly

`nanom_shark/defrag.hpp` is the first heap-owning, cross-packet **stateful** table anywhere in the
nano-family. A reassembled datagram's bytes are disjoint in the source file, but reassembly is
**fully zero-copy**: every individual fragment's IP header is decoded over the file's own bytes,
fragments are buffered as non-owning `std::span`s into that same source buffer, and on completion
`add_fragment` returns an ordered, overlap-trimmed **list of views** — `Result::parts`, a
`nanom::segments` — that the L4 re-entry parses straight over with `strct_seg`. No stitched buffer
is ever built.

```cpp
ReassemblyTable<Ipv4Key> table;
auto r = table.add_fragment(key, packet_id, offset_bytes, more_fragments, payload);
if (r.completed) {
  // r.parts is a nanom::segments: ordered, overlap-trimmed VIEWS into the source buffer.
  nm::seg_input in = nm::from(r.parts);
  auto udp = nm::strct_seg<Udp>()(in);   // parsed straight over the fragment views, no copy
}
table.evict_stale(now_packet_id);        // ages out timed-out / stuck-in-conflict reassemblies
```

This is what nanom's [segmented input](#segmented-input-parsing-across-disjoint-byte-ranges) layer
(`nanom/segmented.hpp`) exists for. Earlier this was documented as impractical — "a `join_view`
over disjoint spans is only a `forward_range`, can't yield the pointer+length pair the parser
needs." The insight that dissolved that: nanom's field decode already takes a *raw pointer*, so
segmentation is solved by **windowing** one level above it — a bounded, stack-only gather of one
struct's bytes only when a struct straddles a fragment seam, and a pure pointer read otherwise.
The ~124 core combinators never changed. Measured payoff: parsing the L4 header off the segment
list is **33–43× faster** than the old stitch-then-parse for a 64 KiB datagram (the whole-datagram
copy is gone), and the every-packet hot path is byte-for-byte unchanged (`bench/segmented_bench.cpp`,
`bench/parse_bench.cpp`). A lazy `materialize()` escape hatch remains for the rare consumer that
truly needs one contiguous buffer — the only place a copy can still happen, and only if asked.

`fuzz/fuzz_defrag.cpp` is a dedicated libFuzzer harness for this table (out-of-order fragments,
overlapping/conflicting fragments, capacity/timeout eviction, plus parsing a struct chain over the
returned segment list) — within its first run it found a real bug (a stale key-to-id mapping
surviving eviction, causing a crash on key reuse), now fixed and regression-tested.

## Segmented input: parsing across disjoint byte ranges

`nanom/segmented.hpp` is the library layer that makes zero-copy reassembly possible — a general
nanom feature, not nanom_shark-specific, but reassembly is its motivating consumer. It parses a
logical buffer whose bytes live in an ordered list of **disjoint spans**, without ever copying
them into one contiguous block.

- `segments` — a non-owning, ordered list of `std::span<const std::byte>` parts.
- `seg_input` — the cursor. It mirrors `input`'s member API (`size`/`advance`/`operator[]`/…), and
  its hot fields are raw pointers into the *current* part, so a read inside one part is a pointer
  compare + deref, exactly like the contiguous cursor.
- `strct_seg<T>()` / the cursor kit (`seg_u8`, `seg_be16`, `seg_be32`, …) — parse structs and
  scalars over `seg_input`. `strct_seg` reuses the **same** field-decode code as `strct` (nanom's
  `decode_field`/`assign_field` already take a raw pointer); a `gather<N>` primitive supplies that
  pointer — pointing straight into segment memory when the `N`-byte window lies inside one part, or
  into a bounded stack buffer only when it straddles a seam.
- `overlay_seg<T>()` — **zero-copy or a recoverable error, never a hidden copy**: it yields a
  `view<T>` into segment memory when the struct is contiguous, and fails (so you fall back to
  `strct_seg`, by value) when it would straddle. A view must never point at a temporary.

The three design guarantees: (1) **zero cost when unused** — `input` and every combinator are
untouched; don't include the header, don't pay; (2) **pay only at the seams** — an in-part read is
pointer-based, only a straddling read gathers, and only one struct's worth of bytes onto the stack;
(3) **honest views**. Explicitly out of scope (v1): the general combinator vocabulary
(`alt`/`many0`/`tag`/`dec`/…) whose text-oriented members need physically contiguous memory —
segmented parsing covers struct decode and hand-rolled cursor walks, which is what a re-entry
parser (like SOME/IP over a reassembled datagram) needs. `tests/test_segmented.cpp` proves the
cursor agrees with the contiguous cursor over every split, `strct_seg`/`overlay_seg` agree with
`strct`/`overlay` over every split of six real wire structs, and `fuzz/fuzz_segmented.cpp`
differentially fuzzes segmented vs contiguous parses.

## The JSON sink

`nanom_shark/json_tree.hpp`'s `PacketJson` builds the tshark-shaped `{"_index":N,"_source":{"layers":{...}}}`
tree at runtime. `add_layer_json(name, json)` inserts a layer; a **second** call with the same name
promotes it to a JSON array — this is what makes VLAN stacking, the IPv6 extension-header chain,
LLDP TLVs, and SOME/IP SD entries render as repeated-field arrays, matching tshark's own shape,
without the caller needing to know in advance how many of a given layer a packet will have.

## The Avro sink

`nanom_shark/avro_ocf.hpp` is a real Avro Object Container File writer — `"Obj\x01"` magic, a metadata map
(`avro.schema` = `nanom::avro_schema<T>()`, reused verbatim from `schema.hpp`; `avro.codec` =
`"null"`), a random 16-byte sync marker, then one block per `nanom::soa<T>` chunk. The binary
encoding itself is zigzag varints + raw IEEE-754 bytes + length-prefixed byte strings — no external
Avro library needed for the `"null"` codec. `write_chunk()` reads each row's fields directly out of
the chunk's own column buffers (`nanom::soa<T>::chunk::as<V>(i)`) rather than reconstructing a `T`
value first, since `soa<T>` never stores rows any other way.

## The heavier sinks: nanoshark

Parquet and Lance both need external libraries nanom itself never depends on, so they live in a
sibling repo, [nanoshark](https://github.com/yoavbendor/nanoshark), which vendors nanom (plus
[nanoarrow2parquet](https://github.com/yoavbendor/nanoarrow2parquet) and
[nanolance](https://github.com/yoavbendor/nanolance)) as read-only git submodules. The bridge
between nanom's columnar storage and either target schema is `nanom_shark/soa_columns.hpp`'s
`columns_of<T>` — a compile-time leaf-column **type list** that mirrors `nanom::soa<T>::columns()`'s
own dotted-name flattening exactly (same names, same order, same per-row size — proven by
`tests/test_soa_columns.cpp` across every current row shape), so nanoshark's Parquet and Lance
writers both fold it into their own `Field<Name, T>...`/`column<T, Name>...` packs once and feed
`nanom::soa<T>::chunk::as<Type>(i)` spans straight into `write_chunk()`/`write_batch()` — zero-copy
for every fixed-width column, including MAC/IP-shaped `fixed_size_binary` columns.

nanoshark's `packets` table (mirroring nanom's own `PacketRow`) additionally carries a
`lance.blob.v2 payload_ref` column resolving each packet's raw bytes back to the source capture file
(`uri` = the file, `position`/`size` = that packet's `file_offset`/`caplen`) — every other table
joins back to it by `packet_id` alone, never touching raw file bytes itself.

## Adding a new protocol

**One new file. Zero edits to any library header.** That is the whole of it:

```cpp
struct FooHeader { nanom::be<std::uint32_t> id; nanom::be<std::uint16_t> len; };
NANOM_DESCRIBE(FooHeader, id, len);

struct FooProto {
  using trigger = udp_port<1234>;   // or ethertype<0x88F7>, ip_proto<17>, all_of<...>, ...
  using state   = no_state;         // or a struct, for protocols that carry state across packets
  static constexpr auto tables = table_spec<table_decl<"foo", Node<FooHeader>>>{};

  static void parse(const decode_ctx& c, nanom::seg_input in, state&, auto& t, PacketJson* j) {
    if (auto r = nanom::strct_seg<FooHeader>()(in))
      t.template get<"foo">().push(Node<FooHeader>{c.packet_id, c.datagram_id, c.is_reassembled, r->value});
  }
};

using my_decoder = decoder<CoreL2L3, Someip, Gptp, Lldp, FooProto>;   // register it
tables_of<my_decoder> tables;                                          // and that is the call site
run_decode_pass(file, tables, sink, opts, error);
```

`tests/nanom_shark_test_ergonomics.cpp` is exactly this, as an executable proof — including the
same protocol receiving a datagram that arrived as two IPv4 fragments, decoded across the fragment
seam, with no reassembly-aware code in `FooProto` at all.

### The trigger DSL

`ethertype<E>`, `ip_proto<P>`, `udp_port<Ports...>`, `tcp_port<Ports...>`, `link_type<L>`,
`all_of<...>`, `any_of<...>`, `not_<T>`, `always`, `never`. Each is a compile-time predicate over
`decode_ctx`; where the matched value is a constant it collapses to the same `==` a hand-written
if-chain emits.

The interesting case is a protocol with **no** EtherType and no magic number, identified only by a
port agreed out-of-band — SOME/IP. `udp_port_cfg<&DecodeOptions::someip_ports>` names *which*
runtime vector to consult with a **compile-time pointer-to-member**, so the protocol type list stays
fully unrolled and only the port *values* are late-bound to the `DecodeOptions` the pass was given
(`--someip-port` / `--someip-tlv-port` on the CLI).

### What this buys

Dispatch stays **compile-time only** — no type erasure, no virtual calls, no runtime registry. The
`decoder<...>` fold is unrolled into the same if-chain the hand-written code used to be, and a
dispatch point does not even instantiate a protocol whose trigger cannot match there. The JSON sink
renders the new layer via the same `add_layer` every other protocol uses, and the Avro sink picks
the new tables up through `for_each_table` with no edit. (The Parquet and Lance sinks in the
nanoshark repo still carry a hand-written table list; collapsing them onto `for_each_table` is
Phase 3.)

## See also

- [Design](design.md) — the `describe<T>` seam, zero-copy views, error model (the ideas nanom_shark
  builds on).
- [Memory safety](MEMORY_SAFETY.md) — `NANOM_GENERATION`/`NANOM_GUARD_VIEWS` and what they catch.
- [nanoshark](https://github.com/yoavbendor/nanoshark) — the Parquet/Lance integration repo.
