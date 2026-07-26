# nano_shark: a textbook network analyzer

`examples/nano_shark/` is nanom's flagship example: a single pcap/pcapng decode pass — Ethernet,
VLAN 802.1Q/QinQ, IPv4/IPv6 (with fragment reassembly and the full IPv6 extension-header chain
incl. SRv6), TCP/UDP, SOME/IP (incl. Service Discovery), all 8 gPTP message types, and LLDP — that
drains into whichever sinks you ask for: a tshark-`-T json`-shaped NDJSON dump and a real Avro
Object Container File, both dependency-free. (Parquet and Lance sinks live in a companion repo,
[nanoshark](https://github.com/yoavbendor/nanoshark) — see [below](#the-heavier-sinks-nanoshark).)

This page walks the architecture end to end. If you just want to run it:

```sh
cmake -B build && cmake --build build --target nano_shark -j
./build/nano_shark capture.pcapng --json out.ndjson
```

## The core idea: reuse, don't re-type

Every other pcap-to-columns tool in this space hand-writes a parallel "row" struct per protocol,
duplicating every field name a wire struct already has. nano_shark doesn't: `Node<Body>` wraps an
**existing** `NANOM_DESCRIBE`d wire struct as a nested field, and `nanom::soa<T>`'s dotted-name
flattening already knows how to turn that nesting into `body.<field>` columns with no extra code:

```cpp
// core/node_row.hpp
template <class Body>
struct Node {
  packet_id_t   packet_id      = kNoPacket;
  std::uint32_t datagram_id    = 0;      // non-zero only for a fragment-reassembled row
  bool          is_reassembled = false;
  Body          body;                    // an EXISTING wire struct, reused verbatim
};
```

```cpp
// core/l2l3_nodes.hpp — the entire per-protocol registration is one line:
using EthNode = Node<nmproto::Ethernet>;
```

A single shared partial specialization (`nanom::describe<Node<Body>>`, in `node_row.hpp`) registers
every `Node<...>` instantiation at once — `Node<Body>` is a class-template instantiation, and
nanom's C++26 reflection provider [categorically excludes those](P2996_COMPAT.md), so this is
written as a plain partial specialization rather than through `NANOM_DESCRIBE`, and it compiles
identically whether nanom itself is built in C++23 macro mode or C++26 reflection mode.

`node_table<Row>` is the columnar accumulator each protocol table uses — a name (the JSON layer
key) plus the existing `nanom::soa<Row>`:

```cpp
struct AllTables {
  node_table<PacketRow> packets{"packets"};  // one row per captured frame, decode-outcome-agnostic
  node_table<EthNode>   eth{"eth"};
  node_table<VlanNode>  vlan{"vlan"};
  node_table<Ipv4Node>  ipv4{"ipv4"};
  // ... ipv6, udp, tcp, defrag/datagram tables, someip*, gptp, lldp
};
```

## The decode pass

`run_decode_pass()` (`core/decode_pass.hpp`) is the one entry point every sink drains from:

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
5. UDP/TCP payloads reach `l4_dispatch.hpp`'s `dispatch_l4()` — the single L4 entry point used by
   *both* the normal per-packet path and defrag's reassembly-completion re-entry, so there is never
   a second, divergent copy of the UDP/TCP handling logic.
6. `dispatch_l4()` additionally tries SOME/IP (Service Discovery is always attempted once a
   `SomeipHeader` parses; port-gated for plain/TLV payloads via `DecodeOptions::someip_ports` /
   `someip_tlv_ports`, since SOME/IP has no EtherType/magic-number tag of its own).
7. Ethernet's ethertype also dispatches gPTP (`0x88F7`) and LLDP (`0x88CC`) directly, since both are
   L2-terminal protocols with no IP layer underneath.
8. Every row lands in `AllTables` always; when a JSON sink is attached, each layer *additionally*
   renders straight into that packet's `PacketJson` at the same callback site.

A malformed layer stops **that packet's** walk only (nanom's existing `walk_packet` contract) —
`run_decode_pass()` itself returns `false` only when the pcap/pcapng container scan fails outright
(a corrupt file, not a corrupt packet).

## Fragment reassembly

`core/defrag.hpp` is the first heap-owning, cross-packet **stateful** table anywhere in the
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
nanom feature, not nano_shark-specific, but reassembly is its motivating consumer. It parses a
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

`core/json_tree.hpp`'s `PacketJson` builds the tshark-shaped `{"_index":N,"_source":{"layers":{...}}}`
tree at runtime. `add_layer_json(name, json)` inserts a layer; a **second** call with the same name
promotes it to a JSON array — this is what makes VLAN stacking, the IPv6 extension-header chain,
LLDP TLVs, and SOME/IP SD entries render as repeated-field arrays, matching tshark's own shape,
without the caller needing to know in advance how many of a given layer a packet will have.

## The Avro sink

`core/avro_ocf.hpp` is a real Avro Object Container File writer — `"Obj\x01"` magic, a metadata map
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
between nanom's columnar storage and either target schema is `core/soa_columns.hpp`'s
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

Every step above composes the same way for a new protocol:

1. A `NANOM_DESCRIBE`d (or, under C++26, plain) wire struct for its fixed header.
2. `using FooNode = Node<Foo>;` if it fits the generic envelope, or a small synthesized row (with
   its own `packet_id` field) if it doesn't — SOME/IP's SD entries/options and LLDP's per-TLV row
   are both examples of the latter, since their shape varies by sub-type in a way `Node<Body>`
   doesn't model.
3. One `node_table<FooNode> foo{"foo"};` member on `AllTables`.
4. A dispatch call from wherever the protocol is identifiable (an ethertype, an IP protocol number,
   a UDP/TCP port, or a signature check on the payload itself) in `decode_pass.hpp` / `l4_dispatch.hpp`.

Nothing else changes: the JSON sink renders it via the same `add_layer_json` call every other
protocol uses, the Avro sink and `columns_of<T>` see it automatically (any `nanom::Described` type
qualifies), and — once vendored via nanoshark — so do the Parquet and Lance sinks, with no changes
needed in that repo at all.

## See also

- [Design](design.md) — the `describe<T>` seam, zero-copy views, error model (the ideas nano_shark
  builds on).
- [Memory safety](MEMORY_SAFETY.md) — `NANOM_GENERATION`/`NANOM_GUARD_VIEWS` and what they catch.
- [nanoshark](https://github.com/yoavbendor/nanoshark) — the Parquet/Lance integration repo.
