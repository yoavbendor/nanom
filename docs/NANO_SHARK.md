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

`core/defrag.hpp` is the one deliberate, narrowly-scoped departure from nanom's zero-copy pledge —
and the first heap-owning, cross-packet **stateful** table anywhere in the nano-family. Every
individual fragment's IP header is still decoded zero-copy over the file's own bytes; fragments are
buffered as non-owning `std::span`s into that same source buffer (valid for the whole decode pass),
and only the final cross-fragment stitch — built once a datagram completes — is an owned copy: one
`memcpy`-shaped copy per completed datagram, not one per fragment plus another at the end.

```cpp
ReassemblyTable<Ipv4Key> table;
auto r = table.add_fragment(key, packet_id, offset_bytes, more_fragments, payload);
if (r.completed) {
  // r.assembled is a std::span<const std::byte> over the owned, stitched buffer
}
table.evict_stale(now_packet_id);  // ages out timed-out / stuck-in-conflict reassemblies
```

A genuinely zero-copy reassembly (fragments joined lazily via `std::views::join`, never
materializing a contiguous buffer) isn't practical here: nanom's parsing surface (`nom.hpp`'s
`input`, `strct<T>()`, `overlay<T>()`) is built on a contiguous `[first,last)` pointer pair, not a
generalized range — a `join_view` over disjoint spans is only a `forward_range`, so it can't yield
the pointer+length pair the parser needs. Teaching the core cursor to understand segmented input
would be a change to the *library*, out of scope for an example.

`fuzz/fuzz_defrag.cpp` is a dedicated libFuzzer harness for this table (out-of-order fragments,
overlapping/conflicting fragments, capacity/timeout eviction) — within its first run it found a
real bug (a stale key-to-id mapping surviving eviction, causing a crash on key reuse), now fixed and
regression-tested.

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
