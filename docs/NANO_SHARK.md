# nanom_shark

A pcap/pcapng network decoder built as a nanom library (headers in `include/nanom_shark/`, CLI in
`apps/nanom_shark_cli.cpp`). One decode pass — Ethernet, VLAN 802.1Q/QinQ, IPv4/IPv6 (with fragment
reassembly and the full IPv6 extension-header chain incl. SRv6), TCP/UDP, SOME/IP (incl. Service
Discovery), all 8 gPTP message types, LLDP — draining into whichever sinks you ask for: NDJSON shaped
like `tshark -T json`, a real Avro Object Container File, and (in a
[sibling repo](#the-heavier-sinks-nanoshark)) Parquet and Lance.

```sh
cmake -B build && cmake --build build --target nanom_shark_cli -j
./build/nanom_shark_cli capture.pcapng --json out.ndjson
```

Two things here are not, as far as we know, available anywhere else. They are the reason this library
exists, so they come first.

---

## 1. Fragment reassembly that never copies

Every other library in this space — libtins, PcapPlusPlus — reassembles a fragmented IP datagram by
**stitching the fragments into a new owned buffer** and parsing that. The copy is structural in their
design, because their parsers need one contiguous block of memory to walk.

nanom_shark never builds that buffer. Fragments are buffered as non-owning `std::span`s into the
capture buffer you already have, and on completion `add_fragment` hands back an ordered,
overlap-trimmed **list of views** (`Result::parts`, a `nanom::segments`) that the L4 re-entry parses
*directly*:

```cpp
ReassemblyTable<Ipv4Key> table;                  // Ipv6Key for IPv6 — same table, same path
auto r = table.add_fragment(key, packet_id, offset_bytes, more_fragments, payload);
if (r.completed) {
  // r.parts: ordered, overlap-trimmed VIEWS into the original capture buffer. No stitch happened.
  nm::seg_input in = nm::from(r.parts);
  auto udp = nm::strct_seg<Udp>()(in);           // parsed across the fragment seams, no copy
}
table.evict_stale(now_packet_id);                // ages out timed-out / conflicted reassemblies
```

This works for **IPv4 and IPv6 alike** (`tests/nanom_shark_test_defrag.cpp` covers both, IPv6
end-to-end through `ipv6_fragments_sample.pcap`).

### It is measurably not a copy

`bench/segmented_bench.cpp`, section (A), parses the L4 header off a completed reassembly both ways.
Run it yourself:

```sh
cmake --build build --target nm_segmented_bench -j && ./build/nm_segmented_bench
```

```
=== (A) reassembly re-entry: stitch-then-parse vs zero-copy segments-parse ===
A   1500B x  2 frags   stitch     43.5 ns   segments     42.4 ns    1.03x  (segments)  chk ok
A   1500B x  4 frags   stitch     49.1 ns   segments     42.4 ns    1.16x  (segments)  chk ok
A   1500B x 16 frags   stitch     80.9 ns   segments     43.9 ns    1.84x  (segments)  chk ok
A  65536B x  2 frags   stitch   1620.4 ns   segments     42.4 ns   38.24x  (segments)  chk ok
A  65536B x  4 frags   stitch   1609.4 ns   segments     42.4 ns   37.98x  (segments)  chk ok
A  65536B x 16 frags   stitch   1457.0 ns   segments     43.8 ns   33.23x  (segments)  chk ok
```

The number worth reading is not the speedup column — it is the **`segments` column: 42–44 ns
everywhere.** Reading a header off a reassembled datagram costs the same whether the datagram is 1500
bytes in 2 fragments or 64 KiB in 16, because nothing proportional to the datagram happens. The stitch
column is the one that scales, dominated by allocating and copying the whole datagram, which is also
why it is the noisy one: across repeated runs the 64 KiB stitch lands anywhere from ~1.45 µs to
~1.96 µs — a **33–46× spread** against a flat segments cost that does not move. At MTU-sized datagrams
there is little to win and the benchmark says so (1.03×); the win arrives exactly where the copy gets
expensive.

### And it is provably aliasing, not just fast

Fast is circumstantial evidence. `test_zero_copy_completion` in `tests/nanom_shark_test_defrag.cpp` is
the direct proof: it builds a 24-byte "source file", feeds two fragments that are spans into it, and
asserts every returned part points **inside that original buffer**:

```cpp
// every returned part must alias the source buffer (zero-copy), never an owned copy
bool all_alias = true;
for (std::size_t i = 0; i < r2.parts.parts(); ++i) {
  const auto p = r2.parts.part(i);
  if (p.data() < base || p.data() + p.size() > base + src.size()) all_alias = false;
}
CHECK(all_alias);
```

A pointer-range assertion cannot be satisfied by a copy. The same test pins the overlap-trim semantics
and checks that `materialize()` — the opt-in escape hatch for a consumer that genuinely needs one
contiguous buffer, and **the only place a copy can still happen** — reconstructs the same bytes the old
eager stitch would have.

`fuzz/fuzz_defrag.cpp` fuzzes this table (out-of-order, overlapping and conflicting fragments, capacity
and timeout eviction, plus parsing a struct chain over the returned segment list). Within its first run
it found a real bug — a stale key-to-id mapping surviving eviction, crashing on key reuse — now fixed
and regression-tested (`test_key_reuse_after_eviction`).

---

## 2. Adding a protocol is one new file and zero library edits

Not "one file plus registering it in a registry header". Not "one file plus a line in each sink".
**One file.**

`tests/nanom_shark_test_ergonomics.cpp` is the acceptance test for that claim, and the commit that
added it (`git show --stat 9d33279`) touched exactly two things: the new test file, and the six lines
of `CMakeLists.txt` that build it. Nothing under `include/nanom_shark/` changed. Here is the whole
user-written portion of that file:

```cpp
// 1. The wire struct, described the ordinary nanom way. 12 bytes on the wire.
struct FooHeader {
  nanom::be<std::uint32_t> id;
  nanom::be<std::uint16_t> len;
  nanom::be<std::uint32_t> flags;
  nanom::be<std::uint16_t> tag;
};
NANOM_DESCRIBE(foo::FooHeader, id, len, flags, tag);

// 2. The row: reuse nanom_shark's Node<> envelope so the wire struct's own fields flatten into
//    "body.<field>" columns -- no field is retyped.
using FooNode = nanom_shark::Node<FooHeader>;

// 3. The protocol.
struct FooProto {
  using trigger = nanom_shark::udp_port<1234>;  // compile-time constant -> a plain `==` chain
  using state   = nanom_shark::no_state;        // stateless

  static constexpr auto tables = nanom_shark::table_spec<nanom_shark::table_decl<"foo", FooNode>>{};

  static void parse(const nanom_shark::decode_ctx& c, nanom::seg_input in, state&, auto& t,
                    nanom_shark::PacketJson* json) {
    // strct_seg windows across segment seams itself, so this one line works for a contiguous UDP
    // payload and for a reassembled datagram alike.
    auto r = nanom::strct_seg<FooHeader>()(in);
    if (!r) return;
    t.template get<"foo">().push(
        FooNode{c.packet_id, c.datagram_id, c.is_reassembled, r->value});
    if (json) json->add_layer("foo", r->value);
  }
};

// 4. Registration: the type list IS the registry.
using foo_decoder = nanom_shark::decoder<nanom_shark::CoreL2L3, nanom_shark::Someip,
                                         nanom_shark::Gptp, nanom_shark::Lldp, foo::FooProto>;
```

That is all of it. `foo` now has an Avro table, a Parquet file, a Lance dataset and a JSON layer — and
it decodes correctly when its header arrives split across two IP fragments.

### What it used to cost

The same protocol previously required roughly **8 edit points across 5 library headers** —
`decode_options.hpp` (an options field), `l2l3_nodes.hpp` (a member in the hand-written `AllTables`
struct), `l4_dispatch.hpp` (a dispatch branch), `decode_pass.hpp` (the wiring), `avro_dump.hpp` (a sink
line) — **plus 2 new files**. Every one of those was a place to forget. Now: **1 new file, 0 library
edits.** The test is the proof, not the promise.

### It also proves there is only one dispatch path

The test feeds `FooProto` the same message twice — once as a plain UDP packet, once split across two
IPv4 fragments positioned so the seam falls **inside** the 4-byte `flags` field. Both arrive through
the same `dispatch<layer::l4_payload>`, and the reassembled one arrives as a zero-copy segmented input.
`FooProto` contains no reassembly-aware code whatsoever. A protocol author cannot get the fragmented
case wrong, because there is no fragmented case to get wrong.

A second decoder in the same file registers only `CoreL2L3` + `FooProto`, showing the type list really
is the whole registry: that build has no SOME/IP, gPTP or LLDP tables at all (11 tables, not 25), from
the same unmodified headers.

### The trigger DSL

`ethertype<E>`, `ip_proto<P>`, `udp_port<Ports...>`, `tcp_port<Ports...>`, `link_type<L>`,
`all_of<...>`, `any_of<...>`, `not_<T>`, `always`, `never`. Each is a compile-time predicate over
`decode_ctx`; where the matched value is a constant it collapses to the same `==` a hand-written
if-chain emits. Dispatch stays **compile-time only** — no type erasure, no virtual calls, no runtime
registry — and a dispatch point does not even instantiate a protocol whose trigger cannot match there.

The interesting case is a protocol with **no** EtherType and no magic number, identified only by a port
agreed out-of-band — SOME/IP. `udp_port_cfg<&DecodeOptions::someip_ports>` names *which* runtime vector
to consult with a **compile-time pointer-to-member**, so the protocol type list stays fully unrolled
and only the port *values* are late-bound to the `DecodeOptions` the pass was given (`--someip-port` /
`--someip-tlv-port` on the CLI).

---

## How it works

### Reuse, don't re-type

Every other pcap-to-columns tool hand-writes a parallel "row" struct per protocol, duplicating every
field name a wire struct already has. nanom_shark doesn't: `Node<Body>` wraps an **existing**
`NANOM_DESCRIBE`d wire struct as a nested field, and `nanom::soa<T>`'s dotted-name flattening already
knows how to turn that nesting into `body.<field>` columns with no extra code:

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
every `Node<...>` instantiation at once — `Node<Body>` is a class-template instantiation, and nanom's
C++26 reflection provider [categorically excludes those](P2996_COMPAT.md), so this is written as a
plain partial specialization rather than through `NANOM_DESCRIBE`, and it compiles identically whether
nanom itself is built in C++23 macro mode or C++26 reflection mode.

### The table set is derived, not written

`node_table<Row>` is the columnar accumulator each protocol table uses — a name (the JSON layer key)
plus the existing `nanom::soa<Row>`. The table **set** is not hand-written; it is derived from the
registered protocol type list. Each protocol declares its own named tables, and
`tables_of<decoder<...>>` concatenates them:

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

Two protocols declaring tables with the same name is a `static_assert`, not a silent collision.

`for_each_table` is what lets a sink be written once for every table that will ever exist — and
**every** sink now is one. `dump_all_tables_avro` is a five-line loop over it; so, as of nanoshark's
"Make the Parquet and Lance sinks generic over the decoder's table set", are `dump_all_tables_parquet`
(5 lines) and `dump_all_tables_lance` (18 lines, with one deliberate special case — see
[below](#the-heavier-sinks-nanoshark)). Adding a protocol therefore lands its tables in JSON, Avro,
Parquet **and** Lance with no edit to any sink.

> Earlier revisions of this page claimed sinks picked up new tables automatically before that was
> actually true: at the time, Parquet and Lance each carried a hand-written 24-line table list
> mirroring Avro's by hand, and a new table was silently missing from both until someone remembered to
> add a line to each. The claim is now accurate for all four sinks, and `for_each_table` is the
> mechanism that makes it so.

### The decode pass

`run_decode_pass()` (`nanom_shark/decode_pass.hpp`) is the one entry point every sink drains from:

1. `nmpcap::scan_blocks()` walks the pcap/pcapng container structure (SHB/IDB/EPB or legacy pcap
   records) — reused verbatim from `examples/nanotins_parity/`.
2. For each packet, `PacketRow{packet_id, file_offset, caplen, origlen}` is pushed unconditionally
   (regardless of decode outcome) — this is the table a byte-level sink anchors back to raw file bytes
   with (see [below](#the-heavier-sinks-nanoshark)).
3. `nmproto::walk_packet_ext()` — nanom's extended walk, which (unlike the base `walk_packet`) descends
   the full IPv6 extension-header chain (Hop-by-Hop, Routing/SRv6, Fragment, Destination Options, AH) —
   decodes Ethernet → VLAN → IPv4/IPv6 → TCP/UDP, zero-copy over the packet's own bytes throughout.
4. A fragment-eligible IPv4/IPv6 packet is diverted into `defrag::ReassemblyTable<Key>` instead of
   falling through to L4 (see [above](#1-fragment-reassembly-that-never-copies)).
5. `walk_packet_ext()` reports each layer's **byte offset** (`on_offset` / `on_l2_done`) alongside its
   decoded value, which is what fills in `decode_ctx` — the struct every trigger matches against
   (`packet_id`, `datagram_id`, `is_reassembled`, `ethertype`, `ip_proto`, `src_port`/`dst_port`,
   `link_type`, and the L2/L3/L4 offsets).
6. There are two **dispatch points**, both of them the same `dispatch<Layer, Decoder>` fold over the
   registered protocol type list: `layer::eth_payload` right after Ethernet + VLAN tags (gPTP `0x88F7`,
   LLDP `0x88CC` — both L2-terminal, no IP underneath) and `layer::l4_payload` right after the TCP/UDP
   header (SOME/IP). Every protocol whose trigger matches gets its `parse` called.
7. The reassembly-completion re-entry reaches `layer::l4_payload` through the *same* `dispatch_l4()`,
   over the reassembled datagram's zero-copy segment list — so the normal and reassembled paths cannot
   drift apart. SOME/IP port matching, for instance, exists in exactly one place: `Someip::trigger`.
8. Every row lands in the decoder's table set always; when a JSON sink is attached, each layer
   *additionally* renders straight into that packet's `PacketJson` at the same callback site.

A malformed layer stops **that packet's** walk only (nanom's existing `walk_packet` contract) —
`run_decode_pass()` itself returns `false` only when the pcap/pcapng container scan fails outright (a
corrupt file, not a corrupt packet).

### Segmented input: parsing across disjoint byte ranges

`nanom/segmented.hpp` is the library layer that makes zero-copy reassembly possible — a general nanom
feature, not nanom_shark-specific, but reassembly is its motivating consumer. It parses a logical
buffer whose bytes live in an ordered list of **disjoint spans**, without ever copying them into one
contiguous block.

- `segments` — a non-owning, ordered list of `std::span<const std::byte>` parts.
- `seg_input` — the cursor. It mirrors `input`'s member API (`size`/`advance`/`operator[]`/…), and its
  hot fields are raw pointers into the *current* part, so a read inside one part is a pointer compare +
  deref, exactly like the contiguous cursor.
- `strct_seg<T>()` / the cursor kit (`seg_u8`, `seg_be16`, `seg_be32`, …) — parse structs and scalars
  over `seg_input`. `strct_seg` reuses the **same** field-decode code as `strct` (nanom's
  `decode_field`/`assign_field` already take a raw pointer); a `gather<N>` primitive supplies that
  pointer — pointing straight into segment memory when the `N`-byte window lies inside one part, or into
  a bounded stack buffer only when it straddles a seam.
- `overlay_seg<T>()` — **zero-copy or a recoverable error, never a hidden copy**: it yields a `view<T>`
  into segment memory when the struct is contiguous, and fails (so you fall back to `strct_seg`, by
  value) when it would straddle. A view must never point at a temporary.

This was once documented as impractical — "a `join_view` over disjoint spans is only a `forward_range`,
can't yield the pointer+length pair the parser needs." The insight that dissolved that: nanom's field
decode already takes a *raw pointer*, so segmentation is solved by **windowing** one level above it — a
bounded, stack-only gather of one struct's bytes only when a struct straddles a seam, and a pure
pointer read otherwise. The ~124 core combinators never changed.

The three design guarantees: (1) **zero cost when unused** — `input` and every combinator are
untouched; don't include the header, don't pay; (2) **pay only at the seams** — an in-part read is
pointer-based, only a straddling read gathers, and only one struct's worth of bytes onto the stack;
(3) **honest views**. Explicitly out of scope (v1): the general combinator vocabulary
(`alt`/`many0`/`tag`/`dec`/…) whose text-oriented members need physically contiguous memory —
segmented parsing covers struct decode and hand-rolled cursor walks, which is what a re-entry parser
(like SOME/IP over a reassembled datagram) needs.

`tests/test_segmented.cpp` proves the cursor agrees with the contiguous cursor over every split, and
that `strct_seg`/`overlay_seg` agree with `strct`/`overlay` over every split of six real wire structs;
`fuzz/fuzz_segmented.cpp` differentially fuzzes segmented vs contiguous parses. Section (B) of
`segmented_bench.cpp` prices the wrapper on the normal path at a fixed ~35 ns, which is off the
every-packet hot path (only SOME/IP payloads get wrapped) — `bench/parse_bench.cpp` is byte-identical
with and without this work.

---

## Reading the results

### Composing with `std::views`

A harvested table is a `nanom::soa<Row>`: chunked, columnar, and it **never materializes a `Row`**.
That is deliberate — it is what lets a chunk's column buffers go to Arrow or Lance without a transpose
— and it shapes how you iterate. There is no row range to filter, because there are no row objects to
hand out. The composable unit is a **chunk**, and within a chunk you filter over row *indices* against
that chunk's own column spans.

`soa<T>` exposes the chunk sequence two ways. `for_each_chunk(f)` is the push-only visitor a sink
writer wants. `chunk_count()` and `chunk_at(i)` are the same sequence in the same order, by index —
which is all `std::views` needs:

```cpp
#include <ranges>

const auto& tbl = tables.get<"udp">().soa();

// leaf-column indices come from the table's own flattened, dotted column list — a one-time lookup,
// not a per-row cost
auto col = [&](std::string_view want) {
  const auto& cs = tbl.columns();
  return std::size_t(std::ranges::find_if(cs, [&](const auto& c) { return c.name == want; })
                     - cs.begin());
};
const std::size_t sport_col = col("body.src_port");
const std::size_t dport_col = col("body.dst_port");

// the chunks, as a range you can compose with
auto chunks = std::views::iota(std::size_t{0}, tbl.chunk_count())
            | std::views::transform([&](std::size_t i) -> const auto& { return tbl.chunk_at(i); });

for (const auto& ch : chunks) {
  auto sport = ch.as<std::uint16_t>(sport_col);
  auto dport = ch.as<std::uint16_t>(dport_col);

  // ...and inside a chunk, filter over ROW INDICES against the column spans
  for (std::size_t i : std::views::iota(std::size_t{0}, ch.rows)
                     | std::views::filter([&](std::size_t i) { return dport[i] == 443; })) {
    use(sport[i], dport[i]);
  }
}
```

`soa.hpp` itself takes no dependency on `<ranges>`: the two accessors are an index and a subscript, and
the pipeline is assembled entirely on the caller's side, so a build that never composes anything pays
nothing for the ability. `tests/test_nanom.cpp`'s `test_soa` asserts the indexed view and
`for_each_chunk` visit exactly the same chunks in the same order, before and after `seal()` — the two
cannot disagree.

### The JSON sink

`nanom_shark/json_tree.hpp`'s `PacketJson` builds the tshark-shaped
`{"_index":N,"_source":{"layers":{...}}}` tree at runtime. `add_layer_json(name, json)` inserts a layer;
a **second** call with the same name promotes it to a JSON array — this is what makes VLAN stacking, the
IPv6 extension-header chain, LLDP TLVs, and SOME/IP SD entries render as repeated-field arrays,
matching tshark's own shape, without the caller needing to know in advance how many of a given layer a
packet will have.

### The Avro sink

`nanom_shark/avro_ocf.hpp` is a real Avro Object Container File writer — `"Obj\x01"` magic, a metadata
map (`avro.schema` = `nanom::avro_schema<T>()`, reused verbatim from `schema.hpp`; `avro.codec` =
`"null"`), a random 16-byte sync marker, then one block per `nanom::soa<T>` chunk. The binary encoding
itself is zigzag varints + raw IEEE-754 bytes + length-prefixed byte strings — no external Avro library
needed for the `"null"` codec. `write_chunk()` reads each row's fields directly out of the chunk's own
column buffers (`nanom::soa<T>::chunk::as<V>(i)`) rather than reconstructing a `T` value first, since
`soa<T>` never stores rows any other way.

### The heavier sinks: nanoshark

Parquet and Lance both need external libraries nanom itself never depends on, so they live in a sibling
repo, [nanoshark](https://github.com/yoavbendor/nanoshark), which vendors nanom (plus
[nanoarrow2parquet](https://github.com/yoavbendor/nanoarrow2parquet) and
[nanolance](https://github.com/yoavbendor/nanolance)) as read-only git submodules. The bridge between
nanom's columnar storage and either target schema is `nanom_shark/soa_columns.hpp`'s `columns_of<T>` — a
compile-time leaf-column **type list** that mirrors `nanom::soa<T>::columns()`'s own dotted-name
flattening exactly (same names, same order, same per-row size — proven by `tests/test_soa_columns.cpp`
across every current row shape), so nanoshark's Parquet and Lance writers both fold it into their own
`Field<Name, T>...`/`column<T, Name>...` packs once and feed `nanom::soa<T>::chunk::as<Type>(i)` spans
straight into `write_chunk()`/`write_batch()` — zero-copy for every fixed-width column, including
MAC/IP-shaped `fixed_size_binary` columns.

Both sinks iterate `for_each_table`, so neither needs an edit when a protocol is added. Lance keeps
exactly one per-table special case: its `packets` table (mirroring nanom's own `PacketRow`)
additionally carries a `lance.blob.v2 payload_ref` column resolving each packet's raw bytes back to the
source capture file (`uri` = the file, `position`/`size` = that packet's `file_offset`/`caplen`), so
every other table joins back to it by `packet_id` alone and never touches raw file bytes itself. That
special case is a compile-time `if constexpr` on the row type with the name check nested inside, and
nanoshark's `check_lance.py` asserts both directions of it — `payload_ref` present on `packets` with the
recorded offsets, and absent from every other table.

## See also

- [Design](design.md) — the `describe<T>` seam, zero-copy views, error model (the ideas nanom_shark
  builds on).
- [Memory safety](MEMORY_SAFETY.md) — `NANOM_GENERATION`/`NANOM_GUARD_VIEWS` and what they catch.
- [nanoshark](https://github.com/yoavbendor/nanoshark) — the Parquet/Lance integration repo.
