# nanom

A **single-header C++23 parser-combinator library** for binary formats, modeled
on Rust's [nom](https://github.com/rust-bakery/nom) — plus struct reflection,
automatic schemas (Arrow / Avro / JSON / CSV) and columnar chunked storage for
[nanoarrow](https://github.com/apache/arrow-nanoarrow) / Lance.

- **Zero-copy, always.** Parsers return spans/views into your buffer.
- **nom names.** If you know nom, you already know nanom
  ([cheat sheet](docs/CHEATSHEET.md)). All of nom's combinators are here.
- **Structs are parsers.** Register any C struct with `NANOM_DESCRIBE`; endian
  (`be<>`, `le<>`, mixed) and bit fields (`ubits<>`, msb0 *and* lsb0) live in
  the field types. `strct<T>()` parses by value, `overlay<T>()` gives a
  zero-copy `view<T>` with `v.get<"field">()`.
- **Schemas for free.** `schema_of<T>()`, Arrow C-data format strings,
  `avro_schema<T>()`, `to_json` / `csv_row` for debugging, and `soa<T>` —
  column-wise chunked accumulation ready for Arrow/Lance buffers.
- **Localized errors.** Allocation-free error values; `render()` prints
  offset, `context()` chain, and a hex window with a caret.
- Header-only, no dependencies. gcc ≥ 13, clang ≥ 17. (C++26 reflection will
  make `NANOM_DESCRIBE` optional; nothing else changes.)

```
cmake: add_subdirectory(nanom) + link nanom::nanom     — or just copy include/nanom/nanom.hpp
```

## 60-second tour

```cpp
#include <nanom/nanom.hpp>
namespace nm = nanom;

// 1. describe the wire format as a struct — endianness/bits in the types
struct eth_hdr {
  std::array<std::uint8_t, 6> dst, src;
  nm::be<std::uint16_t>       eth_type;      // big-endian on the wire
};
NANOM_DESCRIBE(eth_hdr, dst, src, eth_type); // at global scope

struct vlan_hdr {
  nm::ubits<3>  pcp;                         // bit fields, msb0 (network) order
  nm::ubits<1>  dei;
  nm::ubits<12> vid;
  nm::be<std::uint16_t> eth_type;
};
NANOM_DESCRIBE(vlan_hdr, pcp, dei, vid, eth_type);

// 2. parse — result is {value, rest} or a localized error
nm::input in = nm::from(buf, len);
auto r = nm::strct<eth_hdr>()(in);
if (!r) { std::puts(r.error().render(in).c_str()); return; }
std::uint16_t etype = r->value.eth_type;     // host order via implicit convert

// zero-copy alternative: decode on access
auto v = nm::overlay<vlan_hdr>()(r->rest);
unsigned vid = v->value.get<"vid">();        // unknown names = compile error

// 3. combine — nom vocabulary
auto frames  = nm::many0(nm::strct<eth_hdr>());
auto tlv     = nm::flat_map(nm::u8, [](auto len) { return nm::take(len); });
auto request = nm::seq(nm::alt(nm::tag("GET"), nm::tag("POST")),
                       nm::preceded(nm::space1, nm::take_until(" ")));

// 4. dump — schema + columnar storage for nanoarrow / lance
nm::soa<eth_hdr> table;                      // SoA, chunked (default 64Ki rows)
table.push(r->value);
for (auto& c : table.columns())              // c.arrow == "w:6", "S", ...
  std::printf("%s %s\n", c.name.c_str(), c.arrow.c_str());
table.for_each_chunk([](auto& ch) { /* ch.col(i) -> contiguous bytes */ });
nm::avro_schema<eth_hdr>();                  // {"type":"record",...}
nm::to_json(r->value); nm::csv_header<eth_hdr>(); nm::csv_row(r->value);
```

## Copy-paste starters

**Length-prefixed record (TLV):**
```cpp
struct tlv_hdr { std::uint8_t type, len; };
NANOM_DESCRIBE(tlv_hdr, type, len);
auto tlv  = nm::flat_map(nm::strct<tlv_hdr>(), [](tlv_hdr h) {
  return nm::map(nm::take(h.len), [h](nm::bytes v) { return std::pair{h, v}; });
});
auto tlvs = nm::all_consuming(nm::many0(tlv));    // parse a whole payload
```

**Runtime endianness (ELF-style — `EI_DATA` decides):**
```cpp
struct hdr { std::uint16_t type; std::uint64_t entry; };  // plain fields
NANOM_DESCRIBE(hdr, type, entry);
auto order = data_byte == 2 ? std::endian::big : std::endian::little;
auto h = nm::strct<hdr>(order)(in);               // one struct, both orders
```

**Precise errors with context + cut:**
```cpp
auto ip = nm::context("ipv4",
    nm::verify(nm::strct<ipv4_hdr>(), [](auto& h) { return h.version == 4; }));
auto pkt = nm::preceded(nm::tag("\x08\x00"), nm::cut(ip));  // cut = commit
// on failure: r.error().render(in) ->
//   parse failure at offset 18: expected verify: predicate
//     in ipv4 (starting at offset 18)
//     ... hex window with ^^ caret ...
```

**Streaming (packet reassembly):**
```cpp
auto r = parser(nm::streaming(nm::from(buf, have)));
if (!r && r.error().kind == nm::errk::incomplete)
  refill(r.error().needed);                        // fetch and re-run
// default (non-streaming) inputs treat end-of-input as a normal error,
// so many0/alt just stop — no complete() wrapping needed.
```

**Text parsing works too:**
```cpp
auto kv = nm::separated_pair(nm::alpha1, nm::chr('='), nm::dec<int>());
auto csv = nm::separated_list1(nm::chr(','), nm::dec<int>());
```

## Worked examples

| file | demonstrates |
|---|---|
| [examples/ethernet.cpp](examples/ethernet.cpp) | Eth → VLAN → IPv4 → UDP → TLV: bit fields, protocol switches, verify, context errors, soa export |
| [examples/elf.cpp](examples/elf.cpp) | magic tags, runtime BE/LE selection, cut(), offset seeking, count() |
| [examples/fat16.cpp](examples/fat16.cpp) | zero-copy views, lsb0 attribute bits, misaligned le<> fields, fixed 32-byte records |

## Data-parallel bulk decode (CPU now, GPU-ready)

For throughput, `<nanom/bulk.hpp>` decodes many packets in parallel into SoA
columns — one task per packet, each scattering its row at its own index
(disjoint writes: no locks, no atomics, no allocation). The per-packet kernel is
a POD, `NANOM_HD`-annotated function written with `overlay<>`/`get<>`, so the
same code runs on a CPU thread pool today and compiles for a CUDA/HIP grid.

```cpp
nm::bulk_table<PacketRow> tbl;
nm::bulk_decode(packets, tbl, kernel, nm::par_exec{});   // kernel: bool(pkt_ref&, Row&)
auto ports = tbl.column<std::uint16_t>("dst_port");      // contiguous, Arrow-ready
```

Verified bit-identical to the serial path and ThreadSanitizer-clean; the decode
path is `static_assert`ed constexpr (device-pure). See [docs/GPU.md](docs/GPU.md).

## Docs

- [docs/CHEATSHEET.md](docs/CHEATSHEET.md) — every nom name → nanom name, one line each
- [docs/GPU.md](docs/GPU.md) — device readiness: what's `NANOM_HD`, and the CUDA launcher
- [docs/NANOTINS_COMPARISON.md](docs/NANOTINS_COMPARISON.md) — measured scorecard vs nanotins
- [DESIGN.md](DESIGN.md) — architecture, nom feature matrix, what was borrowed
  from Boost.Parser / parsi / ezpz / monadic-parser-combinator and why

## Build & test

```sh
cmake -B build && cmake --build build -j && ctest --test-dir build
```

Tests and all examples run clean under ASan + UBSan (`-fsanitize=address,undefined`).

MIT license.
