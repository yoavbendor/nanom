# nanom

[![ci](https://github.com/yoavbendor/nanom/actions/workflows/ci.yml/badge.svg)](https://github.com/yoavbendor/nanom/actions/workflows/ci.yml) [![fuzz](https://github.com/yoavbendor/nanom/actions/workflows/fuzz.yml/badge.svg)](https://github.com/yoavbendor/nanom/actions/workflows/fuzz.yml) [![bench](https://github.com/yoavbendor/nanom/actions/workflows/bench.yml/badge.svg)](https://github.com/yoavbendor/nanom/actions/workflows/bench.yml) [![docs](https://img.shields.io/badge/docs-yoavbendor.github.io%2Fnanom-indigo)](https://yoavbendor.github.io/nanom/)

A **header-only C++23 parser-combinator library** for binary formats, modeled
on Rust's [nom](https://github.com/rust-bakery/nom) — plus struct reflection,
automatic schemas (Arrow / Avro / JSON / CSV) and columnar chunked storage for
[nanoarrow](https://github.com/apache/arrow-nanoarrow) / Lance. The nom-parallel
parser is one self-contained header ([`nom.hpp`](#library-layout)); the reflection
and data-tooling extras layer cleanly on top.

📖 **[Documentation site](https://yoavbendor.github.io/nanom/)** ·
🗺️ **[nom → nanom cheat sheet](docs/CHEATSHEET.md)** ·
📐 **[API reference](https://yoavbendor.github.io/nanom/api/)**

## As fast as Rust nom — proven, not asserted

The point of a C++ nom-alike is *"is it actually as fast as Rust nom?"* nanom answers falsifiably: the
**same streaming pcapng parse in both languages, on the same file, with output proven byte-identical
before any timing is reported** (the harness asserts the aggregate checksums match, then prints the
table — [full methodology](docs/BENCH_RUST_NOM.md)). Every parser reads each Enhanced Packet Block's
fixed fields **and walks all of its option TLVs** — the full block, not a subset.

| parser | work | ns/packet | throughput | output |
|---|---|---:|---:|---|
| **nanom** (`nm::streaming`) | EPB fields + all options | **~110** | ~13 GiB/s | identical |
| **Rust nom** (hand-written) | EPB fields + all options (equal work) | ~119 | ~12 GiB/s | identical |
| Rust `pcap-parser` lib | same, + allocates options | ~203 | ~7 GiB/s | identical |

**Equal-work head-to-head: nanom ~110 ns/pkt vs stable Rust nom ~119 ns/pkt — parity**, a hair in
nanom's favour, both parsing the full block (fixed fields + every option) zero-copy with no per-packet
allocation; against the real `pcap-parser` library doing the identical parse, nanom is ~1.85× faster
(the difference is the library's per-packet `Vec`). Scoped and reproducible
(`python3 bench/compare_rust.py --build`); it is *not* "nanom beats nom in general".

## Try it

**▶ Try it live in Compiler Explorer** — a one-click, no-setup [tour](try/godbolt.cpp) (parse → overlay
view → `soa<>` columns → Avro schema).
<!-- maintainers: run `python3 tools/make_godbolt.py` to mint the permalink, then replace the line above
     with:  **▶ [Try it live in Compiler Explorer](https://godbolt.org/z/XXXX)** -->

Mint that permalink in one command (it inlines the single-header amalgamation and the tour into one
Compiler Explorer session, then prints the `godbolt.org/z/…` link):

```sh
python3 tools/make_godbolt.py            # prints the permalink to drop into the link above
```

Or run the tour locally / paste it yourself — the generated single-file
[`nanom-single.hpp`](https://yoavbendor.github.io/nanom/nanom-single.hpp) (an amalgamation of the
layered headers; the modular ones stay canonical) plus [`try/godbolt.cpp`](try/godbolt.cpp):

```sh
python3 tools/amalgamate.py --out nanom-single.hpp   # regenerate locally
g++-13 -std=c++23 -I . try/godbolt.cpp -o tour && ./tour
```

- **Zero-copy, always.** Parsers return spans/views into your buffer.
- **nom names.** If you know nom, you already know nanom
  ([cheat sheet](docs/CHEATSHEET.md)). All of nom's combinators are here.
- **Structs are parsers.** Under **C++26 (P2996 reflection), any eligible struct
  just works — zero registration, zero macros** ([nanom26](#c26-macro-free-nanom26)).
  Under C++23, one `NANOM_DESCRIBE` line registers it. Endian (`be<>`, `le<>`,
  mixed) and bit fields (`ubits<>`, msb0 *and* lsb0) live in the field types.
  `strct<T>()` parses by value, `overlay<T>()` gives a zero-copy `view<T>` with
  `v.get<"field">()`.
- **Schemas for free.** `schema_of<T>()`, Arrow C-data format strings,
  `avro_schema<T>()`, `to_json` / `csv_row` for debugging, and `soa<T>` —
  column-wise chunked accumulation ready for Arrow/Lance buffers.
- **Localized errors.** Allocation-free error values; `render()` prints
  offset, `context()` chain, and a hex window with a caret.
- Header-only, no dependencies. gcc ≥ 13, clang ≥ 18 for the C++23 macro path;
  a P2996 compiler (Bloomberg clang-p2996) for the macro-free C++26 path.

```
cmake: add_subdirectory(nanom) + link nanom::nanom     — or copy the include/nanom/ folder
```

## Library layout

`#include <nanom/nanom.hpp>` pulls in everything (that umbrella is all any consumer needs). But the
code lives in layered headers, so the file structure itself is the map — pure nom parallel, then the
reflection add-on, then the data-tooling extras:

| header | what | depends on |
|---|---|---|
| `nanom/nom.hpp` | **the rust-nom parallel** — `input`/`result`/`Parser`, every combinator (tag/take/alt/many0/preceded/…), binary numbers (`be_u16`…), text numbers (`dec`/`hex`/`float`), bit-level parsing. **Include this alone for the parser-only subset.** | — (self-contained) |
| `nanom/reflect.hpp` | struct reflection: `fixed_string`, wire types (`be<>`/`ubits<>`), the `describe<T>` seam, `strct<T>()`, `overlay<T>()`/`view<T>` | `nom.hpp` |
| `nanom/schema.hpp` | *extra* — `schema_of<T>()`, Arrow format strings, `avro_schema`, `to_json`/`csv_row` | `reflect.hpp` |
| `nanom/soa.hpp` | *extra* — `soa<T>` columnar (SoA) chunked storage | `schema.hpp` |
| `nanom/bulk.hpp` | *extra, opt-in* — data-parallel (GPU-ready) SoA scatter | `soa.hpp` |
| `nanom/nanom26.hpp`, `nanom/describe_macro.hpp` | the two `describe<T>` providers (C++26 reflection / `NANOM_DESCRIBE` macro), included by `reflect.hpp` | — |
| `nanom/prelude.hpp` | shared config: std includes, `NANOM_HD`, feature probes | — |

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

## C++26: macro-free (nanom26)

With a P2996 compiler the `NANOM_DESCRIBE` lines above simply disappear — the struct definitions
ARE the registration ([include/nanom/nanom26.hpp](include/nanom/nanom26.hpp) auto-describes every
eligible aggregate by static reflection, synthesizing the exact metadata the macro would have):

```cpp
struct eth_hdr {
  std::array<std::uint8_t, 6> dst, src;
  nm::be<std::uint16_t>       eth_type;
};  // ...that's it. strct<>/overlay<>/soa<>/to_json/avro all work; nothing to register.
```

Eligible = named non-union class, no bases, ≥1 member, all members public/named/non-bitfield, and
not inside `std`/`nanom` (`nanom::Reflectable`). Existing `NANOM_DESCRIBE` lines still compile:
each becomes a `static_assert` proving reflection covers that type (define
`NANOM_DESCRIBE_FORCE_MACRO` to keep explicit registration, which also overrides reflection
per-type, e.g. for a member subset). See [examples/reflect26.cpp](examples/reflect26.cpp) — the
zero-registration showcase — and [docs/P2996_COMPAT.md](docs/P2996_COMPAT.md) for the toolchain
survey. Build:

```sh
# today's P2996 compiler: the Bloomberg clang-p2996 fork (<meta> needs its libc++)
cmake -B b26 -DCMAKE_CXX_COMPILER=<fork>/bin/clang++ -DNANOM_CXX26_REFLECTION=ON
cmake --build b26 -j && ctest --test-dir b26        # full suite runs macro-free
```

The whole test + parity corpus passes in pure-reflection mode byte-identically; CI runs it as the
advisory `reflection-cxx26` job. One thing reflection cannot replace: `NANOM_HD` (the CUDA
host/device qualifier) stays a macro, and nvcc TUs keep the macro path automatically.

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

## From Python (zero-copy into Arrow / polars)

Because `soa<T>` columns are already Arrow buffers, you can parse a binary format in C++ with nanom and
hand Python a **zero-copy** Arrow table — straight into polars / pandas / pyarrow / duckdb. On a pcapng
capture producing the same table, nanom is **~35× faster than dpkt and ~90× faster than python-pcapng**
(it parses in C++; the columns need no conversion).

```python
import nanom_pcap, pyarrow as pa, polars as pl
df = pl.from_arrow(pa.table(nanom_pcap.parse(open("cap.pcapng","rb").read())))   # zero-copy both hops
df.group_by("ethertype").agg(pl.col("caplen").mean())
```

The C++ side is one struct + a parse loop; the Arrow bridge (`soa<T>` → `ArrowArrayStream` via the
Arrow PyCapsule protocol) is reusable and nanoarrow-free. Full worked example — both sides, build, and
the benchmark — in [`bindings/python/`](bindings/python/).

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

CI (see `.github/workflows/`) runs on every push/PR:

| workflow | what it does |
|---|---|
| **ci** | build + full `ctest` across `{g++-13, g++-14, clang-18} × {Debug, Release}` with `-Werror`; ASan+UBSan and TSan runs; installed-package `find_package` consumer; each header compiles standalone; macOS portability, extra-warnings, clang-tidy and coverage as advisory jobs |
| **fuzz** | coverage-guided libFuzzer over the pcap scan + L2–L4 walk (ASan+UBSan), 2 min per push, 15 min nightly, seeded from the pcap fixtures |
| **bench** | Release benchmarks tracked over time with regression alerts (`benchmark-action`) |

Reproduce any CI mode locally via CMake options:

```sh
cmake -B b -DNANOM_WERROR=ON                          # warnings are errors
cmake -B b -DNANOM_SANITIZER=address,undefined        # or =thread
cmake -B b -DNANOM_BUILD_FUZZERS=ON -DCMAKE_CXX_COMPILER=clang++-18
python3 bench/collect.py b                             # benchmark numbers as JSON
```

Licensed under [Apache-2.0](LICENSE) — see [NOTICE](NOTICE) and [THIRD-PARTY.md](THIRD-PARTY.md).
The library has no third-party code dependencies (C++ standard library only).
