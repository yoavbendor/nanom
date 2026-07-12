---
title: nanom — a nom-style binary parser combinator for C++23/26
---

# nanom

**A header-only C++23/26 parser-combinator library for binary formats, modeled on Rust's
[nom](https://github.com/rust-bakery/nom)** — plus struct reflection (macro-free under C++26 P2996),
automatic schemas (Apache Arrow / Avro / JSON / CSV), and columnar Struct-of-Arrays storage for
[nanoarrow](https://github.com/apache/arrow-nanoarrow) / Lance.

If you know nom, you already know nanom: every combinator exists under the same name — `tag`, `take`,
`alt`, `opt`, `many0`, `preceded`, `length_data`, `be_u16`, `map`, `verify`, `cut`, `context`. The
nom-parallel parser is one self-contained header (`nom.hpp`); reflection and the data-tooling extras
layer cleanly on top.

[Get started](getting-started.md){ .md-button .md-button--primary }
[Safety for Rust reviewers](RUST_SAFETY_REVIEW.md){ .md-button .md-button--primary }
[Memory safety](MEMORY_SAFETY.md){ .md-button }
[Threat model](THREAT_MODEL.md){ .md-button }
[Cheat sheet](CHEATSHEET.md){ .md-button }
[API reference](https://yoavbendor.github.io/nanom/api/){ .md-button }
[GitHub](https://github.com/yoavbendor/nanom){ .md-button }

## Streaming + safety posture

nanom follows nom's streaming contract directly: parse on `nm::streaming(input)`, and on short prefixes
you get `errk::incomplete` with `needed` so callers can refill and retry.

Safety defaults are strong by default and configurable:

- `NANOM_GENERATION=1` — `wire_arena` runtime stale-buffer detection on `view` / `bytes` access
- `NANOM_GUARD_VIEWS=1` — guard null/uninitialized `view` access
- safe null input handling (`from(nullptr, n>0)` => empty input)
- bounded streaming `needed` (`max_incomplete_needed = 64 KiB`)
- bounds-checked consume on every combinator (`take`, `overlay`, `strct`, …); **`overlay` does not `reinterpret_cast` wire to `T*`** — byte assembly + `std::bit_cast` ([details](MEMORY_SAFETY.md#overlay-decode-strict-aliasing-and-unaligned-reads))
- checked cursor helpers (`safe_at`, `checked_advance`) for defensive hand-rolled paths
- continuous libFuzzer in CI (`fuzz_scan_walk`, `fuzz_streaming_pcapng`, `fuzz_defrag`) + ASan/UBSan matrix

**Coming from Rust nom?** Read [Safety for Rust reviewers](RUST_SAFETY_REVIEW.md) — it
preempts the usual lifetime, UB, and overflow objections with what is enforced, what is
fuzzed, and what remains caller contract. Also see [memory-safety model](MEMORY_SAFETY.md)
and [threat model + checklist](THREAT_MODEL.md).

**Safety- and speed-obsessed?** The [strict profile](COMPILE_TIME_SAFETY.md)
(`-DNANOM_STRICT=1`) narrows the API at compile time — no raw `from(ptr, len)`, no
owning-temporary parses, no GPU/bulk raw-pointer scatter, `[[clang::lifetimebound]]`
diagnostics — so the runtime can drop generation tracking and view guards for a leaner data
model (`input` 48→32 B, `bytes` 32→16 B). Benchmarks at parity with the unchecked build:
**compile-time-enforced memory safety at zero runtime cost**, proven by `WILL_FAIL` negative
compile tests.

## As fast as Rust nom — proven, not asserted

The headline question for a C++ nom-alike is *"is it actually as fast as Rust nom?"* nanom answers it
falsifiably: the **same streaming pcapng parse in both languages, on the same file, with output proven
byte-identical before any timing is reported** (the harness asserts the aggregate checksums match, then
prints the table — see [the full methodology](BENCH_RUST_NOM.md)). Every parser reads each Enhanced
Packet Block's fixed fields **and walks all of its option TLVs** — the full block, not a subset.

| parser | work | ns/packet | throughput | output |
|---|---|---:|---:|---|
| **nanom** (`minimal`) | EPB fields + all options | **~84** | ~17 GiB/s | identical |
| **nanom** (`full`) | same + generation tracking | ~82 | ~18 GiB/s | identical |
| **Rust nom** (hand-written) | EPB fields + all options (equal work) | ~83 | ~18 GiB/s | identical |
| Rust `pcap-parser` lib | same, + allocates options | ~138 | ~11 GiB/s | identical |

**Equal-work head-to-head: nanom ~84 ns/pkt vs stable Rust nom ~83 ns/pkt — parity**, both parsing the
full block (fixed fields + every option) zero-copy with no per-packet allocation. The full safety
profile stays within best-of-5 noise on this workload. Reproduce with
`python3 bench/compare_rust.py --build --safety both`; this is scoped evidence, not a universal claim.

## Why nanom

- **Zero-copy, always.** Parsers return spans/views into your buffer.
- **nom names.** If you know nom, you know nanom ([cheat sheet](CHEATSHEET.md)).
- **Structs are parsers.** Under **C++26 P2996 reflection, any eligible struct just works — zero
  registration, zero macros** ([details](P2996_COMPAT.md)). Under C++23, one `NANOM_DESCRIBE` line
  registers it. Endianness (`be<>`/`le<>`) and bit fields (`ubits<>`, msb0 *and* lsb0) live in the
  field types. `strct<T>()` parses by value; `overlay<T>()` gives a zero-copy `view<T>` with
  `v.get<"field">()`.
- **Schemas for free.** `schema_of<T>()`, Arrow C-data format strings, `avro_schema<T>()`,
  `to_json`/`csv_row`, and `soa<T>` — column-wise chunked accumulation ready for Arrow/Lance buffers.
- **Localized errors.** Allocation-free error values; `render()` prints the offset, the `context()`
  chain, and a hex window with a caret.
- **Header-only, no dependencies.** gcc ≥ 13, clang ≥ 18 for the C++23 macro path; a P2996 compiler
  (Bloomberg clang-p2996) for the macro-free C++26 path.

## 60-second tour

```cpp
#include <nanom/nanom.hpp>
namespace nm = nanom;

// 1. describe the wire format as a struct — endianness/bits in the types
struct eth_hdr {
  std::array<std::uint8_t, 6> dst, src;
  nm::be<std::uint16_t>       eth_type;      // big-endian on the wire
};
NANOM_DESCRIBE(eth_hdr, dst, src, eth_type); // (optional under C++26 reflection)

// 2. parse — result is {value, rest} or a localized error
nm::input in = nm::from(buf, len);
auto r = nm::strct<eth_hdr>()(in);
if (!r) { std::puts(r.error().render(in).c_str()); return; }
std::uint16_t etype = r->value.eth_type;     // host order via implicit convert

// 3. combine — nom vocabulary
auto frames  = nm::many0(nm::strct<eth_hdr>());
auto request = nm::seq(nm::alt(nm::tag("GET"), nm::tag("POST")),
                       nm::preceded(nm::space1, nm::take_until(" ")));

// 4. dump — schema + columnar storage for nanoarrow / lance
nm::soa<eth_hdr> table;                       // SoA, chunked
table.push(r->value);
nm::avro_schema<eth_hdr>();                   // {"type":"record",...}
```

Read on: **[Getting started](getting-started.md)** · **[Cheat sheet](CHEATSHEET.md)** ·
**[Design](design.md)** · **[C++26 reflection](P2996_COMPAT.md)** ·
**[Benchmarks](BENCH_RUST_NOM.md)**.
