# nanom memory safety

nanom's parse path is **zero-copy**: `input`, `bytes`, and `view<T>` reference
caller-owned buffers. Combinators bound-check before every consume; this document
covers what the library **does** enforce and what remains **caller contract**.

**Rust / nom reviewers:** start with [Safety for Rust reviewers](RUST_SAFETY_REVIEW.md)
for a focused answer to lifetime, type-punning UB, and TLV overflow questions.

## Enforced by the library

| Guard | Where | Notes |
|-------|-------|-------|
| Consume bounds | `take`, `tag`, `be_u*`, `overlay`, `strct` | `in.size()` checked before read |
| Zero-consumption | `many0`, `checked_many0` | Inner parser must advance cursor |
| Null `from` | `from(nullptr, n>0)` | Returns empty input |
| Checked accessors | `safe_at`, `checked_advance` | Opt-in; `advance`/`operator[]` stay fast |
| Tag pattern lifetime | `tag()` / `tag_no_case()` | Pattern stored by value (SBO ≤15 B) |
| Streaming `needed` cap | `make_incomplete` | `max_incomplete_needed` (64 KiB) |
| Error render window | `error::render` | Offset clamped to buffer |
| Bulk descriptors | `pkt_ref_valid`, `bulk_decode` | Rejects null data + nonzero len |
| Null view (debug) | `view::get` / `raw` / `to_struct` | `NANOM_GUARD_VIEWS` asserts `p != nullptr` |
| Generation tracking | `wire_arena`, `from(buf, arena)`, `view::get/raw`, `bytes` subscript | `NANOM_GENERATION=1`; enabled by default |
| Safe wire decode | `overlay`, `strct`, `view::get` | byte assembly + `std::bit_cast`; no `reinterpret_cast<T*>` (see below) |

## Overlay decode — strict aliasing and unaligned reads

**Does `overlay<T>()` just `reinterpret_cast` the byte buffer?**

**No.** A `view<T>` stores a `const std::byte* p` to the start of the struct's wire
image. Fields are **decoded on access** into local values — nanom never treats the
buffer as a live `T` object and never casts wire bytes to `T*`.

This is the same safety model as Rust's `zerocopy` / `bytemuck`: read bytes, assemble
a value, return it. Zero-copy means the **view handle** points at your buffer; field
**values** are produced by explicit decode, not aliasing.

### How decode works (`decode_field` in `reflect.hpp`)

| Field kind | Mechanism | UB avoided |
|------------|-----------|------------|
| Plain integrals / floats | Load wire bytes into a local integer `U` with a byte loop, then `std::bit_cast<F>(U)` | No type-punning through a pointer; no unaligned scalar load |
| `be<>` / `le<>` | Same byte assembly into host order | Same |
| `ubits<>` / `ibits<>` | Shift+mask over the covering bytes (or `read_bits` for odd layouts) | Unaligned bit fields: no cast to a wider type at an arbitrary offset |
| Nested structs | Recurse field-by-field | Same decode path as `strct<T>()` |
| `std::array` of 1-byte elements | Zero-copy `span` into the buffer (element pointer, not struct pointer) | Caller lifetime contract |

`overlay<T>()` and `strct<T>()` share this decode engine. `strct` materializes a full
`T` on the stack; `overlay` keeps the lazy `view<T>` and calls `decode_field` inside
`get<"field">()`.

Compile-time layout checks (`layout_ok<T>()`) require non-bit fields to start on byte
boundaries and the total wire size to be a whole number of bytes.

### What nanom does **not** do

- `reinterpret_cast<T*>(wire)` or `std::start_lifetime_as<T>(wire)` — the wire buffer
  is not presented as a `T` object.
- Unaligned wide loads through a misaligned `T*` or `uint32_t*` on the wire.
- Silent strict-aliasing violations from reading the same bytes as two incompatible types.

### Performance

The byte-assembly loops are `constexpr` and compile to the same machine code as a
hand-tuned overlay on hot paths (often one load + `bswap` for 2/4/8-byte fields).
Documenting the decode model does not change the implementation or its speed.

Implementation reference: [`include/nanom/reflect.hpp`](https://github.com/yoavbendor/nanom/blob/main/include/nanom/reflect.hpp)
(`decode_field`, `view<T>::get`, `overlay<T>()`).

## Generation tracking (`NANOM_GENERATION`)

Enabled by default. For strict perf/compat modes, users can opt out with
`-DNANOM_GENERATION=0`.

```cpp
std::vector<std::byte> buf = load();
nm::wire_arena arena;
nm::input in = nm::from(nm::bytes(buf.data(), buf.size()), arena);
auto r = nm::overlay<my_hdr>()(in);
auto v = r->value;
buf.clear();
arena.invalidate();           // or arena.open() after realloc
// v.get<"field">() → generation_exception with stale_generation report
```

| API | Role |
|-----|------|
| `wire_arena` | Registers `[base, size)`; `invalidate()` bumps generation |
| `attested_bytes` | Generation-attested `bytes` wrapper (`operator[]`, `at`) |
| `from(span, arena)` | Attaches arena snapshot to `input` |
| `generation_exception` | Thrown when `NANOM_GENERATION_THROW=1` |
| `render_generation_fault` | Human-readable report (gen diff, offset, hex) |
| `generation_handler` | Optional callback; return `ignore` only in tests |

CMake: `-DNANOM_GENERATION=ON|OFF` or define on one target. Tests: `nanom_generation_tests`.

## Caller contract (documented, not runtime-tracked without `NANOM_GENERATION`)

These `constexpr` flags mark the contract surface:

- `overlay_wire_must_be_immutable` — do not mutate bytes behind an active `view<T>`
- `span_lifetime_is_caller_scoped` — `bytes` and field spans outlive their owner
- `length_prefix_spans_are_unowned` — `length_data` payloads are plain spans

**Rules:**

1. Keep the buffer alive while any `input` cursor, `bytes` span, or `view<T>` into it exists.
2. Treat parsed wire as **read-only** while using `overlay` / `view`.
3. Use `checked_advance` / `safe_at` when building defensive parsers; keep `advance` on hot paths that already checked `size()`.
4. Prefer `checked_many0(p, cap)` for hand-rolled repetition loops; `many0` already rejects zero-consumption but has no iteration cap.
5. Build with `-fsanitize=address,undefined` and run `nanom_memory_safety_tests` / `nm_self_fuzz` in CI.

## Debug options

| Flag | Default | Effect |
|------|---------|--------|
| `NANOM_GUARD_VIEWS` | **on** | Assert null `view` access |
| `NANOM_GENERATION` | **on** | `wire_arena` lifetime checks on `view::get` |
| `NANOM_GENERATION_THROW` | off (abort+print) | Throw `generation_exception` instead of abort |
| `NANOM_STRICT` | off | "Safe routes only" profile — compile-time restrictions replace the runtime nets (see below) |

## Strict profile (`NANOM_STRICT`)

For safety- **and** speed-obsessed users: narrow the API at compile time so the
runtime can drop the checks those APIs made necessary. Strict deletes the raw
`from(ptr, len)` entry, deletes `from(std::string&&)` (owning-temporary dangle),
refuses `<nanom/bulk.hpp>` (GPU/bulk raw-pointer scatter), and adds
`[[clang::lifetimebound]]` diagnostics — then defaults `NANOM_GENERATION=0` and
`NANOM_GUARD_VIEWS=0` for a leaner, faster data model (`input` 48→32 B, `bytes`
32→16 B). Combinator bounds checks stay on. All three profiles benchmark at
parity (~82–84 ns/pkt) — **compile-time safety at the unchecked profile's speed**.

Full details, proofs, and safe-route examples: [Compile-time safety](COMPILE_TIME_SAFETY.md).

Future work: auto-tracked containers; stronger provenance/cross-arena diagnostics.

## Tests

- `tests/test_memory_safety.cpp` — regression suite (`NANOM_GUARD_VIEWS=1`, must pass)
- `tests/test_memory_safety_generation.cpp` — generation suite (`NANOM_GENERATION=1`, must pass)
- `tests/test_memory_safety_gaps.cpp` — **WILL_FAIL** residual hazards without generation tracking
- `tests/test_memory_safety_gaps_generation.cpp` — **WILL_FAIL** attested_bytes / arena gaps
- `tests/test_memory_safety_ub.cpp` — optional ASan red-team demos (`NANOM_MEMORY_SAFETY_UB_DEMOS=ON`)
- `tests/test_streaming_safety.cpp` — streaming/incremental refill safety (`nanom_streaming_safety_tests`)
- `tests/test_strict_profile.cpp` — strict profile contract + safe-route parsing (`nanom_strict_profile_tests`)
- `tests/strict_neg/*.cpp` — **WILL_FAIL** negative compile tests proving strict rejects unsafe routes
- `bench/safety_microbench.cpp` — performance baselines per guard

CMake registers gap targets when `NANOM_MEMORY_SAFETY_GAP_TESTS=ON` (default). Remove
`WILL_FAIL` from a gap test only when every targeted `CHECK` in that file passes.

## CI safety-first profile

The `safety-first` CI job builds with `NANOM_GUARD_VIEWS=ON` and `NANOM_GENERATION=ON`
(explicitly matching library defaults) and runs enforced safety regression tests.

The separate `perf-budget` job runs `bench/compare_rust.py --safety both --max-overhead 1.20`:
full safety (generation + view guards + `wire_arena` on the streaming refill buffer) must stay
within 20% of the opt-out minimal profile on the verified-equal streaming pcapng benchmark.

The `strict-profile` job builds the strict profile, runs its runtime suite and the
negative compile tests (`nanom_strict_rejects_*`), compiles it clang-clean to
exercise `lifetimebound`, and benchmarks strict vs minimal vs full.
