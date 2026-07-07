# Safety for Rust reviewers

This page answers the questions a **nom / cargo-fuzz** audience typically asks when
evaluating a zero-copy C++ parser: dangling views, type-punning UB, and integer
overflow on length-prefixed fields.

nanom is **not** Rust: there is no borrow checker. The library instead combines
**runtime generation tracking**, **bounds-checked combinators**, **continuous
fuzzing**, and **honest gap tests** that document what remains caller contract.

For the full enforcement matrix see [Memory safety](MEMORY_SAFETY.md). For review
checklists and CI commands see [Threat model](THREAT_MODEL.md).

---

## Quick comparison to nom

| Concern | Rust nom | nanom |
|---------|----------|-------|
| Zero-copy output | `&'a [u8]` tied to input lifetime | `bytes` / `view<T>` over caller buffer |
| Lifetime enforcement | compile-time borrow checker | `wire_arena` generation checks (default-on) + documented contract |
| Out-of-bounds reads | safe indexing / slice bounds | combinators gate on `in.size()` before every consume |
| Hostile length prefixes | `Incomplete` / caller policy | `incomplete` + `max_incomplete_needed` (64 KiB cap) |
| Regression testing | `cargo-fuzz`, unit tests | libFuzzer in CI + sanitizer matrix + enforced safety suites |

---

## 1. Lifetime and dangling views

### The Rust objection

nom returns `IResult<&'a [u8], T<'a>>`. The compiler prevents holding a parsed
view after the backing buffer is freed. In C++, a `view<T>` or `bytes` span can
outlive its buffer unless something catches the misuse.

### What nanom does

**Default-on generation tracking** (`NANOM_GENERATION=1`) registers the wire
buffer in a `wire_arena`. Parsed `input`, `bytes`, and `view<T>` carry a
generation snapshot. On `view::get`, `view::raw`, `bytes::operator[]`, and
`bytes::at`, nanom verifies the arena generation is unchanged and the access lies
inside the registered range.

```cpp
std::vector<std::byte> buf = load();
nm::wire_arena arena;
auto r = nm::overlay<my_hdr>()(nm::from(buf.data(), buf.size(), arena));
auto v = r->value;

buf.clear();
arena.invalidate();   // or arena.open() after realloc

// Stale access is caught at runtime (abort+report, or generation_exception if enabled):
// v.get<"field">();
```

| Mode | Behavior |
|------|----------|
| `from(span, arena)` | Generation-attested parses; stale access faulted |
| `from(span)` alone | Documented caller contract (`span_lifetime_is_caller_scoped`) |
| `NANOM_GENERATION=0` | Opt-out for embedded/legacy; contract-only |

CI runs the **safety-first** profile (`NANOM_GUARD_VIEWS=ON`, `NANOM_GENERATION=ON`)
and enforced suites (`nanom_memory_safety_tests`, `nanom_generation_tests`,
`nanom_streaming_safety_tests`). The **full** safety profile is also benchmarked
against minimal opt-out on the streaming pcapng harness — overhead stays within
20% (`perf-budget` CI job).

### Honest limits

This is **runtime** enforcement, not a borrow checker:

- Tracking requires `from(buf, arena)` — plain `from(buf)` is contract-only.
- `bytes::data()`, `as_str()`, and `unchecked_span()` can bypass attestation (documented in gap tests).
- In-place wire mutation behind a live view is not auto-detected when generation is unchanged.

See the `WILL_FAIL` gap suites (`nanom_memory_safety_gap_tests`,
`nanom_memory_safety_gap_generation_tests`) for the residual hazard list.

!!! note "Future: Clang lifetime bounds"
    Annotating `from()` and parse results with `[[clang::lifetimebound]]` is planned
    as a compile-time complement to generation tracking. Not implemented yet.

---

## 2. Type punning, strict aliasing, and unaligned reads

### The Rust objection

Crates like `zerocopy` and `bytemuck` exist because casting `*const u8` to
`*const MyStruct` is UB in Rust and C++ (strict aliasing, alignment traps on
some ISAs). If `overlay<T>()` were a `reinterpret_cast`, reviewers would reject it.

### What nanom does

`overlay<T>()` does **not** cast wire bytes to a `T*`. A `view<T>` holds a
`const std::byte* p` and **decodes on access**:

- Integral and floating fields: byte assembly into a local integer, then
  `std::bit_cast` to the field type.
- `be<>` / `le<>` / `ubits<>` / `ibits<>`: wire-order extraction with shift/mask
  over covering bytes (unaligned-safe; no struct pointer cast).
- `strct<T>()`: same decode path, materializing a value instead of a lazy view.

`layout_ok<T>()` is a compile-time check: non-bit fields are byte-aligned and
the wire size is a whole number of bytes.

`overlay` / `strct` parsers also bounds-check before exposing a view:

```cpp
if (in.size() < wire_size_v<T>) return make_incomplete(in, need - in.size());
```

### Honest limits

- Byte-array fields (MAC addresses, etc.) return a `span` into the buffer — still
  zero-copy, still caller-lifetime scoped.
- Callers must not mutate wire bytes behind an active `view<T>`
  (`overlay_wire_must_be_immutable`).

---

## 3. Integer overflow and TLV lengths

### The Rust objection

Parsing `length` then `take(length)` is a classic overflow/OOB vector when
`offset + length` wraps or exceeds the buffer.

### What nanom does

Every consume combinator checks **remaining size** before reading:

```cpp
// take(n): fails incomplete/err when n > in.size()
if (in.size() < n) return make_incomplete(in, n - in.size());
```

The same pattern applies to `tag`, numeric parsers, `overlay`, and `strct`.
`length_data(np)` reads a length, then delegates to `take(n)` which re-checks.

Additional guards:

| Mechanism | Role |
|-----------|------|
| `max_incomplete_needed` (64 KiB) | Caps hostile streaming `incomplete.needed` |
| `wire_arena::contains(p, len)` | Range check before attested access |
| `dec<T>()` | Overflow-checked decimal parse |
| `checked_many0(p, cap)` | Iteration budget for hand-rolled loops |

### Fuzzing and sanitizers

Continuous coverage-guided fuzzing in CI:

| Target | Exercises |
|--------|-----------|
| `self_fuzz` | Arbitrary bytes through core combinators (ctest) |
| `fuzz_scan_walk` | pcap block scan + packet walk |
| `fuzz_streaming_pcapng` | Streaming refill with variable cap (16..8192 B), `NANOM_GENERATION=1` |

Plus ASan/UBSan matrix builds and the `streaming-sanitizer` job (ASan + streaming
tests + 120 s fuzz run).

`overflow_parity` in `test_nom_parity.cpp` matches nom's adversarial
`many0(length_data(be_u64))` behavior on truncated input.

### Honest limits

- Hot-path `input::advance()` and `input::operator[]` are **precondition-based**
  for speed; use `checked_advance()` / `safe_at()` in defensive code.
- `attested_bytes::operator[]` does not fault OOB the way `at()` does (gap test).

---

## What we do not claim

nanom does **not** guarantee:

- Confidentiality, integrity beyond process memory safety, or side-channel resistance.
- Compile-time prevention of all dangling-view bugs (no borrow checker).
- Detection of in-place wire mutation without a generation transition.
- That every API surface is bounds-checked — some fast paths document preconditions.

These limits are tracked in [Threat model — known gaps](THREAT_MODEL.md#known-gaps-and-residual-risk)
and enforced as `WILL_FAIL` tests until hardened.

---

## Verify it yourself

```sh
# Core + safety regression
cmake -B build -DCMAKE_CXX_COMPILER=g++-13 -DNANOM_WERROR=ON
cmake --build build -j
ctest --test-dir build -R 'nanom_memory_safety_tests|nanom_generation_tests|nanom_streaming_safety_tests' --output-on-failure

# Gap suite (intentionally failing — documents residual hazards)
ctest --test-dir build -R 'nanom_memory_safety_gap' --output-on-failure

# Perf: full safety vs minimal opt-out (must stay within 20% on streaming pcapng)
python3 bench/compare_rust.py --build --safety both --iters 10000 --max-overhead 1.20

# Local fuzz (needs clang + NANOM_BUILD_FUZZERS=ON)
cmake -B build-fuzz -DCMAKE_CXX_COMPILER=clang++-18 -DNANOM_BUILD_FUZZERS=ON
cmake --build build-fuzz --target fuzz_streaming_pcapng
./build-fuzz/fuzz_streaming_pcapng -max_total_time=60 corpus_streaming/
```

---

## Related pages

- [Memory safety model](MEMORY_SAFETY.md) — enforced guards, generation API, caller contract
- [Threat model + reviewer checklist](THREAT_MODEL.md) — scope, gaps, PR checklist
- [Fuzz harnesses](../fuzz/README.md) — target descriptions and build commands
- [vs Rust nom (streaming pcapng)](BENCH_RUST_NOM.md) — equal-work benchmark methodology
