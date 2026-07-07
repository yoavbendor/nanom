# nanom threat model and reviewer checklist

This page describes what nanom's safety features do and do not guarantee, and
provides a concrete checklist for external memory-safety review.

## Scope and assumptions

nanom is a zero-copy parser library. Its core data model (`input`, `bytes`,
`view<T>`) references caller-owned memory. Safety depends on a mix of:

- library-enforced checks (bounds, streaming invariants, view guards, generation checks),
- caller contracts (lifetime, immutability while views are live),
- build/runtime hardening choices (sanitizers, fuzzing, defensive profile flags).

Out of scope:

- confidentiality/integrity beyond process memory safety,
- attacker model involving arbitrary code execution outside parser input,
- side-channel hardening.

## Assets and trust boundaries

Assets:

- process memory integrity and availability,
- parser correctness under malformed/untrusted byte streams.

Trust boundaries:

- **untrusted input bytes** crossing into parser combinators,
- **caller-managed buffer ownership/lifetime** crossing into zero-copy views.

## Safety goals

1. Prevent out-of-bounds reads on parse path.
2. Prevent null/uninitialized view dereference.
3. Detect stale/dangling tracked buffer access when generation tracking is enabled.
4. Keep streaming behavior deterministic under short prefixes (`incomplete` with bounded `needed`).
5. Preserve low-overhead hot-path behavior while allowing stricter opt-ins.

## Enforced protections (current)

| Protection | Mechanism | Default |
|---|---|---|
| Consume bounds checks | `take`, `tag`, numbers, `overlay`, `strct` gate on `in.size()` | on |
| Streaming short-prefix handling | `nm::streaming` + `errk::incomplete` + bounded `needed` | on |
| Needed cap | `max_incomplete_needed` (64 KiB) clamp | on |
| Null view access guard | `NANOM_GUARD_VIEWS` in `view::get/raw/to_struct` | on |
| Null input pointer handling | `from(nullptr, n>0)` => empty input | on |
| Defensive cursor helpers | `safe_at`, `checked_advance` | available |
| Generation lifetime checks | `wire_arena`, `NANOM_GENERATION`, `check_wire_access` | on |

## Caller contracts (required)

1. Keep the backing buffer alive while any `input`, `bytes`, or `view<T>` references it.
2. Treat wire bytes as immutable while overlays/views are live.
3. Call `wire_arena.invalidate()` / `open()` correctly on free/realloc/move of tracked buffers.

Violating these can produce UB when checks are disabled or bypassed by caller behavior.

## Known gaps and residual risk

- In-place mutation without generation transition is contract-level unless actively tracked by caller.
- Not all misuse patterns are runtime-detectable without additional provenance metadata.
- Some checks are assertion-based and behavior differs by build policy.

Track these in failing/gap safety tests and fuzz targets as they are added.

## Reviewer checklist

Use this checklist for PRs touching parse path, lifetime model, or docs claims.

### Code checks

- [ ] Bounds checks still dominate all consume paths before memory access.
- [ ] `nm::streaming` paths propagate `incomplete` and preserve bounded `needed`.
- [ ] `view::get/raw/to_struct` retain null guard and (when enabled) generation checks.
- [ ] No new unchecked pointer arithmetic in hot path without prior validated size.
- [ ] Contract changes are documented in `MEMORY_SAFETY.md` and README/docs index.

### Test checks

- [ ] `nanom_tests` includes incremental streaming behavior (`test_streaming_incremental`).
- [ ] Memory-safety suites pass for expected profile (`nanom_memory_safety_tests`,
      `nanom_generation_tests` where applicable).
- [ ] Any accepted residual risk has a test or documented rationale.

### Performance checks

- [ ] Safety-path changes benchmarked (`bench/safety_microbench.cpp` and/or
      `bench/compare_rust.py` where relevant).
- [ ] Regressions beyond noise are either justified or guarded by opt-in policy.

## Recommended reviewer commands

```sh
# core tests
cmake -B build -DCMAKE_CXX_COMPILER=g++-13
cmake --build build -j
ctest --test-dir build --output-on-failure

# focused safety tests (when generation target exists in this branch)
ctest --test-dir build -R "nanom_memory_safety_tests|nanom_generation_tests" --output-on-failure

# baseline perf sanity
python3 bench/compare_rust.py --build --safety both --iters 20000
```
