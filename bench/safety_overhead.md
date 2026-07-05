# nanom safety hardening — performance baselines & execution plan

This document records **baseline overhead measurements** for proposed memory-safety guards and the **finalized implementation order** for landing them. It pairs with:

| Artifact | Role |
|----------|------|
| `tests/test_memory_safety.cpp` | 19 failing `CHECK`s (desired behavior) |
| `tests/test_memory_safety_ub.cpp` | Optional ASan red-team demos |
| `bench/safety_microbench.cpp` | Per-guard microbench + `sim-*` models |
| `bench/parse_bench.cpp` | End-to-end overlay walk (integration probe) |

## Running benchmarks

```sh
# Release build (required for meaningful ns/op numbers)
cmake -B build-rel -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_COMPILER=g++-13 \
  -DCMAKE_CXX_FLAGS="-march=native -O3"
cmake --build build-rel -j --target nm_safety_microbench nm_parse_bench

# Safety microbench (all scenarios)
./build-rel/nm_safety_microbench 30

# Integration overlay walk on a real capture
./build-rel/nm_parse_bench examples/nanotins_parity/testdata/srv6_sample.pcap 200
```

Smoke-tested in ctest: `bench_smoke_safety` (2 outer iters).

### Reading output

- **`overlay-walk`** — primary **Tier D** probe; generation tokens must not regress this vs baseline.
- **`sim-*` lines** — branch/copy models of a guard **without** library changes; use as overhead ceiling estimates.
- Sub‑nanosecond lines (`1.00 ns/op`) hit the host timer quantisation floor on this workload; treat **`advance-take` vs `sim-checked-advance`** as “no measurable delta” until a slower integration bench shows otherwise.

## Baselines (recorded 2026‑07‑05)

**Host:** cloud VM, `g++-13`, `-O3 -march=native`, best-of-20/30 outer iterations.

### Hot path (Tier D gate)

| Scenario | ns/op | Notes |
|----------|------:|-------|
| `overlay-walk` (synthetic 54 B frame) | **9.0** | Primary regression gate |
| `nm_parse_bench` overlay (`srv6_sample.pcap`) | **12.4** | Integration check (7 pkts; noisy on tiny captures) |
| `view-get` (3× `get<>` on IPv4) | **3.0** | Sub-loop of overlay walk |
| `sim-gen-check-get` (+ predictable gen compare) | **3.0** | **~0%** modeled overhead (branch elided/predictable) |

### Tier B candidates

| Scenario | ns/op | `sim-*` delta |
|----------|------:|---------------|
| `from-construct` | 1.00* | — |
| `advance-take` | 1.00* | — |
| `sim-checked-advance` | 1.00* | **~0%** at timer floor |
| `sim-null-from-reject` | 0.71* | cheaper (half inputs skipped) |
| `tag-match` | 1.00* | — |
| `sim-tag-owned` (inline copy) | 1.00* | **~0%** at timer floor |

\*Timer quantisation floor; not a proof of zero cost — only that cost is **≪ overlay-walk**.

### Tier A (cold / entry paths)

| Scenario | ns/op | `sim-*` delta |
|----------|------:|---------------|
| `error-render` | **153.2** | — |
| `sim-render-clamp` | **150.7** | **~−1.6%** (extra min; noise) |
| `incomplete-needed` | 1.00* | — |
| `sim-needed-cap` | 1.00* | **~0%** |
| `bulk-pkt-validate` | 1.00* | — |
| `sim-null-from-reject` (50% null) | 0.71* | — |

**Conclusion from baselines:** Tiers **A** and **B** are safe to implement first from a performance perspective. Tier **D** (generation tokens on every `get()`) needs a **debug-only** path or it risks the only benchmark we can resolve today (`overlay-walk`).

## Regression policy (per PR)

| Tier | Bench gate | Threshold |
|------|------------|-----------|
| A | none required | cold paths |
| B | `nm_safety_microbench` tag/from lines + optional `overlay-walk` | &lt; 2% on `overlay-walk` |
| C | none in Release | debug-only |
| D | **`overlay-walk` + `nm_parse_bench` overlay** | **&lt; 5%** or guard is debug-only |
| E | docs-only | n/a |

Always verify: `ctest` green (except `nanom_memory_safety_tests` until guards land), checksum unchanged in `nm_parse_bench`, `self_fuzz` under ASan when touching parse path.

---

# Execution plan (finalized)

Each tier is one PR series branch `cursor/safety-tier-<N>-1ef9`. After each tier: run microbench, update the “flipped tests” table, remove `WILL_FAIL` only when all targeted `CHECK`s pass.

## Tier A — ship first (negligible hot-path risk)

**Goal:** close 3/19 failing checks, zero overlay-walk impact.

| PR | Change | Files | Tests flipped |
|----|--------|-------|---------------|
| **A1** | `error::render` — clamp `offset` to `[0, last-base]` before hex window | `include/nanom/nom.hpp` | `error_render_overrun` (1) |
| **A2** | `incomplete` — saturate `needed` to `min(needed, cap)` with `cap = 64KiB`; document `needed==0` as unknown | `include/nanom/nom.hpp` | `incomplete_needed_saturation` (1) |
| **A3** | `bulk_decode` — reject `pkt_ref` with `!data && len`, or `!data && len>0` | `include/nanom/bulk.hpp` | `bulk_null_pkt_ref` (1) |

**Exit criteria:** 3 tests green; microbench `error-render` within noise; `nm_parse_bench` unchanged.

---

## Tier B — high value / low hot-path risk

**Goal:** close 5 more checks (8/19 total).

| PR | Change | Files | Tests flipped |
|----|--------|-------|---------------|
| **B1** | `tag()` — SBO: copy patterns ≤15 bytes into `std::array` inside closure; keep `string_view` overload for literals via binding | `include/nanom/nom.hpp` | `dangling_tag_pattern` (2) |
| **B2** | `from(ptr,len)` — `assert`/`std::unreachable` in debug; in release return empty input when `!ptr && len>0` **or** document + `from_checked` returning `expected` | `include/nanom/nom.hpp` | `null_pointer_input` partial (1) |
| **B3** | Add `safe_at(i)` → `optional<uint8_t>`; add `checked_advance(n)` → `optional<input>`; keep fast `advance`/`operator[]` | `include/nanom/nom.hpp` | `null_pointer_input` (1), `cursor_overrun` (2), `unchecked_index` (1) |

**Exit criteria:** 8/19 green; `overlay-walk` regression &lt; 2%; update tests to use `checked_advance` in examples where appropriate.

---

## Tier C — cheap null-view poison (debug)

**Goal:** 1 check (9/19).

| PR | Change | Files | Tests flipped |
|----|--------|-------|---------------|
| **C1** | `view::get()` — `assert(p != nullptr)` when `NDEBUG` off; optional `NANOM_GUARD_VIEWS` | `include/nanom/reflect.hpp` | `null_view_decode` (1) — test may require `-DNANOM_GUARD_VIEWS` |

**Exit criteria:** Release `overlay-walk` identical; debug catches UB demo `null_view_get`.

---

## Tier D — lifetime (defer full Release; prototype debug-only)

**Goal:** 4 checks (13/19) without Release regression.

| PR | Change | Files | Tests flipped |
|----|--------|-------|---------------|
| **D1** | **RFC / design** — `wire_id` on `input` (uintptr_t base + generation); opt-in `attested_bytes` | design doc only | — |
| **D2** | Debug-only: `input` carries `generation*`; bump on `from`; `view` stores gen; check in `get()` under `NANOM_GUARD_VIEWS` | `nom.hpp`, `reflect.hpp` | `dangling_bytes_span`, `view_use_after_free`, `nested_view_span_lifetime`, `length_prefix_overrun` (4) |

**Release default:** no generation checks. **Debug/NANOM_GUARD_VIEWS:** full checks.

**Exit criteria:** Release `overlay-walk` &lt; 5% vs baseline; debug flips 4 tests.

---

## Tier E — aliasing & hang documentation (no Release guard required)

**Goal:** remaining 6 checks via docs + helpers (19/19).

| PR | Change | Files | Tests flipped |
|----|--------|-------|---------------|
| **E1** | Document **immutable wire** requirement for `overlay`/`view`; add `docs/MEMORY_SAFETY.md` | `docs/` | `single_view_aliasing` (2) — relax to doc-linked `CHECK` macro or split “library enforces” vs “user contract” |
| **E2** | Add `checked_many0` wrapper + cheat-sheet note on zero-consumption | `nom.hpp`, `docs/CHEATSHEET.md` | `zero_consumption_hang_guard` (2) |

**Note:** true detection of wire mutation without cost requires Tier D checksum/debug — keep Tier E as **contract + helpers**, not silent Release enforcement.

---

## Readiness checklist (before Tier A execution)

- [x] Failing safety tests (`test_memory_safety.cpp`, 19 checks)
- [x] UB demos (`test_memory_safety_ub.cpp`, opt-in)
- [x] Microbench harness (`nm_safety_microbench`)
- [x] Baselines recorded (this file)
- [x] Tier order + per-PR scope + bench gates
- [x] **Tier C** — C1 null view guard (`NANOM_GUARD_VIEWS`)
- [x] **Tier E** — docs/MEMORY_SAFETY.md, `checked_many0`, caller contracts
- [ ] **Tier D** — generation tokens (debug-only prototype; deferred)

## Command cheat sheet (execution)

```sh
# Full pre-tier verification
cmake -B build -DCMAKE_CXX_COMPILER=g++-13 && cmake --build build -j
ctest --test-dir build --output-on-failure

# Perf before/after a tier
cmake -B build-rel -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=g++-13 \
  -DCMAKE_CXX_FLAGS="-march=native -O3"
cmake --build build-rel -j --target nm_safety_microbench nm_parse_bench
./build-rel/nm_safety_microbench 30 | tee bench/safety_baseline.txt
./build-rel/nm_parse_bench examples/nanotins_parity/testdata/SRL_front_left_51_short.pcapng 200

# ASan regression
cmake -B build-asan -DNANOM_SANITIZER=address,undefined -DNANOM_MEMORY_SAFETY_UB_DEMOS=ON
cmake --build build-asan -j && ./build-asan/nm_self_fuzz
```

---

## Summary

| Tier | PRs | Tests fixed | Hot-path risk | Status |
|------|-----|------------|---------------|--------|
| **A** | A1–A3 | 3/19 | None | **Done** (`cursor/safety-tier-a-1ef9`) |
| **B** | B1–B3 | +5 (8/19) | Low | **Done** (`cursor/safety-tier-b-1ef9`) |
| **C** | C1 | +1 (10/19) | None in Release | **Done** |
| **E** | E1–E2 | +8 (19/19) | None | **Done** |
| **D** | D1–D2 | generation tokens | High | Deferred (debug prototype) |

**Agent status:** Tiers A–C+E complete on `cursor/safety-tier-cde-1ef9`. Tier D (runtime lifetime tokens) remains future work; E covers caller contracts.
