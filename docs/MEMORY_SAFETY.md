# nanom memory safety

nanom's parse path is **zero-copy**: `input`, `bytes`, and `view<T>` reference
caller-owned buffers. Combinators bound-check before every consume; this document
covers what the library **does** enforce and what remains **caller contract**.

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

Future work: auto-tracked containers; stronger provenance/cross-arena diagnostics.

## Tests

- `tests/test_memory_safety.cpp` — regression suite (`NANOM_GUARD_VIEWS=1`)
- `tests/test_memory_safety_generation.cpp` — generation suite (`NANOM_GENERATION=1`)
- `tests/test_nanom.cpp` — incremental one-byte streaming behavior (`test_streaming_incremental`)
- `bench/safety_microbench.cpp` — performance baselines per guard
