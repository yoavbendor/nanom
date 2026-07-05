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

## Caller contract (documented, not runtime-tracked)

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
| `NANOM_GUARD_VIEWS` | on in debug, off in `NDEBUG` | Assert null `view` access |

Future work (not yet in Release): generation tokens tying `view`/`bytes` to buffer
lifetime — see `bench/safety_overhead.md` Tier D.

## Tests

- `tests/test_memory_safety.cpp` — regression suite (`NANOM_GUARD_VIEWS=1`)
- `tests/test_memory_safety_ub.cpp` — optional ASan red-team (`NANOM_MEMORY_SAFETY_UB_DEMOS=ON`)
- `bench/safety_microbench.cpp` — performance baselines per guard
