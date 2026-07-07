# Memory safety and streaming model

nanom is zero-copy by design, so safety is mostly about making lifetime and bounds contracts explicit
and machine-checkable while preserving parser performance.

## Streaming contract (nom-style)

Use `nm::streaming(input)` when bytes may arrive incrementally.

- short prefix => `errk::incomplete`
- `error.needed` reports additional bytes required (capped by `max_incomplete_needed`)
- caller refills and re-runs the parser

```cpp
auto r = parser(nm::streaming(nm::from(buf, have)));
if (!r && r.error().kind == nm::errk::incomplete) refill(r.error().needed);
```

This is verified by one-byte-at-a-time tests in `tests/test_nanom.cpp` (`test_streaming_incremental`).

## Default runtime protections

Defaults are intentionally safety-first and can be overridden per build/target:

| Macro | Default | Effect |
|---|---:|---|
| `NANOM_GUARD_VIEWS` | `1` | asserts on null/uninitialized `view` access (`get` / `raw` / `to_struct`) |

Additional parser-side protections enabled by default:

- `from(nullptr, n>0)` returns empty input (safe null handling)
- `make_incomplete` caps `needed` via `max_incomplete_needed` (64 KiB)
- `input::safe_at()` and `input::checked_advance()` provide bounds-checked alternatives

## Configuration

### Compiler defines

```sh
-DNANOM_GUARD_VIEWS=0
```

### CMake options

```sh
cmake -B build \
  -DNANOM_GUARD_VIEWS=ON
```

## Test coverage for reviewers

- `tests/test_nanom.cpp` — incremental streaming behavior (including one-byte feed)
- `tests/test_memory_safety.cpp` — memory-safety regression surface (tracks desired behavior)
- `tests/test_memory_safety_ub.cpp` — optional ASan red-team UB demos
