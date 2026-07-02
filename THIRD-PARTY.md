# Third-party notices & provenance

## The library depends on nothing but the C++ standard library

`include/nanom/nanom.hpp` and `include/nanom/bulk.hpp` — the entire
distributable — include only standard headers. There is **no third-party code**
in the library and therefore no bundled third-party licenses to comply with.

## Design inspirations (no code copied)

nanom is a **clean-room implementation**. Its combinator vocabulary and error
model were *inspired by* the projects below; no source code was copied from any
of them. API names and structure (e.g. `tag`, `many0`, `alt`) are not
copyrightable, and every line of nanom was written from scratch.

| project | license | what nanom took (concepts only) |
|---|---|---|
| [rust-bakery/nom](https://github.com/rust-bakery/nom) | MIT | the combinator names and the three-way error model (Error/Failure/Incomplete), `cut`, `context`, streaming vs complete |
| [boostorg/parser](https://github.com/boostorg/parser) | BSL-1.0 | the emphasis on localized, human-quality error messages |
| [acd1034/monadic-parser-combinator](https://github.com/acd1034/monadic-parser-combinator) | — | that C++20 concepts + monadic bind make clean combinators |
| [hexorer/parsi](https://github.com/hexorer/parsi) | — | the always-`constexpr`, always-inlinable function-object discipline |
| [OneBit74/ezpz](https://github.com/OneBit74/ezpz) | — | results decaying into user structs |

See `DESIGN.md` for the detailed rationale.

## Test fixtures and comparison harness (dev-only, not shipped)

These are **not** part of the installed library and are only built when running
the project's own tests/benchmarks:

- `examples/nanotins_parity/testdata/*.pcap`, `*.pcapng` and the `*.ndjson`
  golden files derive from the **nanolance** project
  (<https://github.com/yoavbendor/nanolance>, Apache-2.0) and the parity work
  against **nanotins** (<https://github.com/yoavbendor/nanotins>, Apache-2.0),
  both by the same author as nanom.
- `fuzz/differential_fuzz.cpp` `#include`s nanotins headers **only** to diff
  nanom's decode against nanotins'. It compiles solely if nanotins is present on
  the include path; nanotins is not vendored, shipped, or linked into nanom.
