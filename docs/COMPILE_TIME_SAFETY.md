# Compile-time safety and the strict profile

nanom's default safety model is **runtime** (bounds checks, `wire_arena`
generation tracking, view guards). The **strict profile** (`NANOM_STRICT=1`) is
for users who want the opposite trade: **narrow the API at compile time so the
runtime can drop the checks those APIs made necessary** — memory safety enforced
by the compiler, at the speed of the unchecked build.

It is the *sweetened pill*: you accept compile-time restrictions, and in return
nanom compiles **out** the runtime safety machinery, giving a leaner, faster data
model with no loss of safety on the routes that remain.

## The three profiles

| | compile-time | runtime | for |
|---|---|---|---|
| **default / safety-first** | permissive API | `NANOM_GENERATION=1`, `NANOM_GUARD_VIEWS=1` | ergonomic zero-copy, unknown caller discipline |
| **minimal** | permissive API | both off | max speed, no safety net, footguns available |
| **strict** (`NANOM_STRICT=1`) | **narrowed API + deleted footguns + compile-time lifetime diagnostics** | both off (lean) | safety- **and** speed-obsessed C++ |

Strict = minimal's runtime speed **plus** compile-time-enforced safety that plain
minimal lacks.

## What strict enforces at compile time

| Restriction | Mechanism | Why |
|-------------|-----------|-----|
| No raw `from(const void*, size_t)` | overload removed under strict | provenance is always a **sized** span/array/string_view, never a `(ptr, len)` pair a caller can get wrong |
| No `from(std::string&&)` / owning temporaries | `= delete` | parsing a temporary you don't keep is a **compile error**, not a runtime use-after-free |
| No GPU/bulk raw-pointer scatter | `#error` in `<nanom/bulk.hpp>` | the device/bulk path is deliberately **outside** the bounds-checked combinator model; pick one |
| Dangling-view diagnostics | `[[clang::lifetimebound]]` on `from()`/`as_str()` | Clang warns when a view/span is bound to a temporary buffer (zero runtime cost) |

Combinator bounds checks (`take`, `overlay`, `strct`, …) are **kept** — defense
against hostile input is not a caller-discipline question — and the library stays
continuously fuzzed.

To override the GPU/bulk ban after auditing your kernel, define
`NANOM_ALLOW_BULK_IN_STRICT`.

## What strict buys at runtime

- `NANOM_GENERATION=0`, `NANOM_GUARD_VIEWS=0` by default (no per-access generation branch).
- A **leaner data model** — measured with `sizeof`:

| type | default (full) | strict / minimal |
|------|---------------:|-----------------:|
| `nanom::input` | 48 B | **32 B** |
| `nanom::bytes` | 32 B (`attested_bytes`) | **16 B** (`std::span`) |

Smaller cursors mean less register pressure and copying on the hot path.

## Performance proof

Streaming pcapng, verified byte-identical output, `g++-13 -O3 -march=native`,
best-of-5 (reproduce with `python3 bench/compare_rust.py --build --safety all`):

| profile | ns/packet | throughput |
|---------|----------:|-----------:|
| minimal | 84 | 17.5 GiB/s |
| full (safety-first) | 82 | 17.8 GiB/s |
| **strict** | **83** | 17.5 GiB/s |
| Rust nom (hand-written) | 83 | 17.7 GiB/s |

All three nanom profiles are at parity (within best-of-5 noise): on this workload
generation tracking is already essentially free, so strict's win is the
**compile-time guarantees + leaner data model**, not a throughput bump. The honest
claim is *"compile-time-enforced memory safety at the unchecked profile's speed."*

## Using it

=== "CMake"

    ```sh
    cmake -B build -DNANOM_STRICT=ON
    ```

=== "Compile flag"

    ```sh
    g++ -std=c++23 -DNANOM_STRICT=1 -I include my_parser.cpp
    ```

Belt-and-suspenders: combine strict compile-time restrictions **with** runtime
tracking by re-enabling generation explicitly:

```sh
-DNANOM_STRICT=1 -DNANOM_GENERATION=1
```

### Safe routes (what you write under strict)

```cpp
#include <nanom/nanom.hpp>
namespace nm = nanom;

std::vector<std::byte> buf = load();
auto in = nm::from(std::span<const std::byte>(buf.data(), buf.size()));  // sized
auto r  = nm::strct<my_hdr>()(in);

std::string body = read_body();          // named, not a temporary
auto t = nm::tag("GET")(nm::from(body));

// nm::from(load_string());               // COMPILE ERROR under strict (dangles)
// nm::from(buf.data(), buf.size());       // COMPILE ERROR under strict (raw ptr+len)
// #include <nanom/bulk.hpp>               // COMPILE ERROR under strict (GPU/bulk)
```

## Tests and CI

- `tests/test_strict_profile.cpp` (`nanom_strict_profile_tests`) — `static_assert`s
  the compile-time contract (raw entry removed, owning temporaries deleted,
  `bytes == std::span`, lean flags), then parses through the safe routes.
- `nanom_strict_rejects_raw_ptr`, `nanom_strict_rejects_string_temp`,
  `nanom_strict_rejects_bulk` — **negative compile tests** (`WILL_FAIL`): a
  regression that re-enables an unsafe route turns them red.
- The `strict-profile` CI job builds the tree, runs those tests, compiles the
  strict suite clang-clean (to exercise `lifetimebound`), and benchmarks
  strict vs minimal vs full.

## Related

- [Memory safety model](MEMORY_SAFETY.md) — the runtime enforcement matrix
- [Safety for Rust reviewers](RUST_SAFETY_REVIEW.md) — lifetime/UB/overflow answers
- [Threat model + reviewer checklist](THREAT_MODEL.md)
- [vs Rust nom (streaming pcapng)](BENCH_RUST_NOM.md) — benchmark methodology
