# Getting started

nanom is **header-only** with no dependencies. You need a C++23 compiler (gcc ≥ 13, clang ≥ 18) for the
macro path, or a P2996 compiler (the Bloomberg clang-p2996 fork) for the macro-free C++26 path.

## Install

=== "CMake (add_subdirectory)"

    ```cmake
    add_subdirectory(nanom)
    target_link_libraries(myapp PRIVATE nanom::nanom)
    ```

=== "CMake (install + find_package)"

    ```sh
    cmake -B build -DCMAKE_INSTALL_PREFIX=/usr/local
    cmake --install build
    ```
    ```cmake
    find_package(nanom CONFIG REQUIRED)
    target_link_libraries(myapp PRIVATE nanom::nanom)
    ```

=== "Copy the headers"

    Copy the `include/nanom/` folder into your project and add `include/` to your include path — it
    is header-only. Or grab the generated single-file
    [`nanom-single.hpp`](https://yoavbendor.github.io/nanom/nanom-single.hpp) for a one-file drop-in.

Then:

```cpp
#include <nanom/nanom.hpp>       // the umbrella — pulls in everything
namespace nm = nanom;
```

Or include just the layer you need — `#include <nanom/nom.hpp>` gives the **parser-only** subset (the
pure rust-nom parallel), with none of the reflection/schema/soa extras.

## Safety defaults and knobs

nanom defaults to strong runtime safety checks:

- `NANOM_GENERATION=1` (tracked lifetime checks for `input` / `bytes` / `view`)
- `NANOM_GUARD_VIEWS=1` (guards null/uninitialized view access)
- `NANOM_GENERATION_THROW=0` (set to `1` to throw `generation_exception` instead of abort+report)

Override per target/build with compile definitions (`-DNANOM_GENERATION=0`, etc.). See
[MEMORY_SAFETY.md](MEMORY_SAFETY.md) for contracts and review guidance.

## Your first parser

```cpp
#include <nanom/nanom.hpp>
#include <array>
#include <cstdint>
#include <cstdio>
namespace nm = nanom;

struct eth_hdr {
  std::array<std::uint8_t, 6> dst, src;
  nm::be<std::uint16_t>       eth_type;      // big-endian on the wire
};
NANOM_DESCRIBE(eth_hdr, dst, src, eth_type); // at global scope (optional under C++26 reflection)

int main() {
  const std::array<std::uint8_t, 14> frame = {
    0x01,0x02,0x03,0x04,0x05,0x06, 0x0a,0x0b,0x0c,0x0d,0x0e,0x0f, 0x08,0x00 };

  nm::input in = nm::from(frame);
  auto r = nm::strct<eth_hdr>()(in);         // parse by value -> {value, rest} or error
  if (!r) { std::puts(r.error().render(in).c_str()); return 1; }

  std::printf("ethertype = 0x%04x\n", (unsigned)r->value.eth_type);  // host order
  return 0;
}
```

Build it:

```sh
g++-13 -std=c++23 -I include first.cpp -o first && ./first    # ethertype = 0x0800
```

## Where to next

- **[Cheat sheet](CHEATSHEET.md)** — the fastest way in if you know Rust nom: a nom-name → nanom-name
  map for every combinator.
- **[Design](design.md)** — how the pieces fit: the `describe<T>` seam, zero-copy views, error model.
- **[C++26 reflection](P2996_COMPAT.md)** — drop the `NANOM_DESCRIBE` lines entirely; eligibility rules
  and toolchain notes.
- **[Benchmarks](BENCH_RUST_NOM.md)** — the verified-equal-output comparison with stable Rust nom.

## Zero registration under C++26

With a P2996 compiler the `NANOM_DESCRIBE` line disappears — the struct definition *is* the
registration:

```cpp
struct eth_hdr {
  std::array<std::uint8_t, 6> dst, src;
  nm::be<std::uint16_t>       eth_type;
};  // that's it. strct<>/overlay<>/soa<>/to_json/avro all work; nothing to register.
```

See the [C++26 reflection](P2996_COMPAT.md) page for the eligibility rules and how to build with the
fork.
