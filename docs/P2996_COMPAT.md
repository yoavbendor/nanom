# P2996 toolchain compatibility survey (nanom + sibling nano libs)

Date: 2026-07-03. Toolchain: **Bloomberg clang-p2996 fork** (clang 21.0.0git, branch `p2996`,
commit `7220baf`), built from source, `<meta>` from its bundled libc++. This is the survey behind
the C++26 reflection port: does the experimental fork compile the whole nano stack, at the
current standards and at `-std=c++26`?

## Toolchain facts (pinned empirically)

| fact | value |
|---|---|
| flags | `-std=c++26 -freflection-latest` (plain `-freflection` also suffices for nanom's surface) |
| reflection header | `<meta>` (and `<experimental/meta>`), **only in the fork's libc++** ⇒ `-stdlib=libc++` |
| feature-test macro | **none** — the fork defines no `__cpp_*` for reflection; probe is `__has_feature(reflection)` (nanom.hpp accepts `__cpp_impl_reflection` too, for future conforming compilers) |
| API level | two-arg `nonstatic_data_members_of(r, access_context::unchecked())`; `identifier_of`; `&[:m:]` NTTP member-pointer splice; `parent_of` walk; info `==` with `^^::` — all work |
| runtime | binaries need `-Wl,-rpath,<toolchain>/lib/x86_64-unknown-linux-gnu` for libc++ |
| CI image | `vsavkov/clang-p2996@sha256:6672c4227b09efc7318695c17e8a8f696e193f451b52d885d220f593593dc1c8` (digest fetched 2026-07-03; the sandbox's egress policy blocked Docker Hub's blob CDN, hence the from-source local build — GitHub runners pull it fine) |

## Results matrix

| repo | standard | compiler mode | build | tests |
|---|---|---|---|---|
| **nanom** | C++23 | fork clang, libstdc++ | ✅ `-Werror` clean | ✅ 13/13 |
| **nanom** | C++26 | pure reflection (`NANOM_CXX26_REFLECTION=ON`) | ✅ `-Werror` clean | ✅ **15/15** incl. all 4 golden-diff parity suites, byte-identical |
| **nanom** | C++26 | macro-parity (`+ NANOM_DESCRIBE_FORCE_MACRO`) | ✅ | ✅ 15/15 |
| **nanom** | C++23 | g++-13 / clang++-18 (regression check) | ✅ | ✅ 13/13 both |
| **nanotins** | current (C++20/23) | fork clang, libstdc++ | ✅ (77 targets) | ✅ **33/33** |
| **nanotins** | `-std=c++26` | fork clang, libstdc++ | ✅ | ✅ 33/33 |
| **nanolance** | current | fork clang, libstdc++ (tools + examples + pcapng2lance_nanom) | ✅ | functional smoke ✅ |
| **nanolance** | `-std=c++26` | fork clang, libstdc++ | ✅ | converter output **byte-identical** to known-good (pylance-verified) |
| **nanolance pcapng2lance_nanom** | C++26 | **pure reflection** (`-freflection-latest -stdlib=libc++`) | ✅ | **byte-identical Lance datasets** on SRL (224 pkt, L1+PDU) and SRv6 (ext-header chain: routing/option/tcp/udp tables) |

## Verdicts

- **nanom**: fully compatible; the reflection port is validated end to end. The entire parity
  corpus runs through pure P2996 reflection with byte-identical goldens.
- **nanotins**: fully compatible with fork clang at both standards, all 33 tests green. No stdexec
  breakage materialized (the stdexec-dependent paths live in the nanolance example tree, not the
  standalone nanotins build).
- **nanolance**: fully compatible at both standards, including its C dependencies (nanoarrow,
  zstd — compiled by the host C compiler) and the Rust-pylance-verified converter output. The
  flagship result: **the pcapng→Lance converter (incl. the SRv6 extension-header walk) builds in
  pure-reflection mode — every `NANOM_DESCRIBE` in nm_pcap.hpp / nm_protocols.hpp compiled down to
  a coverage `static_assert` — and produces byte-identical datasets.**
- **No fixes were required anywhere** — zero source changes to nanotins or nanolance. The expected
  pain points (fork strictness, stdexec, mixed C/C++ deps) did not bite.

## Caveats / watch items

- One experimental compiler is the entire C++26 validation surface; the C++23 matrix remains the
  blocking CI. The reflection CI job is advisory.
- The fork's API still moves (access_context arity, feature macro). nanom's fork-facing surface is
  ~6 `std::meta` calls confined to `nanom26.hpp`; re-pinning after a fork bump is a one-file diff.
- Full-reflection *libc++* builds of nanolance were only exercised for the pcapng2lance_nanom
  target (the library's own test suite ran under libstdc++ modes); a libc++ run of nanolance's
  full test suite is future work if ever needed — reflection only requires libc++ in TUs that
  include `<meta>`.

## CI status (branch runs)

- `reflection-cxx26 (reflection)` and `reflection-cxx26 (macro-parity)`: **green** on GitHub
  runners — the digest-pinned image pulled, built, and passed the full suite in both modes.
- The macOS advisory job fails on `std::from_chars(double)` (nanom.hpp:1314), unsupported by brew
  libc++18 — **pre-existing** (fails identically on the pre-reflection commit; see the earlier
  "revert invalid double from_chars" upstream commit) and unrelated to this port.
- The clang-tidy advisory job briefly failed because its `examples/*.cpp` glob picked up the new
  reflection-only `reflect26.cpp` (which `#error`s without a P2996 compiler); fixed by filtering
  those TUs out of the tidy invocation.
