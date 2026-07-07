# nanom fuzzers

Fuzzers feeding arbitrary bytes into nanom parse paths. `self_fuzz` runs in ctest;
libFuzzer targets run in the `fuzz` workflow and `streaming-sanitizer` CI job.

## `self_fuzz.cpp` — robustness (self-contained, in CI)

Asserts the library **never crashes or reads out of bounds** on arbitrary input.
No external deps. Build with sanitizers to make any violation fatal:

```sh
g++-13 -std=c++23 -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -I include -o self_fuzz fuzz/self_fuzz.cpp && ./self_fuzz
```

Run as the `self_fuzz` ctest target.

## `fuzz_scan_walk.cpp` — pcap scan + walk (libFuzzer, in CI)

Coverage-guided fuzz of `scan_blocks` + `walk_packet` on arbitrary file and packet bytes.

## `fuzz_streaming_pcapng.cpp` — streaming refill (libFuzzer, in CI)

Feeds arbitrary bytes into the **streaming pcapng** parse loop with a **variable
refill-window cap** (16..8192 bytes). Built with `NANOM_GENERATION=1` and
`NANOM_GUARD_VIEWS=1`. Exercises `nm::streaming` → `incomplete` → refill boundaries.

```sh
cmake -B build -DCMAKE_CXX_COMPILER=clang++-18 -DNANOM_BUILD_FUZZERS=ON
cmake --build build --target fuzz_streaming_pcapng
mkdir -p corpus_streaming && cp examples/nanotins_parity/testdata/*.pcapng corpus_streaming/
./build/fuzz_streaming_pcapng -max_total_time=60 corpus_streaming/
```

## `differential_fuzz.cpp` — parity with nanotins (manual)

Asserts **nanom and nanotins decode identically** on every input. Needs nanotins
headers; not in default CI.

```sh
g++-13 -std=c++23 -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -I include -I . \
    -I path/to/nanotins/nanotins/include -I path/to/nanotins/soatins/include \
    -o difffuzz fuzz/differential_fuzz.cpp && ./difffuzz
```
