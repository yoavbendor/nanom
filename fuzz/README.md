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

## `fuzz_segmented.cpp` — segmented vs contiguous parity (libFuzzer, in CI)

Differential: for a fuzzer-chosen buffer AND a fuzzer-chosen segmentation of it, a fixed parse
script (struct parses, scalar reads, skips, subranges, `many0`/`checked_many0`) must produce
IDENTICAL results over the segmented and the contiguous form. Any divergence traps.

It also builds **without libFuzzer**, for environments with no compiler-rt fuzzer runtime: the
same `LLVMFuzzerTestOneInput` is driven from a plain `main()` over pseudo-random and seed-mutated
inputs.

```sh
g++ -std=c++23 -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -DNANOM_FUZZ_STANDALONE -I include -o fuzz_segmented_standalone fuzz/fuzz_segmented.cpp
./fuzz_segmented_standalone 300000      # iteration count, default 300k
```

The `-DNANOM_BUILD_FUZZERS` build does not define `NANOM_FUZZ_STANDALONE`, so it keeps libFuzzer's
own `main`.

## `differential_fuzz.cpp` — parity with nanotins (manual)

Asserts **nanom and nanotins decode identically** on every input. Needs nanotins
headers; not in default CI.

```sh
g++-13 -std=c++23 -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -I include -I . \
    -I path/to/nanotins/nanotins/include -I path/to/nanotins/soatins/include \
    -o difffuzz fuzz/differential_fuzz.cpp && ./difffuzz
```
