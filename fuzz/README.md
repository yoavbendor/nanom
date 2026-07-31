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

## `fuzz_streaming_defrag.cpp` — streaming buffer-release contract (libFuzzer + standalone, in CI)

Differential fuzz of `nanom_shark::StreamingDecodeSession`'s **buffer-release contract**: the
fuzzer input becomes a capture full of IPv4 fragments (out-of-order, overlapping, gapped,
oversized, never-completing), which is then decoded twice — whole-file via `run_decode_pass`, and
one block at a time via the streaming session with **every buffer poisoned and freed the instant
its token is reported released**. The two decodes must be byte-identical; a premature release shows
up either as an ASan heap-use-after-free on the stale fragment span or as an output divergence.

Runs in ctest as `streaming_defrag_fuzz` via a standalone PRNG driver (no libFuzzer runtime
needed), and as a coverage-guided target when `NANOM_BUILD_FUZZERS=ON`:

```sh
./build/nm_streaming_defrag_fuzz 60000        # standalone; [iterations] [seed]
./build/fuzz_streaming_defrag -max_total_time=60 corpus/   # libFuzzer (Clang)
```

The deterministic counterpart is `tests/nanom_shark_test_streaming.cpp`, which drives a fixed
capture through a fixed 8-slot pool and additionally asserts the memory bound.

## `differential_fuzz.cpp` — parity with nanotins (manual)

Asserts **nanom and nanotins decode identically** on every input. Needs nanotins
headers; not in default CI.

```sh
g++-13 -std=c++23 -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -I include -I . \
    -I path/to/nanotins/nanotins/include -I path/to/nanotins/soatins/include \
    -o difffuzz fuzz/differential_fuzz.cpp && ./difffuzz
```
