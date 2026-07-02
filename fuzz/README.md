# nanom fuzzers

Two fuzzers, both feeding random / bit-flipped / truncated / extended bytes into
the pcap scan + Eth/VLAN/IPv4/IPv6/TCP/UDP walk.

## `self_fuzz.cpp` — robustness (self-contained, in CI)

Asserts the library **never crashes or reads out of bounds** on arbitrary input.
No external deps. Build with sanitizers to make any violation fatal:

```sh
g++-13 -std=c++23 -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -I include -o self_fuzz fuzz/self_fuzz.cpp && ./self_fuzz
# self fuzz: 600000 cases, no crash (sink ...)
```

Run as the `self_fuzz` ctest target. Every combinator bounds-checks by
construction, so this is where a zero-copy parser library must be airtight.

## `differential_fuzz.cpp` — parity with nanotins (manual)

Additionally asserts that **nanom and nanotins decode identically** — same
layers emitted, same field values — on every input. Needs the nanotins headers
on the include path, so it is not in the default CI build:

```sh
g++-13 -std=c++23 -O1 -fsanitize=address,undefined -fno-sanitize-recover=all \
    -I include -I . \
    -I path/to/nanotins/nanotins/include -I path/to/nanotins/soatins/include \
    -o difffuzz fuzz/differential_fuzz.cpp && ./difffuzz
# differential fuzz: 600000 cases, 0 mismatches
```

Result on the current tree: **600,000 cases, 0 mismatches**, clean under
ASan+UBSan — strong evidence that the nanom port is behaviorally equivalent to
nanotins on malformed input, not just on the curated captures.
