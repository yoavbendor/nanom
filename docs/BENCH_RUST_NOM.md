# nanom vs stable Rust nom — streaming pcapng, verified-equal output

The headline question for a C++ nom-alike is: *is it actually as fast as Rust nom?* This is the
falsifiable answer. Same task, same file, same streaming model, in both languages — and the two
parsers are **proven to produce byte-identical output** before any timing is reported.

## The task

Parse a pcapng capture in **streaming mode**: walk the block stream through a bounded, refilling
buffer (a 64 KiB window that `refill()`s from the source — the whole file is never resident in the
parser's working set) and read each **Enhanced Packet Block**'s fixed fields (`interface_id`,
timestamp, `caplen`, `origlen`). No payload copy. No option-TLV walk. Every parser accumulates the
same aggregate — `(packets, Σcaplen, Σoriglen, fnv1a(ts_raw, caplen, origlen))` — and the harness
[`bench/compare_rust.py`](https://github.com/yoavbendor/nanom/blob/main/bench/compare_rust.py) **asserts all aggregates are identical** before it
prints a single timing number. (This is the cross-language analogue of the `parse_bench` field
checksum.)

## The three parsers (fair by construction)

| parser | file | work per packet |
|---|---|---|
| **nanom** | [`bench/streaming_pcapng_bench.cpp`](https://github.com/yoavbendor/nanom/blob/main/bench/streaming_pcapng_bench.cpp) | `nm::streaming` header read + `strct<png_epb_body>` fixed fields |
| **Rust nom** (hand-written) | [`bench/rust_nom` `min`](https://github.com/yoavbendor/nanom/blob/main/bench/rust_nom/src/main.rs) | stable nom's own `streaming::{le,be}_u32` over the same window — **equal work** |
| Rust `pcap-parser` (library) | [`bench/rust_nom` `full`](https://github.com/yoavbendor/nanom/blob/main/bench/rust_nom/src/main.rs) | the standard nom-based pcapng crate — **also parses + allocates each packet's options** |

The **equal-work** row is `nanom` vs a hand-written minimal scanner on nom's *own* combinators — the
honest parser-combinator head-to-head. The `pcap-parser` row is what people actually use; it is slower
here only because it does strictly more per packet (`opt_parse_options` builds a `Vec<PcapNGOption>`),
and it is included precisely so the minimal scanner can't be accused of strawmanning nom.

## Result

Best-of-5, one machine (`g++-13 -O3 -march=native`; `cargo --release` LTO; nom 8.0.0,
pcap-parser 0.17.0), 224-packet / 352 KiB capture, 5000 iterations:

| parser | work | ns/packet | throughput | output |
|---|---|---:|---:|---|
| **nanom** (`nm::streaming`) | EPB fixed fields | **~46** | ~31 GiB/s | identical |
| **Rust nom** (hand-written) | EPB fixed fields (equal work) | ~52 | ~28 GiB/s | identical |
| Rust `pcap-parser` lib | + parses/allocs options | ~143 | ~10 GiB/s | identical |

**Equal-work head-to-head: nanom ~46 ns/pkt vs Rust nom ~52 ns/pkt — parity (~1.1×), a hair in
nanom's favour.** Both are zero-copy with no per-packet allocation. Against the real `pcap-parser`
library, either minimal scanner is ~3× faster because the library also parses options.

## Honesty notes

- These are best-of-N numbers on a single noisy machine; the **ratio** (parity) is the claim, not the
  absolute ns. Reproduce with `python3 bench/compare_rust.py --build`.
- The claim is scoped: *streaming pcapng EPB scanning*. It is not "nanom beats nom in general" — it is
  "on this equal-work streaming parse, nanom is at parity with stable Rust nom, with identical output."
- Fairness is falsifiable: the full harness, both sources, and the exact flags are in the repo. If the
  aggregates ever diverge, `compare_rust.py` fails loudly and prints no timings.

## Reproduce

```sh
python3 bench/compare_rust.py --build           # builds both, verifies equal output, prints the table
python3 bench/compare_rust.py --iters 20000     # more iterations for a steadier number
```
