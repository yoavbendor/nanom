# nanom vs stable Rust nom — streaming pcapng, verified-equal output

The headline question for a C++ nom-alike is: *is it actually as fast as Rust nom?* This is the
falsifiable answer. Same task, same file, same streaming model, in both languages — and the two
parsers are **proven to produce byte-identical output** before any timing is reported.

## The task

Parse a pcapng capture in **streaming mode**: walk the block stream through a bounded, refilling
buffer (a 64 KiB window that `refill()`s from the source — the whole file is never resident in the
parser's working set) and, for each **Enhanced Packet Block**, read the fixed fields (`interface_id`,
timestamp, `caplen`, `origlen`) **and walk every option TLV** — the same `many0(parse_option)` region
the `pcap-parser` library walks, down to the `opt_endofopt` terminator. No payload copy. Every parser
accumulates the same aggregate — `(packets, Σcaplen, Σoriglen, #options, fnv1a(ts_raw, caplen, origlen,
and every option's code/length/value bytes))` — and the harness
[`bench/compare_rust.py`](https://github.com/yoavbendor/nanom/blob/main/bench/compare_rust.py) **asserts all aggregates are identical** before it
prints a single timing number. (This is the cross-language analogue of the `parse_bench` field
checksum.) Because the checksum folds the option bytes too, the gate proves all three parsers decode
the option TLVs the same way — not just the fixed fields.

## The three parsers (fair by construction)

| parser | file | work per packet |
|---|---|---|
| **nanom** | [`bench/streaming_pcapng_bench.cpp`](https://github.com/yoavbendor/nanom/blob/main/bench/streaming_pcapng_bench.cpp) | `nm::streaming` header + `strct<png_epb_body>` fixed fields + `strct<png_opt_hdr>` option walk |
| **Rust nom** (hand-written) | [`bench/rust_nom` `min`](https://github.com/yoavbendor/nanom/blob/main/bench/rust_nom/src/main.rs) | stable nom's own `streaming::{le,be}_u32/u16`, fixed fields + the same option walk — **equal work** |
| Rust `pcap-parser` (library) | [`bench/rust_nom` `full`](https://github.com/yoavbendor/nanom/blob/main/bench/rust_nom/src/main.rs) | the standard nom-based pcapng crate — the same parse, but **allocates each packet's options into a `Vec<PcapNGOption>`** |

All three do the **same work** — fixed fields *and* the full option-TLV walk. The **equal-work** row is
`nanom` vs a hand-written scanner on nom's *own* combinators: the honest parser-combinator head-to-head,
both zero-copy. The `pcap-parser` row is what people actually use; the only difference from the
hand-written scanner is that `opt_parse_options` allocates a `Vec<PcapNGOption>` per packet — so that
row isolates the **cost of allocation**, not of extra parsing.

## Safety profiles

`compare_rust.py` builds nanom twice for the equal-work streaming benchmark:

| profile | flags | role |
|---|---|---|
| **minimal** | `NANOM_GENERATION=0`, `NANOM_GUARD_VIEWS=0` | opt-out perf baseline |
| **full** | `NANOM_GENERATION=1`, `NANOM_GUARD_VIEWS=1`, `wire_arena` on refill buffer | **safety-first** (matches CI/library defaults) |

Both profiles must produce **identical** aggregates before timings are reported. CI's `perf-budget`
job fails if `full/minimal` ns/packet exceeds **1.20×** on the standard fixture.

## Result

Best-of-5, one machine (`g++-13 -O3 -march=native`; `cargo --release` LTO; nom 8.0.0,
pcap-parser 0.17.0), 224-packet / 352 KiB capture (896 options total, incl. `opt_endofopt`), 20000
iterations:

| parser | work | ns/packet | throughput | output |
|---|---|---:|---:|---|
| **nanom** (`nm::streaming`) | EPB fields + all options | **~110** | ~13 GiB/s | identical |
| **Rust nom** (hand-written) | EPB fields + all options (equal work) | ~119 | ~12 GiB/s | identical |
| Rust `pcap-parser` lib | same, + allocates options | ~203 | ~7 GiB/s | identical |

**Equal-work head-to-head: nanom ~110 ns/pkt vs Rust nom ~119 ns/pkt — parity (~1.1×), a hair in
nanom's favour.** Both parse the full block — fixed fields and every option TLV — zero-copy, with no
per-packet allocation. Against the real `pcap-parser` library doing the identical parse, nanom is
~1.85× faster, the difference being the library's per-packet `Vec` allocation.

## Honesty notes

- These are best-of-N numbers on a single noisy machine; the **ratio** (parity) is the claim, not the
  absolute ns. Reproduce with `python3 bench/compare_rust.py --build`.
- The claim is scoped: *streaming pcapng EPB parsing, fixed fields + options*. It is not "nanom beats
  nom in general" — it is "on this equal-work streaming parse, nanom is at parity with stable Rust nom,
  with identical output."
- The comparison parses the **full** block, including every option TLV — nanom is not made to look fast
  by doing less than `pcap-parser`; it does the same decode and folds the same option bytes into the
  verified checksum.
- Fairness is falsifiable: the full harness, both sources, and the exact flags are in the repo. If the
  aggregates ever diverge, `compare_rust.py` fails loudly and prints no timings.

## Reproduce

```sh
python3 bench/compare_rust.py --build --safety both    # both profiles + parity table
python3 bench/compare_rust.py --iters 20000            # steadier numbers
python3 bench/compare_rust.py --build --safety both --max-overhead 1.20  # CI budget gate
```
