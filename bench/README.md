# nanom parse-only benchmark

`parse_bench.cpp` times **only the decode** — capture is read into memory once,
the block scan is done once, and the timed loop is purely the per-packet
L2/L3/L4 walk. No file I/O, no JSON, no output allocation in the loop. A FNV-1a
checksum of every decoded field is accumulated so the optimizer can't elide the
work and so the number is comparable field-for-field against another decoder.

```sh
g++-13 -std=c++23 -O3 -march=native -I include -o nm_bench bench/parse_bench.cpp
./nm_bench capture.pcapng 300      # 300 iterations, reports best
```

## Why parse-only

The `pcapng2json` converter is dominated by `snprintf` + `fwrite`; its wall time
(~0.12 s) says nothing about the parser. This bench isolates the walk, which is
the part nanotins parallelizes and the only fair basis for a core-vs-core speed
claim.

## Result (g++-13 -O3 -march=native, 67 MiB capture, 44,800 packets, best of 300)

| decoder | ns/packet | MB/s | vs nanotins |
|---|---:|---:|---:|
| nanotins (wire_spec overlay) | ~29–31 | ~50,000 | 1.00× |
| **nanom `overlay<T>()`** (lazy field decode) | **~28–32** | ~50,000 | **~1.0× (parity)** |
| nanom `strct<T>()` (materialize every field) | ~74 | ~20,000 | ~2.4× |

All three produce the **identical checksum** (`ac8f6ce882238780`) — nanom decodes
every field to the same value as nanotins. (Numbers are from one noisy shared
cloud host, ±3 ns run-to-run; overlay and nanotins trade places between runs.)

## How overlay reached parity (measured, not guessed)

The first version of this bench had `overlay<>` at 35.6 ns/pkt (1.2× nanotins).
Callgrind attribution of the walk showed the gap was **one thing**: the msb0
bit-field decode ran a bit-*at-a-time* loop (`read_bits`), which was **~35% of
the walk** (extracting `ihl`, `frag_offset`, `vid`, `data_offset`). It was *not*
the `std::expected` result size and *not* per-packet allocation — the overlay
path allocates nothing per packet.

The fix (in `decode_field`): for a byte-spanning `ubits<>/ibits<>` in msb0 order,
load the covering bytes as one big-endian word and shift+mask — O(bytes), not
O(bits) — exactly nanotins' technique. That single localized change took overlay
from 35.6 → ~28 ns/pkt, i.e. to parity, with the checksum and the 600k-case
differential fuzz unchanged.

## Reading the result

- **`overlay<T>()` is the hot path and is now at parity** with a hand-tuned
  overlay parser. It decodes only the fields you touch, exactly like nanotins'
  `wire_spec` overlay.
- **`strct<T>()` is the convenience path**: it materializes every field by value
  (all 13 IPv4 fields, both address arrays), so it stays ~2.4× slower. Use it —
  and `soa<T>` — when you keep every column (tabulation); use `overlay<T>()` for
  a hot classification walk that reads a handful of fields.

`result<T>` is 96 bytes (down from 168, after the error type was shrunk to 4
context frames + 32-bit offsets); the profile showed it is not on the critical
path for the overlay walk, so no further no-`expected` fast path is warranted
for now.

## Honest scorecard vs nanotins

| axis | nanom | nanotins |
|---|---|---|
| decode correctness | identical checksum | reference |
| overlay decode speed | **parity** (~28–32 ns/pkt) | ~29–31 ns/pkt |
| ergonomics / LOC | one `NANOM_DESCRIBE`, no boost, no DAG headers | wire_spec + spec_dag + boost.describe |
| runtime endianness | one arg (`strct<T>(order)`) | parallel LE/BE readers |
| **device-callable / GPU** | **no** (allocates in `many*`, `std::expected`) | **yes** (`NANOTINS_HD`, POD) |
| **bulk count-then-scatter** | **no** | **yes** (stdexec) |
| schema / Arrow / SoA | yes | yes |

nanom wins on ergonomics, **ties on overlay decode speed and on the CPU/columnar
capability**, and is **behind only on the device/GPU-bulk path**, which is
nanotins' design priority. The GPU gap is real (nanom's `many*` allocate and it
returns `std::expected`); it is *not* a general CPU-speed gap — the profiler
showed the earlier speed difference was a single bit-loop, now fixed.
