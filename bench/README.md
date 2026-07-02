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
| nanotins (wire_spec overlay) | 29.3 | 51,200 | 1.00× |
| **nanom `overlay<T>()`** (lazy field decode) | **35.6** | 42,155 | **1.21×** |
| nanom `strct<T>()` (materialize every field) | 82.6 | 18,148 | 2.82× |

All three produce the **identical checksum** (`ac8f6ce882238780`) — nanom decodes
every field to the same value as nanotins. (Numbers are from one shared cloud
host and will vary; the *ratios* are the point.)

## Reading the result

- **`overlay<T>()` is the hot path and is competitive** — within ~20% of a
  hand-tuned overlay parser. It decodes only the fields you touch (the walk
  reads ~5 of IPv4's 13 fields), exactly like nanotins' `wire_spec` overlay.
- **`strct<T>()` is the convenience path**: it materializes every field by value
  (and extracts every bit field), so it's ~2.8× slower here. Use it — and
  `soa<T>` — when you keep every column (tabulation); use `overlay<T>()` for a
  hot classification walk where you read a handful of fields.

## The remaining ~20% (overlay vs nanotins)

Two known costs, both addressable, neither yet optimized:

1. **Bit-field extraction.** nanom's `read_bits` consumes bits in a loop;
   nanotins byteswaps the whole word once and shift+masks. For headers with
   byte-spanning bit fields (IPv4 flags/frag, IPv6 flow_label) this is the main
   gap. A word-load-then-mask fast path for byte-spanning `ubits<>` would close
   most of it.
2. **`std::expected` result size.** `result<T>` is 96 bytes (was 168 before the
   error type was shrunk to 4 context frames + 32-bit offsets); it is still
   larger than nanotins' `bool` + out-param. A thin no-`expected` fast path is
   possible but would complicate the API.

## Honest scorecard vs nanotins

| axis | nanom | nanotins |
|---|---|---|
| decode correctness | identical checksum | reference |
| overlay decode speed | ~1.2× slower | baseline |
| ergonomics / LOC | one `NANOM_DESCRIBE`, no boost, no DAG headers | wire_spec + spec_dag + boost.describe |
| runtime endianness | one arg (`strct<T>(order)`) | parallel LE/BE readers |
| **device-callable / GPU** | **no** (allocates, `std::expected`) | **yes** (`NANOTINS_HD`, POD) |
| **bulk count-then-scatter** | **no** | **yes** (stdexec) |
| schema / Arrow / SoA | yes | yes |

nanom wins on ergonomics and ties on capability for the CPU/columnar path; it is
**behind on raw speed and on the device/bulk path**, which are nanotins' design
priorities. See the top-level DESIGN notes for the planned no-alloc POD mode.
