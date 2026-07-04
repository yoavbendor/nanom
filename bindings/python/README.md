# nanom from Python — zero-copy into Arrow / polars

A complete, ~1-file example of the pattern that makes nanom useful to Python data folks: **parse your
binary format in C++ with nanom, and hand Python a zero-copy Arrow table** that polars, pandas, pyarrow
and duckdb all consume without a copy. You get C++ parse speed and land directly in the dataframe stack.

On a 224-packet pcapng, producing the *same* columnar table, nanom is **~35× faster than dpkt and ~90×
faster than python-pcapng** — because it parses in C++ and the columns are already Arrow buffers.

| parser | ms/run | packets/sec | ns/packet | slowdown |
|---|---:|---:|---:|---:|
| **nanom** (C++ + zero-copy Arrow) | **~0.08** | **~2.9 M** | **~344** | 1.0× |
| dpkt (pure Python) | ~2.7 | ~82 k | ~12 200 | ~35× |
| python-pcapng (pure Python) | ~7.1 | ~31 k | ~31 800 | ~92× |

It's an honest C++-vs-Python comparison — which *is* the pitch. All engines are asserted to produce the
identical `(packets, Σcaplen)` before any timing (`bench.py`).

## The two sides

**C++ side** — [`example_pcapng.cpp`](example_pcapng.cpp): declare the row you want as columns, fill it
in a parse loop, expose it. The Arrow bridge is generic and lives in
[`nanom_arrow.hpp`](nanom_arrow.hpp) — you don't touch it.

```cpp
struct pkt_row {                                   // <-- your columns
  std::uint32_t interface_id, caplen, origlen;
  std::uint64_t ts;
  std::array<std::uint8_t,6> eth_dst, eth_src;     // -> Arrow fixed_size_binary(6)
  std::uint16_t ethertype;
};
NANOM_DESCRIBE(pkt_row, interface_id, ts, caplen, origlen, eth_dst, eth_src, ethertype);
// ... parse with nanom (nm::strct<>(order)), push each row into an nm::soa<pkt_row> ...
```

**Python side** — [`demo.py`](demo.py): three lines, zero-copy the whole way.

```python
import nanom_pcap, pyarrow as pa, polars as pl
tbl = pa.table(nanom_pcap.parse(open("cap.pcapng","rb").read()))   # zero-copy (Arrow PyCapsule)
df  = pl.from_arrow(tbl)                                            # zero-copy into polars
print(df.group_by("ethertype").agg(pl.col("caplen").mean()))
```

## Build & run

```sh
cd bindings/python
pip install .                       # builds the nanobind extension (needs a C++23 compiler + cmake)
python demo.py  ../../examples/nanotins_parity/testdata/SRL_front_left_51_short.pcapng
pip install '.[bench]' && python bench.py     # nanom vs dpkt / python-pcapng (/ scapy if present)
```

No network dependency beyond nanobind: the Arrow C Data Interface bridge is hand-rolled in
`nanom_arrow.hpp` (nanoarrow is intentionally *not* required), so the extension stays tiny.

## To parse *your* format — change ~10 lines

1. Rewrite `pkt_row` + its `NANOM_DESCRIBE` to the fields you want as columns (scalars → primitive Arrow
   columns; `std::array<u8,N>` → `fixed_size_binary(N)`; `nm::be<>`/`nm::ubits<>` fields decode to host
   order automatically).
2. Replace the parse loop with your nanom parser (`nm::strct<YourHeader>(order)`, combinators, etc.),
   pushing each decoded row into the `nm::soa<pkt_row>`.
3. Rename the module in `NB_MODULE(...)` and `CMakeLists.txt`.

Everything else — `nanom_arrow.hpp`, the PyCapsule glue, the Python side — is unchanged.

## How the zero-copy works

`nm::soa<T>` stores each column as a contiguous, host-order buffer whose Arrow C-data **format string**
it already knows (`"I"`, `"L"`, `"w:6"`, …). `nanom_arrow.hpp` wraps those buffers as an
`ArrowArrayStream` — one struct `RecordBatch` per soa chunk, each child array pointing straight at the
column buffer — and the extension exposes it through the **Arrow PyCapsule protocol**
(`__arrow_c_stream__`). The consumer (pyarrow/polars) imports the pointers directly; a `shared_ptr` in
the stream's release callback keeps the `soa` alive until Python is done. No serialization, no copy.

Because every soa column is fixed-width, the whole table is zero-copy. (Variable-length payloads, e.g.
via `length_data`, would need Arrow var-binary/list layout — out of scope for this example, which sticks
to the decoded header fields.)

## Files

- [`nanom_arrow.hpp`](nanom_arrow.hpp) — **reusable, domain-free**: `soa<T>` → `ArrowArrayStream`.
- [`example_pcapng.cpp`](example_pcapng.cpp) — the nanobind module (`nanom_pcap`): the struct + parser.
- [`demo.py`](demo.py) / [`bench.py`](bench.py) — the Python demo and the benchmark.
- [`test_arrow_cpp.cpp`](test_arrow_cpp.cpp) — pure-C++ ASan/UBSan check of the exporter's lifetime.

## Want a harder example?

[`gptp/`](gptp/) is the comprehensive version: a full gPTP (IEEE 802.1AS) parser — 8 message kinds,
runtime tagged dispatch, a bit-packed tag byte, a 48-bit timestamp, and two kinds of TLV — landing in 9
zero-copy Arrow tables. Same `nanom_arrow.hpp` bridge, unchanged.
