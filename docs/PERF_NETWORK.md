# Network decode and crafting performance

How fast nanom_shark turns a capture into tables, how fast frames can be crafted, and where the
remaining time goes. Everything here is reproducible from the repository:

```sh
python3 bench/automotive_gen.py auto.pcap 1000000     # 1.05 M packets, 331 MB (deterministic)
python3 bench/automotive_gen.py small.pcap 20000      # 21 k packets, for callgrind
cmake --build build --target nm_shark_bench nm_craft_bench
./build/nm_shark_bench auto.pcap 3                     # sections A-E, best of 3
./build/nm_craft_bench 2000000 5                       # crafting A-F
valgrind --tool=callgrind ./build/nm_shark_bench small.pcap 1 C   # one section, one rep
```

The capture is synthetic automotive Ethernet: 802.1Q VLAN on every frame; 70% IPv4/UDP SOME/IP
notifications (32-byte payload), 10% SOME/IP-SD (two OfferService entries, one IPv4 endpoint
option), 10% IPv6 SOME/IP, 5% SOME/IP-TP segments (1392 bytes), 5% 2.9 kB SOME/IP messages split
into IPv4 fragments. `ctest` runs both benches on a 2 k-packet capture as a smoke test.

## Decode: `bench/nanom_shark_bench.cpp`

| section | what it times |
|---|---|
| A zero-copy floor | walk the pcap records and read two fields of each SOME/IP header with pointer arithmetic: the cost of touching the file at all |
| B bare walk | record header + `nmproto::walk_packet_ext` with an empty visitor (L2–L4 decode, no tables) |
| C decode, all tables | `run_decode_pass` into a fresh `default_decoder` table set: 25 tables, 6.3 rows and 167 bytes of columns per packet |
| D decode, projected | the same with only `packets` and `someip` enabled (`tables.enable_only(...)`) |
| E streaming | `StreamingDecodeSession::feed_epb` per block, a distinct buffer token per packet, every released token counted |

Measured on a shared 4-core cloud VM (g++ 13, `-O2 -DNDEBUG`, default safety profile:
`NANOM_GENERATION=1`, `NANOM_GUARD_VIEWS=1`), best of 3, ±5–10 % between runs. **Ir** = callgrind
instructions per packet over the 210 k-packet capture, with the file read and block scan
subtracted; it is exact and load-independent. For B in this table the block list is scanned
before the timed loop, as in the earlier ad-hoc bench these numbers are compared with; the
in-repo bench times the scan too (≈ +20 ns).

| | `main` 12f9e2b | + parser work (384ddb3) | **this change** |
|---|---:|---:|---:|
| A zero-copy floor | 48–53 ns | 49–50 ns | 50–51 ns |
| B bare walk | 96 ns, 793 Ir | 55 ns, 261 Ir | **53–56 ns, 261 Ir** |
| C decode, all tables | 594–622 ns, 7447 Ir | 460–470 ns, 5119 Ir | **250–265 ns, 1579 Ir** |
| D decode, packets + someip | — | — | **~175 ns** |
| E streaming, token per packet | 570–614 ns, 7468 Ir | 377–398 ns, 5363 Ir | **250–270 ns, 1659 Ir** |
| heap allocations / packet (C) | 0.35 | 0.34 | **0.19** |
| heap allocations / packet (E) | 1.55 | 1.53 | **0.29** |

The allocations that remain all belong to IP reassembly (one reassembled datagram every ~21
packets: its two hash-map entries, its fragment list, its part list, and in E the buffer pin):
an ordinary packet allocates nothing in either mode.

### What changed

* **`soa<T>` append path.** Every field of every row used to be appended with
  `std::vector<std::byte>::insert` into its own growing vector — 59 % of all instructions in C.
  The column layout is a compile-time fact, so `push()` is now an unrolled sequence of fixed-size
  stores at `column base + row × width`: one per leaf column, no per-field size check. A chunk owns
  one 64-byte-aligned allocation for all its columns; the open chunk grows geometrically
  (256 rows, doubling) to `chunk_rows`, and the next chunk starts at the size the previous one
  reached. A table that never receives a row allocates nothing. (Pre-reserving every column at
  `chunk_rows` and appending with `resize` + `memcpy`, the obvious fix, keeps a size check and a
  store of the vector's end pointer per field and still allocates 64 Ki rows for every table,
  used or not.) The read API — `chunks`, `chunk_at`, `cols[i].data()/size()`, `col(i)`,
  `as<V>(i)`, `column<"a.b">()`, `span<"a.b">()`, `columns()`, `rows()` — is unchanged in use;
  `chunk::cols[i]` is now a read-only `soa<T>::column_bytes` instead of a `std::vector<std::byte>`.
* **One pass over the file.** `run_decode_pass` collected a `BlockRef` per packet into a vector,
  then walked the vector, so every packet of a 331 MB file was fetched from memory twice. It now
  decodes each block as `nmpcap::for_each_block` reaches it.
* **Per-packet session work.** `FeedResult::released` is a `defrag::token_list` (inline storage,
  reads like the vector it replaces) instead of a fresh `std::vector` per call; the reassembly
  tables' per-packet `evict_stale` is skipped with an inline `may_evict()` test unless some entry
  can actually have aged out; eviction and retirement have non-allocating forms; reassembly sorts
  fragment pointers on the stack and builds the part list in place; the dispatch points wrap a
  contiguous payload as a one-part `seg_input` only when some protocol's trigger matched; the
  SOME/IP port test is one pass over the configured list.
* **Projection.** `tables.enable_only({...})` / `set_enabled(name, on)` / `set_all_enabled(on)`:
  a disabled table keeps nothing, and a protocol whose tables are all disabled is not parsed.

### Where the remaining time goes

Section C is now memory-bound, not instruction-bound. At ~1.6 k instructions a packet the CPU work
is ~120 ns at the IPC this host sustains; the rest is memory:

* **Reading the input**: ~50 ns/packet (section A) — 315 bytes of capture per packet streamed from
  DRAM, which no decode can avoid.
* **Writing the output**: 167 bytes per packet across ~50 concurrently advancing column streams
  (25 tables). A push-only microbenchmark that writes the same six rows per packet and decodes
  nothing takes ~75 ns/packet against already-mapped memory and ~150 ns when the memory is fresh.
  Section D, which writes ~52 of the 167 bytes, is ~75 ns faster than C.
* **First touch of fresh table memory**: 0.036 minor page faults per packet (~150 MB of new
  columns per pass). Measured in isolation, first-touching 175 MB costs ~60 ns/packet on this VM;
  inside the decode it overlaps with other work (an allocator configured to keep freed memory
  removes the faults but moves C by less than the run-to-run noise).

Instructions, by part (callgrind, C, 1524 Ir at `-O2` in a direct `run_decode_pass` driver): container
scan + record header + session bookkeeping ~250, the L2–L4 walk and visitor ~600, SOME/IP header +
SD + its table rows ~380, the other tables' pushes ~300.

Tried and rejected, because they did not move the wall time: transparent huge pages for the chunk
blocks (`madvise(MADV_HUGEPAGE)`: 98 % fewer faults, same time — the kernel still zeroes the
memory), `MADV_POPULATE_WRITE` (≈ 10 % off the fault cost in isolation, nothing measurable here),
and software prefetch of the column write streams.

## Crafting: `bench/craft_bench.cpp`

Building a 94-byte Eth + VLAN + IPv4 + UDP + SOME/IP notification (best of 5, 2 M frames). All six
variants produce byte-identical frames (FNV hash compared):

| | ns / frame |
|---|---:|
| A `emit<>` per layer (computed IPv4 length + checksum, UDP / SOME/IP lengths) | 25–33 (`main`: ~80) |
| B template copy + patch, full IPv4 header checksum (`inet::checksum`) | 11 |
| C template copy + patch, RFC 1624 incremental checksum (`inet::update16`) | 7 |
| D C plus a pcap record header, into one output buffer | 16–18 (6–7 GB/s written) |
| E `nanom::craft` combinators (`put_bytes | framed_by(...)` ×5) into a `span_sink` | 138–147 |
| F template copy + `overlay_mut` patch + `recompute()` | 11–21 |

A prebuilt template patched in place is the fastest way to produce many similar frames; the
RFC 1624 update replaces the checksum pass with three additions. `emit<>` per layer pays for
building and range-checking every field.

## Checksums: `nanom/checksum.hpp`

The Internet checksum adds 8 bytes per step into a 64-bit accumulator (≈ 30 GB/s on a 64 KiB
buffer, auto-vectorized), and sums runs shorter than 64 bytes as byte pairs, which is both cheap
and immune to the store-forwarding stall a wide load suffers right after the header was written a
byte at a time (that stall made the template patch above 2× slower). The AUTOSAR CRCs are
slicing-by-8 over compile-time tables, ≈ 2 GB/s each. Both are verified against bitwise reference
implementations on random data of every length and alignment, and the CRCs against the
SWS_Crc check values, in `tests/test_checksum.cpp`.
