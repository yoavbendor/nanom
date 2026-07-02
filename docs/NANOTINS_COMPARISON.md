# nanom as a nanotins replacement — evidence

This is the falsifiable comparison behind "can nanom replace nanotins?". Every
claim here is reproduced by code in this repo (`examples/nanotins_parity/`,
`bench/`, `fuzz/`) and was checked against **nanotins built from source**.

## TL;DR

nanom is a **behaviorally exact, more ergonomic** replacement for nanotins'
reflection-struct parsing core on the CPU + columnar path, at **parity decode
speed** when you use the zero-copy overlay path (~28–32 vs ~29–31 ns/pkt). It is
**not** a replacement for nanotins' device-callable / GPU-bulk path — that is out
of scope by design.

"nanom ≥ nanotins" is therefore **true on ergonomics and correctness, a tie on
CPU decode speed and columnar capability, and false only on the device/GPU-bulk
axis.** Parity rewrites alone could never have shown this — the measurements did,
and profiling turned an apparent 1.2× speed gap into a one-line fix (below).

## What was proven, and how

### 1. Correctness / equivalence — PASS (strongest evidence)

- **pcapng2json** (`pcapng2json.cpp`): NDJSON output **byte-identical** to the
  upstream nanotins example over 1,236 packets across 4 real captures
  (SRL/PTP/ipv4-options/srv6) and a 34 MB multi-section concat.
- **dpar + lldp** (`dpar_lite.cpp`): rule-engine `packets_seen`, `matched_any`,
  and per-rule `matched`/`rows` all agree with nanotins' dpar/lldp binaries.
- **Differential fuzz** (`fuzz/differential_fuzz.cpp`): 600,000 random / mutated
  inputs, nanom vs nanotins decode compared field-for-field → **0 mismatches**.
- The parse-only bench accumulates a field checksum: nanom (both paths) and
  nanotins produce the **identical** `ac8f6ce882238780`.

### 2. Safety — PASS

- **self_fuzz** (in CI) + differential_fuzz: **1.2M total fuzz cases, no crash /
  no OOB** under ASan+UBSan. Every combinator bounds-checks by construction.
- Round-trip invariant: `scan_blocks`+`parse_epb` reproduce payloads exactly
  (raw-walk vs pcap-wrapped-walk hashes cancel).

### 3. Speed — PARITY on overlay (was 1.2×, profiled and fixed)

Parse-only, no JSON/IO, 44,800 packets, best of 300 (`bench/parse_bench.cpp`):

| decoder | ns/pkt | vs nanotins |
|---|---:|---:|
| nanotins (wire_spec overlay) | ~29–31 | 1.00× |
| nanom `overlay<T>()` | ~28–32 | **~1.0× (parity)** |
| nanom `strct<T>()` (materialize all) | ~74 | ~2.4× |

**How, and why this matters methodologically.** The first bench had overlay at
1.2×. Rather than guess, callgrind attributed the walk: the gap was **one thing**
— the msb0 bit-field decode ran a *bit-at-a-time* loop, ~35% of the walk. It was
**not** the `std::expected` result size and **not** allocation (the overlay path
allocates nothing per packet). A word-load+shift-mask fast path in `decode_field`
(O(bytes), nanotins' technique) closed it to parity — checksum and the 600k-case
differential fuzz unchanged. `strct<>` stays ~2.4× because it materializes every
field; lesson: **`overlay<>` for hot walks, `strct<>`/`soa<>` for tabulation.**

### 4. Capability (columnar → Lance) — PASS for the data path

`pcap2columns.cpp` builds the pcapng2lance L1 PacketRow path on `nm::soa<T>`:
correct Arrow C-Data schema strings (`L/I/S/C`, `w:4`/`w:16` fixed-binary for
addresses), contiguous per-column buffers, and a **lossless round-trip** from
the column spans (0 mismatches, `parity_columns` test). The only missing step vs
a real `.lance` write is the nanoarrow call on top of those buffers (nanoarrow
isn't vendored here).

### 5. Ergonomics — nanom AHEAD

One `NANOM_DESCRIBE` per struct replaces `boost.describe` + the `wire_spec` /
`spec_dag` / bulk header set. Runtime endianness is one argument
(`strct<T>(order)`) instead of parallel LE/BE readers. Rule-field matching is
reflection-driven with no hand-maintained field catalog.

## Scorecard

| axis | verdict |
|---|---|
| decode correctness | **=** identical checksums, 0 fuzz mismatches |
| safety on malformed input | **=** 1.2M cases clean (both bounded) |
| CPU overlay decode speed | **=** parity (~28–32 vs ~29–31 ns/pkt) |
| `strct<>` materialize speed | **nanotins** by ~2.4× (use overlay for hot walks) |
| schema / Arrow / SoA columns | **=** both produce Arrow-ready columns |
| ergonomics / LOC | **nanom** |
| runtime endianness | **nanom** |
| device-callable / GPU bulk | **nanotins** (nanom has no POD/no-alloc mode) |

## What's still missing to fully close "≥"

1. **A no-alloc, POD, device-callable mode** for nanom (no `std::expected`, no
   `std::vector` in `many*`) — the prerequisite for matching nanotins' GPU/bulk
   story. This is the one axis where nanom is structurally behind. Note the
   profiling result: CPU overlay speed is *not* blocked on this — the overlay
   walk already allocates nothing per packet and is at parity.
2. **The real `.lance` write** (nanoarrow import of the `soa<T>` column buffers)
   plus a tshark round-trip, once nanoarrow is on the include path.
