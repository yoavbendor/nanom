# nanom as a nanotins replacement — evidence

This is the falsifiable comparison behind "can nanom replace nanotins?". Every
claim here is reproduced by code in this repo (`examples/nanotins_parity/`,
`bench/`, `fuzz/`) and was checked against **nanotins built from source**.

## TL;DR

nanom is a **behaviorally exact, more ergonomic** replacement for nanotins'
reflection-struct parsing core on the CPU + columnar path, at **~1.2× the decode
cost** when you use the zero-copy overlay path. It is **not** a replacement for
nanotins' device-callable / GPU-bulk path — that is out of scope by design.

"nanom ≥ nanotins" is therefore **true on ergonomics and correctness, a tie on
CPU capability, false on raw speed and on the device/bulk axis.** Parity rewrites
alone could never have shown this — the measurements did.

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

### 3. Speed — nanom BEHIND (~1.2× overlay, ~2.8× strct)

Parse-only, no JSON/IO, 44,800 packets, best of 300 (`bench/parse_bench.cpp`):

| decoder | ns/pkt | vs nanotins |
|---|---:|---:|
| nanotins (wire_spec overlay) | 29.3 | 1.00× |
| nanom `overlay<T>()` | 35.6 | 1.21× |
| nanom `strct<T>()` (materialize all) | 82.6 | 2.82× |

The overlay gap is the bit-field extraction (`read_bits` loop vs word-mask) and
the 96-byte `result<T>` (already shrunk from 168). Both are addressable; see
`bench/README.md`. Lesson: **`overlay<>` for hot walks, `strct<>`/`soa<>` for
tabulation.**

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
| CPU overlay decode speed | **nanotins** by ~1.2× |
| `strct<>` materialize speed | **nanotins** by ~2.8× (use overlay) |
| schema / Arrow / SoA columns | **=** both produce Arrow-ready columns |
| ergonomics / LOC | **nanom** |
| runtime endianness | **nanom** |
| device-callable / GPU bulk | **nanotins** (nanom has no POD/no-alloc mode) |

## What's still missing to fully close "≥"

1. **A no-alloc, POD, device-callable mode** for nanom (no `std::expected`, no
   `std::vector` in `many*`) — the prerequisite for matching nanotins' GPU/bulk
   story. This is the one axis where nanom is structurally behind.
2. **A word-mask fast path** for byte-spanning `ubits<>` to close most of the
   overlay speed gap.
3. **The real `.lance` write** (nanoarrow import of the `soa<T>` column buffers)
   plus a tshark round-trip, once nanoarrow is on the include path.
