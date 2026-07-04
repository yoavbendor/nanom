# nanom from Python, comprehensive edition — a full gPTP parser (IEEE 802.1AS)

The [pcapng example](../README.md) one directory up shows the pattern with one flat struct. This one is
the stress test: is "add your own C++ nanom parser and use it from Python" still easy for a *real*
protocol with a genuinely harder shape? **gPTP (IEEE 802.1AS)** has 8 message kinds with different
bodies, dispatched at runtime from a bit-packed tag byte, a 48-bit timestamp field, and two kinds of
TLV — exactly the friction points a toy example doesn't surface.

```
python demo.py
```
parses a synthetic gPTP capture (`build_fixture.py`) and lands **9 zero-copy Arrow tables** — one per
message kind, plus one for Announce's `PATH_TRACE` entries — straight into polars.

## The 8 message kinds, as tables

| table | message kind | notable field(s) |
|---|---|---|
| `sync` | Sync | — |
| `follow_up` | Follow_Up | Follow_Up Information TLV (rate offset, GM time base, freq change) |
| `delay_req` | Delay_Req (E2E) | — |
| `delay_resp` | Delay_Resp (E2E) | nested `requesting_port_identity` |
| `pdelay_req` | Pdelay_Req (P2P) | — |
| `pdelay_resp` | Pdelay_Resp (P2P) | nested `requesting_port_identity` |
| `pdelay_resp_follow_up` | Pdelay_Resp_Follow_Up (P2P) | nested `requesting_port_identity` |
| `announce` | Announce | grandmaster fields, `PATH_TRACE` presence/count |
| `path_trace` | *(one row per Announce PATH_TRACE clockIdentity)* | joins back via `msg_index` |

**N separate tables, not one wide struct** — matching how nanolance's `pcapng2lance_nanom` example
handles its 10 PDU types (Ethernet/VLAN/IPv4/IPv6/TCP/UDP/…): each message kind gets its own natural
column set, no wasted/null columns (`soa<T>` has no null bitmap, so a one-wide-struct design would need
zero-filled placeholders for every field that doesn't apply to a given row).

## How nanom handles a tagged/variant protocol (the pattern this example exists to prove out)

nanom's `alt()` and `flat_map()` combinators both require **one common return type across every
branch** — `alt` via `std::common_type_t<...>`, `flat_map` via a single deduced closure return type
(see `include/nanom/nom.hpp`). That's fine for "try these parsers, they all produce a `u64`"
(`examples/nanotins_parity/dpar_lite.cpp`'s hex-or-decimal `alt`), but it structurally **cannot**
dispatch one tag byte into N *differently-shaped* row types — there's no `std::variant`-returning
combinator in nanom today.

The pattern that works (and is already proven elsewhere in this codebase — `nm_pcap.hpp`'s SHB/IDB/EPB
dispatch, and nanolance's 10-PDU-type visitor dispatch) is:

1. Parse the shared header once via `strct<>()`.
2. Plain C++ `switch` on the discriminant field.
3. Call a separate function per kind — each returns/builds its own row type and pushes it into its own
   `soa<T>`.

```cpp
auto hdr = nm::strct<GptpHeader>(std::endian::big)(msg);
switch (std::uint8_t(hdr->value.message_type)) {
  case kMsgSync:     return parse_sync(tables, common, body);
  case kMsgAnnounce: return parse_announce(tables, common, body);
  // ...
}
```
See [`gptp_parse.hpp`](gptp_parse.hpp)'s `parse_gptp_message`. This is deliberately **not** a case for a
new core combinator — a hypothetical `nm::dispatch<Tag>(...)` would need to settle on something like
`std::variant<Rows...>` as its return type, which is a real core-library design question of its own, not
a quick addition. The switch-based pattern above is proven, low-risk, and — as this example shows —
scales cleanly to 8 kinds.

## The other friction points, resolved

- **Bit-packed tag byte**: `transportSpecific:4 | messageType:4` is one `nm::ubits<4>` pair, the same
  shape as the main README's `vlan_hdr{ubits<3> pcp; ubits<1> dei; ...}` example.
- **The 48-bit timestamp — no `reinterpret_cast` anywhere**: `nm::be_u48` already exists and returns the
  correctly-combined value as a `uint64_t` (nanom handles non-power-of-2 integer widths at the raw
  combinator level, "like nom does"). There's no struct-field wire type for a 48-bit scalar (no C++
  `uint48_t`), so `gptp_parse.hpp`'s `FieldReader` just calls `be_u48()` directly — see `read_timestamp`.
- **TLV walking**: Announce's `PATH_TRACE` and Follow_Up's Information TLV both use the same
  bounded-manual-while-loop shape as the pcapng-option walk in `bench/streaming_pcapng_bench.cpp` — parse
  a small `[type, length]` header, bound the value to what's declared, **advance by the declared length**
  (not by how much of it was actually decoded) so an unrecognized/future TLV can never desync the walk.
- **Nested nesting**: `PortIdentity` (`clockIdentity` + `portNumber`) is a small `Described` struct nested
  inside `RowCommon` inside e.g. `AnnounceRow` — `soa<T>` flattens it automatically into dotted columns
  (`common.source_port_identity.clock_identity`), two levels deep, with zero extra code.

## Build & run

```sh
cd bindings/python/gptp
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build && export PYTHONPATH=build
python demo.py
python test_gptp.py     # correctness suite: exact per-kind row counts + known field values
```

`build_fixture.py` hand-builds a synthetic pcapng capture (no real gPTP captures are as readily available
as pcapng ones) covering all 8 message kinds, a 3-entry `PATH_TRACE` TLV, and a Follow_Up Information
TLV — and exposes every value it used so `test_gptp.py` asserts against ground truth, not duplicated
magic numbers.

No cross-language timing claim here (unlike the pcapng example): there's no established pure-Python gPTP
parser to compare against fairly, so this example's deliverable is **correctness and coverage** — every
message kind, both TLV kinds, and the exact reconstructed 48-bit timestamps, verified against a fixture
whose bytes are fully known.

## Files

- [`gptp_rows.hpp`](gptp_rows.hpp) — `GptpHeader`, `PortIdentity`, the 8 per-kind row structs, and
  `PathTraceEntryRow` — all plain `NANOM_DESCRIBE`'d structs.
- [`gptp_parse.hpp`](gptp_parse.hpp) — the header-parse + switch dispatch, the TLV walks, and the
  self-contained pcapng/Ethernet demux (ethertype `0x88F7`).
- [`example_gptp.cpp`](example_gptp.cpp) — the nanobind module (`nanom_gptp`); reuses
  [`../nanom_arrow.hpp`](../nanom_arrow.hpp) **completely unchanged**.
- [`build_fixture.py`](build_fixture.py) — the synthetic capture generator + expected-values ground truth.
- [`demo.py`](demo.py) / [`test_gptp.py`](test_gptp.py) — the polars walkthrough and the correctness suite.
