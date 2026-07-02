# nanotins parity ports

These examples re-implement [nanotins](https://github.com/yoavbendor/nanotins)'
parsing seam and worked examples on top of **nanom**, to demonstrate that nanom
is a drop-in replacement for nanotins' reflection-struct + DAG parsing core.

Each port produces output that was verified **byte-identical** to the upstream
nanotins example built from source on the same inputs.

| file | ports | verified against |
|---|---|---|
| `nm_pcap.hpp` | `nanotins/pcap_blocks.hpp` — pcap/pcapng Phase-A block scan + Phase-B EPB/IDB parse | — |
| `nm_protocols.hpp` | `nanotins/protocols.hpp` + `protocol_decode.hpp` `walk_packet` — Eth/VLAN/IPv4/IPv6/TCP/UDP | — |
| `pcapng2json.cpp` | `examples/pcapng2json` — NDJSON per packet | byte-identical, 1236 packets across 4 captures + 34 MB concat |
| `dpar_lite.cpp` | `examples/dpar` + `examples/lldp` — rule engine, SOME/IP-TLV / raw-TLV / oddtlv / LLDP | stats + rows match on `dpar_sample.pcap` |

## What nanom changes vs nanotins

- **Runtime endianness** (`strct<T>(order)`) replaces nanotins' hand-written
  `rd16/rd32(le)` reader pairs: pcapng's per-section byte order and classic
  pcap's swapped magics are one argument, not a parallel reader set.
- **One `NANOM_DESCRIBE`** gives a struct its parser, its `view<T>` overlay,
  its schema, its JSON/CSV, and its `soa<T>` columns — no `boost::describe`,
  no separate `wire_spec` / `spec_dag` / bulk headers.
- **Reflection-driven rule matching**: `dpar_lite` matches `<node>.<field>`
  against any described header with no hand-maintained field catalog, and the
  rules DSL itself is parsed with nanom's text combinators.
- **Combinator TLV parsers**: LLDP's packed `[type:7][length:9]` header is two
  `ubits<>` fields; SOME/IP-TLV width dispatch is a `flat_map`.

## Known non-goals (where nanom is *not* yet a superset)

nanom does **not** replicate nanotins' device-callable (`NANOTINS_HD`) parsers
or its `bulk_for_each` count-then-scatter GPU path. nanom's combinators
allocate (`many0` → `std::vector`) and use `std::expected`, so they are host
CPU parsers. See the top-level DESIGN notes for the planned no-alloc POD mode.

## Running

Built and tested by the top-level CMake (`parity_json_*`, `parity_dpar`,
`parity_lldp` tests). Manually:

```sh
nm_pcapng2json capture.pcapng            # NDJSON per packet
nm_dpar_lite --stats rules.txt capture.pcapng
```
