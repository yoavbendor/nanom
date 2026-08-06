# `nanom_shark` from Python — every decoded table, zero-copy, via Arrow

`nanom_shark` decodes a pcap/pcapng capture end to end in one pass — Ethernet, VLAN 802.1Q/QinQ,
IPv4 (with defragmentation), IPv6 (full extension-header chain incl. SRv6), TCP/UDP, SOME/IP (incl.
Service Discovery and TLV), gPTP (all 8 message types), LLDP — into 24 in-memory columnar tables.
This binding hands all 24 to Python as zero-copy Arrow streams.

```python
import nanom_shark, pyarrow as pa, polars as pl

result = nanom_shark.parse(open("capture.pcapng", "rb").read())

print(result.table_names)          # all 24 declared tables
print(result.non_empty.keys())     # just the ones this capture actually produced

eth = pa.table(result["eth"])      # zero-copy: Arrow points straight into the C++ soa buffers
ip  = pl.from_arrow(result["ipv4"])
print(eth.num_rows, ip["body.ttl"].value_counts())
```

Batteries included: unlike the sibling [`bindings/python/`](../README.md) example — which is a
tutorial for wrapping *your own* struct — this package wraps nanom_shark's real, complete decoder.

## Install

With [uv](https://docs.astral.sh/uv/) (recommended — this is the path CI exercises):

```sh
uv venv
uv pip install '.[demo]'      # builds the wheel through scikit-build-core + CMake + nanobind
uv run python demo.py ../../../examples/nanotins_parity/testdata/SRL_front_left_51_short.pcapng
```

or with pip:

```sh
pip install '.[demo]'
```

`uv build --wheel` works too. `uv build` on its own (which builds an sdist first, then the wheel
*from* that sdist) does **not**: this package lives inside the nanom repo and reaches up to
`../../../include` and `../nanom_arrow.hpp`, neither of which an sdist rooted at this directory can
contain. That is a property of the in-repo layout shared with the sibling `nanom-pcap` package, not
of this binding; publishing a standalone sdist would mean vendoring the headers in first.

or build the extension directly with CMake (what the repo's CI does for the other bindings, and the
fastest edit/rebuild loop):

```sh
cmake -S . -B /tmp/nspybuild -DCMAKE_BUILD_TYPE=Release \
  -DPython_EXECUTABLE="$(which python3)" -Dnanobind_DIR="$(python3 -m nanobind --cmake_dir)"
cmake --build /tmp/nspybuild -j
cp /tmp/nspybuild/nanom_shark*.so .
python test_nanom_shark.py
```

Only nanobind is needed to build; nanom and nanom_shark are header-only (`INTERFACE`) libraries, so
there is nothing to link. The Arrow C Data Interface bridge is hand-rolled in
[`../nanom_arrow.hpp`](../nanom_arrow.hpp) — no nanoarrow, no libarrow, no Arrow C++ dependency at
build time. Any Arrow consumer (pyarrow, polars, pandas, duckdb) imports the result without a copy.

## API

| | |
|---|---|
| `parse(capture_bytes, someip_ports=None, someip_tlv_ports=None)` | decode; returns a `DecodeResult`. The two optional arguments mirror the CLI's `--someip-port` / `--someip-tlv-port`. |
| `DecodeResult.tables` | `dict[str, Table]` — all 24 declared tables |
| `DecodeResult.non_empty` | `dict[str, Table]` — only those with rows |
| `DecodeResult.table_names`, `len(r)`, `r["eth"]`, `"eth" in r`, `r.total_rows` | the rest of the surface |
| `Table.name`, `Table.num_rows`, `len(t)` | |
| `Table.__arrow_c_stream__()` | the Arrow PyCapsule protocol — what `pa.table(t)` / `pl.from_arrow(t)` call |
| `nanom_shark.table_count` | 24 |

A `Table` (and any Arrow table imported from it) keeps the decoded data alive on its own, so it
stays valid after the `DecodeResult` it came from is dropped.

## Why this file is ~180 lines and contains no protocol code

There is exactly **one** bound table class, reused for all 24 tables — not one per row type.

`nanom_shark::table_set::for_each_table(f)` is a compile-time fold that calls `f(name, const
soa<Row>&)` once per declared table, with no per-table code at the call site. Arrow's C Data
Interface is a *runtime* description of schema + buffers. So the fold runs once, inside C++, at parse
time, and collapses 24 distinct C++ `Row` types into 24 runtime instances of the same type-erased
`Table` class. Registering a 25th table in `default_decoder` needs **zero** new lines in this binding
— it just appears as one more entry in `DecodeResult.tables`. (Registering a brand-new *protocol*
still requires recompiling the extension: the decoder is a compile-time type list. That is inherent
to the design, not something this binding changes.)

Two details worth knowing if you read the source:

- **A fresh Arrow stream per import.** `ArrowArrayStream::get_next()` is a stateful cursor, so
  `Table.__arrow_c_stream__()` rebuilds the stream on every call. `pa.table(t)` twice gives you the
  full table twice, not an empty second result.
- **Borrowed tables, separate keepalive.** The fold hands out `const soa<Row>&` — a sub-object of the
  shared `AllTables` aggregate, not something individually owned. `nanom_arrow.hpp`'s
  `export_stream(const soa<T>&, shared_ptr<const void> keepalive, ArrowArrayStream*)` overload takes
  ownership separately (the `shared_ptr<AllTables>`), so no `const_cast` or aliasing-`shared_ptr`
  trick is needed. `table_set` holds fixed table slots, so each sub-object's address is stable for
  the aggregate's whole lifetime.

## Tests

`test_nanom_shark.py` runs three sections, all plain asserts (no pytest):

- **gPTP** — the exact assertions the retired `bindings/python/gptp/` binding used to make (row
  counts, 48-bit timestamp reconstruction, nested `requesting_port_identity.*`, both TLV kinds,
  PATH_TRACE join integrity), re-pointed at nanom_shark's `gptp_*` tables and driven by the same
  `build_fixture.py` capture.
- **Golden cross-check** — decodes `SRL_front_left_51_short.pcapng` and checks every table against
  values derived from nanom_shark's own native decode pass. Pass `--ndjson <path>` (from
  `nanom_shark_cli <capture> --json <path>`) to re-derive those constants live and prove they have
  not drifted.
- **Stream freshness / lifetime** — double import, all 24 tables imported twice, and a table
  outliving the `DecodeResult` that produced it.
