#!/usr/bin/env python3
"""nanom from Python — parse a pcapng in C++ (nanom), get a zero-copy Arrow table into polars.

Build the extension first (from bindings/python/):
    pip install .            # or: cmake -S . -B build && cmake --build build && export PYTHONPATH=build
Then:
    python demo.py path/to/capture.pcapng
"""
import sys

import nanom_pcap        # the C++ nanom extension (this directory)
import pyarrow as pa
import polars as pl


def main(path: str) -> None:
    data = open(path, "rb").read()

    table = nanom_pcap.parse(data)   # C++ nanom parse -> soa<pkt_row>  (fast, columnar)
    tbl = pa.table(table)            # zero-copy import via the Arrow PyCapsule protocol
    tbl.validate(full=True)
    df = pl.from_arrow(tbl)          # zero-copy into a polars DataFrame

    print(f"{df.height} packets, {df.width} columns: {df.columns}\n")
    print(df.head(5))

    print("\nmean captured length by ethertype (a real polars query on the parsed table):")
    print(
        df.group_by("ethertype")
        .agg(pl.len().alias("packets"), pl.col("caplen").mean().round(1).alias("mean_caplen"))
        .sort("packets", descending=True)
    )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: python demo.py <capture.pcapng>")
    main(sys.argv[1])
