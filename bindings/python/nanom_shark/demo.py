#!/usr/bin/env python3
"""nanom_shark from Python — decode a capture in C++, get every table zero-copy into polars.

Build the extension first (from bindings/python/nanom_shark/):
    uv pip install '.[demo]'   # or: pip install '.[demo]'
    # or, for the fastest edit/rebuild loop:
    #   cmake -S . -B /tmp/nspybuild -DCMAKE_BUILD_TYPE=Release \
    #     -DPython_EXECUTABLE="$(which python3)" -Dnanobind_DIR="$(python3 -m nanobind --cmake_dir)"
    #   cmake --build /tmp/nspybuild -j && cp /tmp/nspybuild/nanom_shark*.so .
Then:
    python demo.py path/to/capture.pcapng
"""
import sys

import nanom_shark      # the C++ nanom_shark extension (this directory)
import polars as pl
import pyarrow as pa


def main(path: str) -> None:
    data = open(path, "rb").read()

    result = nanom_shark.parse(data)   # one C++ decode pass -> 24 columnar tables

    print(f"{nanom_shark.table_count} tables declared by default_decoder, "
          f"{len(result.non_empty)} non-empty, {result.total_rows} rows total\n")
    for name, table in result.non_empty.items():
        print(f"  {name:<12} {table.num_rows:>8} rows")

    # Every one of them imports zero-copy through the same Arrow PyCapsule protocol — no per-table
    # Python code here, and none in the C++ binding either.
    frames = {name: pl.from_arrow(pa.table(t)) for name, t in result.non_empty.items()}

    packets = frames["packets"]
    print(f"\npackets: {packets.height} rows, {packets.width} columns: {packets.columns}")
    print(packets.head(5))

    if "eth" in frames:
        print("\npackets by ethertype (a real polars query on the decoded table):")
        print(
            frames["eth"]
            .group_by("body.ethertype")
            .agg(pl.len().alias("packets"))
            .sort("packets", descending=True)
        )

    # The tables are relational: packet_id joins any protocol table back to its frame.
    if "ipv4" in frames:
        joined = frames["ipv4"].join(packets.select("packet_id", "caplen"), on="packet_id")
        print("\nipv4 joined back to its frames on packet_id — mean caplen by TTL:")
        print(
            joined.group_by("body.ttl")
            .agg(pl.len().alias("packets"), pl.col("caplen").mean().round(1).alias("mean_caplen"))
            .sort("packets", descending=True)
            .head(10)
        )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: python demo.py <capture.pcapng>")
    main(sys.argv[1])
