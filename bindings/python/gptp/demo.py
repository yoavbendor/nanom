#!/usr/bin/env python3
"""nanom_gptp demo — a full gPTP (IEEE 802.1AS) capture, parsed in C++, landing in 9 zero-copy Arrow
tables (one per message kind, plus one for Announce's PATH_TRACE entries), analyzed with polars.

Build the extension first (from this directory):
    pip install .            # or: cmake -S . -B build && cmake --build build && export PYTHONPATH=build
Then:
    python demo.py            # uses the synthetic fixture from build_fixture.py
"""
import nanom_gptp
import polars as pl
import pyarrow as pa

from build_fixture import build_fixture


def main() -> None:
    data, _expected = build_fixture()
    msgs = nanom_gptp.parse(data)  # C++ nanom parse: dispatch 8 message kinds -> 9 soa<T> tables

    tables = {
        "Sync": msgs.sync,
        "Follow_Up": msgs.follow_up,
        "Delay_Req": msgs.delay_req,
        "Delay_Resp": msgs.delay_resp,
        "Pdelay_Req": msgs.pdelay_req,
        "Pdelay_Resp": msgs.pdelay_resp,
        "Pdelay_Resp_Follow_Up": msgs.pdelay_resp_follow_up,
        "Announce": msgs.announce,
        "PathTraceEntry": msgs.path_trace,
    }

    print("message kind          rows")
    print("-" * 26)
    frames = {}
    for name, view in tables.items():
        df = pl.from_arrow(pa.table(view))  # zero-copy both hops: soa<T> -> Arrow -> polars
        frames[name] = df
        print(f"{name:<22} {df.height:>4}")

    print("\nSync/Follow_Up timestamps (seconds reconstructed from the 48-bit wire field):")
    print(pl.concat([
        frames["Sync"].select(pl.lit("Sync").alias("kind"), "common.sequence_id",
                              "origin_timestamp_seconds", "origin_timestamp_nanoseconds"),
        frames["Follow_Up"].select(pl.lit("Follow_Up").alias("kind"), "common.sequence_id",
                                   pl.col("precise_origin_timestamp_seconds").alias("origin_timestamp_seconds"),
                                   pl.col("precise_origin_timestamp_nanoseconds").alias("origin_timestamp_nanoseconds")),
    ]))

    print("\nAnnounce messages (grandmaster info + whether a PATH_TRACE TLV was present):")
    print(frames["Announce"].select(
        "common.sequence_id", "grandmaster_identity", "grandmaster_priority1",
        "has_path_trace_tlv", "path_trace_count"))

    print("\nPATH_TRACE entries (joined back to their Announce message via msg_index):")
    joined = frames["PathTraceEntry"].join(
        frames["Announce"].select(pl.col("common.msg_index").alias("msg_index"), "common.sequence_id"),
        on="msg_index", how="left")
    print(joined.select("common.sequence_id", "entry_index", "clock_identity"))

    print("\nRequesting clockIdentity across all E2E/P2P response kinds (nested-struct flattening in "
          "action — 'requesting_port_identity.clock_identity' is a real dotted Arrow column name):")
    for kind in ("Delay_Resp", "Pdelay_Resp", "Pdelay_Resp_Follow_Up"):
        print(f"  {kind:24s}", frames[kind].select(
            "requesting_port_identity.clock_identity", "requesting_port_identity.port_number").row(0))


if __name__ == "__main__":
    main()
