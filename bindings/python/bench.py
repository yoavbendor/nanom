#!/usr/bin/env python3
"""Benchmark: parsing a pcapng into a columnar Arrow table — nanom (C++, zero-copy) vs pure-Python.

Every engine produces the SAME table (caplen, ethertype, eth_dst, eth_src per packet); the harness
asserts identical (packets, sum(caplen)) before timing, so it's apples-to-apples. It is honestly a
C++-vs-Python comparison — which is exactly the point: nanom lets a Python dev get C++ parse speed for
their own binary format and land straight in Arrow/polars.

    pip install .            # build nanom_pcap first (see README)
    python bench.py [capture.pcapng]
"""
import io
import sys
import time

import nanom_pcap
import pyarrow as pa
import pyarrow.compute as pc

DEFAULT = "../../examples/nanotins_parity/testdata/SRL_front_left_51_short.pcapng"


def _table(caps, ets, dst, src):
    return pa.table({
        "caplen": pa.array(caps, pa.uint32()), "ethertype": pa.array(ets, pa.uint16()),
        "eth_dst": pa.array(dst, pa.binary(6)), "eth_src": pa.array(src, pa.binary(6)),
    })


def run_nanom(d):
    return pa.table(nanom_pcap.parse(d))


def run_dpkt(d):
    import dpkt
    caps, ets, dst, src = [], [], [], []
    for _ts, buf in dpkt.pcapng.Reader(io.BytesIO(d)):
        caps.append(len(buf))
        if len(buf) >= 14:
            dst.append(buf[0:6]); src.append(buf[6:12]); ets.append((buf[12] << 8) | buf[13])
        else:
            dst.append(b"\0" * 6); src.append(b"\0" * 6); ets.append(0)
    return _table(caps, ets, dst, src)


def run_pcapng(d):
    from pcapng import FileScanner
    caps, ets, dst, src = [], [], [], []
    for blk in FileScanner(io.BytesIO(d)):
        if type(blk).__name__ == "EnhancedPacket":
            buf = blk.packet_data
            caps.append(len(buf))
            if len(buf) >= 14:
                dst.append(buf[0:6]); src.append(buf[6:12]); ets.append((buf[12] << 8) | buf[13])
            else:
                dst.append(b"\0" * 6); src.append(b"\0" * 6); ets.append(0)
    return _table(caps, ets, dst, src)


def run_scapy(d):
    from scapy.all import rdpcap  # optional; heavy and may be unavailable
    caps, ets, dst, src = [], [], [], []
    for p in rdpcap(io.BytesIO(d)):
        raw = bytes(p)
        caps.append(len(raw))
        if len(raw) >= 14:
            dst.append(raw[0:6]); src.append(raw[6:12]); ets.append((raw[12] << 8) | raw[13])
        else:
            dst.append(b"\0" * 6); src.append(b"\0" * 6); ets.append(0)
    return _table(caps, ets, dst, src)


ENGINES = [
    ("nanom (C++ + zero-copy Arrow)", run_nanom, 300),
    ("dpkt (pure Python)", run_dpkt, 80),
    ("python-pcapng (pure Python)", run_pcapng, 40),
    ("scapy (rdpcap)", run_scapy, 10),
]


def agg(tbl):
    return tbl.num_rows, pc.sum(tbl["caplen"]).as_py()


def main(path):
    data = open(path, "rb").read()
    ref = agg(run_nanom(data))

    available = []
    print("verifying equal output (packets, sum_caplen)...")
    for name, fn, reps in ENGINES:
        try:
            got = agg(fn(data))
        except BaseException as e:  # noqa: BLE001 — optional deps may be missing or a native
            print(f"  {name:34s} skipped ({type(e).__name__})")  # ext (e.g. scapy/pyo3) may panic
            continue
        assert got == ref, f"{name}: {got} != {ref}"
        print(f"  {name:34s} rows={got[0]} sum_caplen={got[1]}  OK")
        available.append((name, fn, reps))
    print(f"all agree: {ref[0]} packets, sum_caplen={ref[1]}\n")

    print(f"{'parser':34s} {'ms/run':>9} {'pkts/sec':>13} {'ns/pkt':>9} {'slowdown':>9}")
    base = None
    for name, fn, reps in available:
        fn(data)  # warm up
        best = min((lambda s: (fn(data), time.perf_counter() - s)[1])(time.perf_counter())
                   for _ in range(reps))
        base = base or best
        print(f"{name:34s} {best * 1e3:9.3f} {ref[0] / best:13,.0f} "
              f"{best / ref[0] * 1e9:9.0f} {best / base:8.1f}x")
    print("\nSame output, best-of-N on one machine. nanom parses in C++ and lands zero-copy in Arrow; "
          "the Python parsers build the columns in a Python loop — that gap is the pitch.")


if __name__ == "__main__":
    import pathlib
    p = sys.argv[1] if len(sys.argv) > 1 else str(pathlib.Path(__file__).parent / DEFAULT)
    main(p)
