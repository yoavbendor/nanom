#!/usr/bin/env python3
"""Correctness suite for the gPTP example: exact per-kind row counts and known field values against
build_fixture.py's synthetic capture, whose exact bytes (and therefore correct answers) we control.

Plain assert-based script — no pytest dependency, consistent with the rest of bindings/python/.

    python test_gptp.py
"""
import sys

import nanom_gptp
import pyarrow as pa
import pyarrow.compute as pc

from build_fixture import build_fixture

FAILS = 0


def check(name, cond):
    global FAILS
    status = "ok" if cond else "FAIL"
    if not cond:
        FAILS += 1
    print(f"  [{status}] {name}")


def main():
    data, exp = build_fixture()
    msgs = nanom_gptp.parse(data)

    tables = {
        "sync": msgs.sync, "follow_up": msgs.follow_up, "delay_req": msgs.delay_req,
        "delay_resp": msgs.delay_resp, "pdelay_req": msgs.pdelay_req, "pdelay_resp": msgs.pdelay_resp,
        "pdelay_resp_follow_up": msgs.pdelay_resp_follow_up, "announce": msgs.announce,
        "path_trace": msgs.path_trace,
    }
    arrow = {name: pa.table(t) for name, t in tables.items()}

    print("zero-copy validation (pa.table(...).validate(full=True)):")
    for name, tbl in arrow.items():
        try:
            tbl.validate(full=True)
            check(f"{name}: validate(full=True)", True)
        except Exception as e:  # noqa: BLE001
            check(f"{name}: validate(full=True) -> {e}", False)

    print("\nper-kind row counts (each of the 8 message kinds appears exactly once, "
          "except Announce which appears twice by construction):")
    for kind in ("sync", "follow_up", "delay_req", "delay_resp", "pdelay_req", "pdelay_resp",
                 "pdelay_resp_follow_up"):
        check(f"{kind}: 1 row", arrow[kind].num_rows == 1)
    check("announce: 2 rows", arrow["announce"].num_rows == exp["announce_count"] == 2)
    check("path_trace: 3 rows (one per PATH_TRACE clockIdentity entry)",
          arrow["path_trace"].num_rows == len(exp["path_trace_entries"]) == 3)

    print("\nfield-level checks (the parts that could actually break: 48-bit timestamp reconstruction, "
          "nested PortIdentity flattening, both TLV kinds, message ordering):")

    def col(tbl, name, i=0):
        return tbl[name][i].as_py()

    for kind in ("sync", "delay_req", "pdelay_req"):
        tbl, e = arrow[kind], exp[kind]
        check(f"{kind}: sequence_id", col(tbl, "common.sequence_id") == e["sequence_id"])
        check(f"{kind}: origin_timestamp_seconds (48-bit)",
              col(tbl, "origin_timestamp_seconds") == e["seconds"])
        check(f"{kind}: origin_timestamp_nanoseconds", col(tbl, "origin_timestamp_nanoseconds") == e["nanoseconds"])

    for kind, ts_field in (("pdelay_resp", "request_receipt_timestamp"),
                           ("delay_resp", "receive_timestamp"),
                           ("pdelay_resp_follow_up", "response_origin_timestamp")):
        tbl, e = arrow[kind], exp[kind]
        check(f"{kind}: {ts_field}_seconds", col(tbl, f"{ts_field}_seconds") == e["seconds"])
        check(f"{kind}: requesting_port_identity.clock_identity (nested)",
              col(tbl, "requesting_port_identity.clock_identity") == e["requesting_clock_identity"])
        check(f"{kind}: requesting_port_identity.port_number (nested)",
              col(tbl, "requesting_port_identity.port_number") == e["requesting_port_number"])

    fu, e = arrow["follow_up"], exp["follow_up"]
    check("follow_up: has_follow_up_info_tlv", bool(col(fu, "has_follow_up_info_tlv")) == True)  # noqa: E712
    check("follow_up: cumulative_scaled_rate_offset",
          col(fu, "cumulative_scaled_rate_offset") == e["cumulative_scaled_rate_offset"])
    check("follow_up: gm_time_base_indicator", col(fu, "gm_time_base_indicator") == e["gm_time_base_indicator"])
    check("follow_up: scaled_last_gm_freq_change",
          col(fu, "scaled_last_gm_freq_change") == e["scaled_last_gm_freq_change"])

    an = arrow["announce"]
    check("announce: message order preserved (sequence_id [107, 108])",
          an["common.sequence_id"].to_pylist() == [exp["announce_no_tlv"]["sequence_id"],
                                                    exp["announce_with_path_trace"]["sequence_id"]])
    check("announce: has_path_trace_tlv [False, True]", an["has_path_trace_tlv"].to_pylist() == [False, True])
    check("announce: path_trace_count [0, 3]", an["path_trace_count"].to_pylist() == [0, 3])
    check("announce: grandmaster_identity (row 0, no TLV)",
          col(an, "grandmaster_identity", 0) == exp["announce_no_tlv"]["grandmaster_identity"])
    check("announce: grandmaster_identity (row 1, with TLV)",
          col(an, "grandmaster_identity", 1) == exp["announce_with_path_trace"]["grandmaster_identity"])

    pt = arrow["path_trace"]
    got_entries = [pt["clock_identity"][i].as_py() for i in range(pt.num_rows)]
    check("path_trace: entries match, in order", got_entries == list(exp["path_trace_entries"]))
    check("path_trace: entry_index is 0,1,2", pt["entry_index"].to_pylist() == [0, 1, 2])
    check("path_trace: all 3 entries join to the same Announce message",
          len(set(pt["msg_index"].to_pylist())) == 1)

    print(f"\n{'ALL CHECKS PASSED' if FAILS == 0 else f'{FAILS} CHECK(S) FAILED'}")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
