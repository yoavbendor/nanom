#!/usr/bin/env python3
"""Correctness suite for the nanom_shark Python binding.

Three independent sections, all plain assert-based (no pytest dependency, consistent with the rest
of bindings/python/):

  A. gPTP — the EXACT assertions bindings/python/gptp/test_gptp.py used to make against the
     hand-rolled `nanom_gptp` extension, re-pointed at nanom_shark's own `gptp_*` tables and driven
     by the same build_fixture.py capture. This is the regression proof that retiring
     bindings/python/gptp/ loses no coverage.
  B. Golden cross-check — decode examples/nanotins_parity/testdata/SRL_front_left_51_short.pcapng
     and compare every table against nanom_shark's OWN native decode pass. The constants in GOLDEN
     were derived from `nanom_shark_cli <that file> --json out.ndjson`; pass --ndjson <path> to
     re-derive them live from a freshly generated NDJSON and prove the constants have not drifted.
  C. Stream freshness — importing the same table twice must yield the full table twice
     (ArrowArrayStream.get_next() is a stateful cursor, so the stream has to be rebuilt per call).
  D. Options plumbing — the someip_ports / someip_tlv_ports kwargs actually reach DecodeOptions and
     change what gets decoded; malformed input raises rather than crashing.

    python test_nanom_shark.py [--ndjson /path/to/golden.ndjson]
"""
import json
import pathlib
import sys

import nanom_shark
import pyarrow as pa

from build_fixture import build_fixture

FAILS = 0
REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
SRL_PCAPNG = REPO_ROOT / "examples/nanotins_parity/testdata/SRL_front_left_51_short.pcapng"


def check(name, cond):
    global FAILS
    status = "ok" if cond else "FAIL"
    if not cond:
        FAILS += 1
    print(f"  [{status}] {name}")


def col(tbl, name, i=0):
    return tbl[name][i].as_py()


# ---------------------------------------------------------------------------------------------
# A. gPTP: test_gptp.py's assertions, ported onto nanom_shark's gptp_* tables
# ---------------------------------------------------------------------------------------------
def section_gptp():
    print("=== A. gPTP correctness (ported from bindings/python/gptp/test_gptp.py) ===")
    data, exp = build_fixture()
    result = nanom_shark.parse(data)

    # The old binding exposed msgs.sync/.follow_up/...; nanom_shark declares the same nine tables
    # under gptp_* names, reached generically through the one type-erased handle class.
    tables = {kind: result[f"gptp_{kind}"] for kind in
              ("sync", "follow_up", "delay_req", "delay_resp", "pdelay_req", "pdelay_resp",
               "pdelay_resp_follow_up", "announce", "path_trace")}
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

    print("\nfield-level checks (the parts that could actually break: 48-bit timestamp "
          "reconstruction, nested PortIdentity flattening, both TLV kinds, message ordering):")
    for kind in ("sync", "delay_req", "pdelay_req"):
        tbl, e = arrow[kind], exp[kind]
        check(f"{kind}: sequence_id", col(tbl, "common.sequence_id") == e["sequence_id"])
        check(f"{kind}: origin_timestamp_seconds (48-bit)",
              col(tbl, "origin_timestamp_seconds") == e["seconds"])
        check(f"{kind}: origin_timestamp_nanoseconds",
              col(tbl, "origin_timestamp_nanoseconds") == e["nanoseconds"])

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
    check("follow_up: has_follow_up_info_tlv", bool(col(fu, "has_follow_up_info_tlv")) is True)
    check("follow_up: cumulative_scaled_rate_offset",
          col(fu, "cumulative_scaled_rate_offset") == e["cumulative_scaled_rate_offset"])
    check("follow_up: gm_time_base_indicator",
          col(fu, "gm_time_base_indicator") == e["gm_time_base_indicator"])
    check("follow_up: scaled_last_gm_freq_change",
          col(fu, "scaled_last_gm_freq_change") == e["scaled_last_gm_freq_change"])
    # nanom_shark names Follow_Up's timestamp preciseOriginTimestamp (per 802.1AS) where the old
    # fork called it origin_timestamp — same 48-bit reconstruction, checked here too.
    check("follow_up: precise_origin_timestamp_seconds (48-bit)",
          col(fu, "precise_origin_timestamp_seconds") == e["seconds"])

    an = arrow["announce"]
    check("announce: message order preserved (sequence_id [107, 108])",
          an["common.sequence_id"].to_pylist() == [exp["announce_no_tlv"]["sequence_id"],
                                                   exp["announce_with_path_trace"]["sequence_id"]])
    check("announce: has_path_trace_tlv [False, True]",
          [bool(x) for x in an["has_path_trace_tlv"].to_pylist()] == [False, True])
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

    # Beyond the old fork's reach: nanom_shark decodes the FULL frame, so the gPTP messages also
    # show up in the L2 tables. This is the "strict superset" claim, asserted rather than assumed.
    check("packets: 9 rows (one per gPTP frame) — full L2 decode, which the gptp fork never did",
          len(result["packets"]) == exp["message_count"] == 9)
    eth = pa.table(result["eth"])
    check("eth: 9 rows, all ethertype 0x88F7",
          eth.num_rows == 9 and set(eth["body.ethertype"].to_pylist()) == {0x88F7})


# ---------------------------------------------------------------------------------------------
# B. Golden cross-check against nanom_shark's own native decode pass
# ---------------------------------------------------------------------------------------------
# Derived from:  build/nanom_shark_cli examples/nanotins_parity/testdata/SRL_front_left_51_short.pcapng
#                  --json srl.ndjson
# Run this script with --ndjson srl.ndjson to re-derive every one of these live and prove they still
# match the native pass exactly (see golden_from_ndjson below).
GOLDEN = {
    "row_counts": {"packets": 224, "eth": 224, "vlan": 224, "ipv4": 224, "udp": 7,
                   "ipv4_frag": 224, "datagram": 7},
    "non_empty": ["packets", "eth", "vlan", "ipv4", "udp", "ipv4_frag", "datagram"],
    "packets": {"caplen_sum": 331884, "origlen_sum": 331884},
    "eth": {"dst": "01005e060601", "src": "d47c441011b0", "ethertypes": {0x8100}},
    "vlan": {"vids": {2110}, "inner_ethertypes": {0x0800}},
    "ipv4": {"total_length_sum": 327852, "checksum_sum": 6944507, "protocols": {17},
             "ttls": {255}, "ihls": {5},
             "identifications": [29826, 29827, 29828, 29829, 29830, 29831, 29833]},
    "udp": {"dst_ports": [2468] * 7, "lengths": [46196] * 7},
    "ipv4_frag": {"datagram_ids": [1, 2, 3, 4, 5, 6, 7], "frag_offset_sum": 5138560,
                  "more_fragments_count": 217, "is_first_count": 7, "is_last_count": 7},
    "datagram": {"total_lengths": [46196] * 7, "fragment_counts": [32] * 7,
                 "ip_versions": {4}, "completion_statuses": {0}},
}


def golden_from_ndjson(path):
    """Re-derive GOLDEN from the native CLI's NDJSON, so the constants above can't silently rot."""
    layers = [json.loads(line)["_source"]["layers"] for line in open(path)]
    lay = lambda k: [L[k] for L in layers if k in L]  # noqa: E731
    ip, udp, frag, reasm = lay("ip"), lay("udp"), lay("ip.fragment"), lay("ip.reassembled")
    return {
        "row_counts": {"packets": len(layers), "eth": len(lay("eth")), "vlan": len(lay("vlan")),
                       "ipv4": len(ip), "udp": len(udp), "ipv4_frag": len(frag),
                       "datagram": len(reasm)},
        "non_empty": ["packets", "eth", "vlan", "ipv4", "udp", "ipv4_frag", "datagram"],
        "packets": {"caplen_sum": sum(L["frame"]["caplen"] for L in layers),
                    "origlen_sum": sum(L["frame"]["origlen"] for L in layers)},
        "eth": {"dst": next(iter({e["dst"] for e in lay("eth")})),
                "src": next(iter({e["src"] for e in lay("eth")})),
                "ethertypes": {e["ethertype"] for e in lay("eth")}},
        "vlan": {"vids": {v["vid"] for v in lay("vlan")},
                 "inner_ethertypes": {v["inner_ethertype"] for v in lay("vlan")}},
        "ipv4": {"total_length_sum": sum(x["total_length"] for x in ip),
                 "checksum_sum": sum(x["checksum"] for x in ip),
                 "protocols": {x["protocol"] for x in ip}, "ttls": {x["ttl"] for x in ip},
                 "ihls": {x["ihl"] for x in ip},
                 "identifications": sorted({x["identification"] for x in ip})},
        "udp": {"dst_ports": [u["dst_port"] for u in udp], "lengths": [u["length"] for u in udp]},
        "ipv4_frag": {"datagram_ids": sorted({f["datagram_id"] for f in frag}),
                      "frag_offset_sum": sum(f["frag_offset_bytes"] for f in frag),
                      "more_fragments_count": sum(bool(f["more_fragments"]) for f in frag),
                      "is_first_count": sum(bool(f["is_first"]) for f in frag),
                      "is_last_count": sum(bool(f["is_last"]) for f in frag)},
        "datagram": {"total_lengths": [r["total_length"] for r in reasm],
                     "fragment_counts": [r["fragment_count"] for r in reasm],
                     "ip_versions": {4}, "completion_statuses": {r["completion_status"] for r in reasm}},
    }


def section_golden(ndjson_path=None):
    print("\n=== B. cross-check vs nanom_shark's own native decode pass "
          f"({SRL_PCAPNG.name}) ===")
    g = GOLDEN
    if ndjson_path:
        live = golden_from_ndjson(ndjson_path)
        check(f"live NDJSON ({ndjson_path}) reproduces the hardcoded GOLDEN constants exactly",
              live == GOLDEN)
        g = live

    result = nanom_shark.parse(SRL_PCAPNG.read_bytes())
    check("24 tables declared by default_decoder (a 25th needs zero new binding code)",
          len(result) == nanom_shark.table_count == 24)
    check(f"non-empty tables == {g['non_empty']}",
          sorted(result.non_empty.keys()) == sorted(g["non_empty"]))

    arrow = {name: pa.table(result[name]) for name in g["row_counts"]}
    for name, tbl in arrow.items():
        try:
            tbl.validate(full=True)
        except Exception as e:  # noqa: BLE001
            check(f"{name}: validate(full=True) -> {e}", False)
    for name, want in g["row_counts"].items():
        check(f"{name}: {want} rows", arrow[name].num_rows == want)

    p = arrow["packets"]
    check("packets: packet_id is 0..223 in order", p["packet_id"].to_pylist() == list(range(224)))
    check(f"packets: caplen sum == {g['packets']['caplen_sum']}",
          sum(p["caplen"].to_pylist()) == g["packets"]["caplen_sum"])
    check(f"packets: origlen sum == {g['packets']['origlen_sum']}",
          sum(p["origlen"].to_pylist()) == g["packets"]["origlen_sum"])

    e = arrow["eth"]
    check(f"eth: every dst == {g['eth']['dst']}",
          {x.hex() for x in e["body.dst"].to_pylist()} == {g["eth"]["dst"]})
    check(f"eth: every src == {g['eth']['src']}",
          {x.hex() for x in e["body.src"].to_pylist()} == {g["eth"]["src"]})
    check("eth: ethertypes == {0x8100} (802.1Q)",
          set(e["body.ethertype"].to_pylist()) == g["eth"]["ethertypes"])

    v = arrow["vlan"]
    check(f"vlan: vids == {g['vlan']['vids']}", set(v["body.vid"].to_pylist()) == g["vlan"]["vids"])
    check("vlan: inner_ethertypes == {0x0800} (IPv4)",
          set(v["body.inner_ethertype"].to_pylist()) == g["vlan"]["inner_ethertypes"])

    ip, gi = arrow["ipv4"], g["ipv4"]
    check(f"ipv4: total_length sum == {gi['total_length_sum']}",
          sum(ip["body.total_length"].to_pylist()) == gi["total_length_sum"])
    check(f"ipv4: checksum sum == {gi['checksum_sum']}",
          sum(ip["body.checksum"].to_pylist()) == gi["checksum_sum"])
    check(f"ipv4: protocols == {gi['protocols']} (UDP)",
          set(ip["body.protocol"].to_pylist()) == gi["protocols"])
    check(f"ipv4: ttls == {gi['ttls']}, ihls == {gi['ihls']}",
          set(ip["body.ttl"].to_pylist()) == gi["ttls"]
          and set(ip["body.ihl"].to_pylist()) == gi["ihls"])
    check(f"ipv4: identifications == {gi['identifications']}",
          sorted(set(ip["body.identification"].to_pylist())) == gi["identifications"])

    u = arrow["udp"]
    check(f"udp: dst_ports == {g['udp']['dst_ports']}",
          u["body.dst_port"].to_pylist() == g["udp"]["dst_ports"])
    check(f"udp: lengths == {g['udp']['lengths']}",
          u["body.length"].to_pylist() == g["udp"]["lengths"])
    check("udp: all 7 rows are reassembled datagrams (is_reassembled)",
          all(bool(x) for x in u["is_reassembled"].to_pylist()))

    f, gf = arrow["ipv4_frag"], g["ipv4_frag"]
    check(f"ipv4_frag: datagram_ids == {gf['datagram_ids']}",
          sorted(set(f["datagram_id"].to_pylist())) == gf["datagram_ids"])
    check(f"ipv4_frag: frag_offset_bytes sum == {gf['frag_offset_sum']}",
          sum(f["frag_offset_bytes"].to_pylist()) == gf["frag_offset_sum"])
    check(f"ipv4_frag: more_fragments count == {gf['more_fragments_count']}",
          sum(bool(x) for x in f["more_fragments"].to_pylist()) == gf["more_fragments_count"])
    check(f"ipv4_frag: is_first == {gf['is_first_count']}, is_last == {gf['is_last_count']}",
          sum(bool(x) for x in f["is_first"].to_pylist()) == gf["is_first_count"]
          and sum(bool(x) for x in f["is_last"].to_pylist()) == gf["is_last_count"])

    d, gd = arrow["datagram"], g["datagram"]
    check(f"datagram: total_lengths == {gd['total_lengths']}",
          d["total_length"].to_pylist() == gd["total_lengths"])
    check(f"datagram: fragment_counts == {gd['fragment_counts']}",
          d["fragment_count"].to_pylist() == gd["fragment_counts"])
    check("datagram: fragment_counts sum == the 224 ipv4_frag rows",
          sum(d["fragment_count"].to_pylist()) == g["row_counts"]["ipv4_frag"])
    check(f"datagram: ip_versions == {gd['ip_versions']}, completion_statuses == "
          f"{gd['completion_statuses']} (complete)",
          set(d["ip_version"].to_pylist()) == gd["ip_versions"]
          and set(d["completion_status"].to_pylist()) == gd["completion_statuses"])


# ---------------------------------------------------------------------------------------------
# C. stream freshness — the one real lifetime/statefulness risk in the type-erased design
# ---------------------------------------------------------------------------------------------
def section_double_import():
    print("\n=== C. double import / stream freshness ===")
    result = nanom_shark.parse(SRL_PCAPNG.read_bytes())
    h = result["eth"]
    t1 = pa.table(h)
    t2 = pa.table(h)
    check("eth imported twice: both have 224 rows (not an exhausted 2nd stream)",
          t1.num_rows == t2.num_rows == 224)
    check("eth imported twice: identical contents", t1.equals(t2))
    t3 = pa.table(result["eth"])  # a fresh handle object for the same underlying table
    check("eth via a freshly fetched handle: 224 rows again", t3.num_rows == 224)

    # Every table, twice, interleaved — 24 handles, 48 imports, all off the same AllTables.
    twice_ok = True
    for name in result.table_names:
        a, b = pa.table(result[name]), pa.table(result[name])
        twice_ok = twice_ok and a.num_rows == b.num_rows == len(result[name])
    check("all 24 tables imported twice each: row counts stable", twice_ok)

    # Outliving the DecodeResult: the exported batches hold the only remaining reference to
    # AllTables. If the keepalive were wrong, this is where it would read freed memory.
    held = pa.table(result["ipv4"])
    del result, h, t1, t2, t3
    import gc
    gc.collect()
    held.validate(full=True)
    check("table outlives its DecodeResult (keepalive holds AllTables): 224 rows, still valid",
          held.num_rows == 224 and sum(held["body.total_length"].to_pylist()) == 327852)

    # An empty table must still export a valid, empty Arrow table (0 chunks, schema intact).
    r2 = nanom_shark.parse(SRL_PCAPNG.read_bytes())
    empty = pa.table(r2["tcp"])
    empty.validate(full=True)
    check("an empty table (tcp) exports a valid 0-row table with a full schema",
          empty.num_rows == 0 and len(empty.schema) > 0)


# ---------------------------------------------------------------------------------------------
# D. DecodeOptions plumbing + error handling
# ---------------------------------------------------------------------------------------------
def section_options():
    print("\n=== D. options plumbing + error handling ===")
    data = SRL_PCAPNG.read_bytes()

    # This capture's reassembled datagrams are UDP port 2468 — not SOME/IP's default 30490 — so the
    # someip tables are empty by default and populated only when the port is configured. That makes
    # it a real test of the kwargs reaching DecodeOptions, not just of them being accepted.
    default = nanom_shark.parse(data)
    check("someip tables empty with default ports (30490)",
          len(default["someip"]) == 0 and len(default["someip_tlv"]) == 0)

    tuned = nanom_shark.parse(data, someip_ports=[2468])
    check("someip_ports=[2468]: someip gets the 7 reassembled datagrams",
          len(tuned["someip"]) == 7)
    check("someip_ports alone leaves someip_tlv empty (TLV is opt-in)",
          len(tuned["someip_tlv"]) == 0)

    tlv = nanom_shark.parse(data, someip_tlv_ports=[2468])
    check("someip_tlv_ports=[2468] implies someip_ports (as the CLI does): 7 someip rows",
          len(tlv["someip"]) == 7)
    check("someip_tlv_ports=[2468]: 54 TLV member rows", len(tlv["someip_tlv"]) == 54)
    check("someip TLV table imports zero-copy", pa.table(tlv["someip_tlv"]).num_rows == 54)

    for name, bad in (("garbage bytes", b"not a capture at all"),
                      ("empty input", b""),
                      ("truncated SHB", bytes.fromhex("0a0d0d0a1c000000"))):
        try:
            nanom_shark.parse(bad)
            check(f"{name}: raises", False)
        except RuntimeError as e:
            check(f"{name}: raises RuntimeError({e})", True)


def main():
    ndjson = None
    if "--ndjson" in sys.argv:
        ndjson = sys.argv[sys.argv.index("--ndjson") + 1]
    section_gptp()
    section_golden(ndjson)
    section_double_import()
    section_options()
    print(f"\n{'ALL CHECKS PASSED' if FAILS == 0 else f'{FAILS} CHECK(S) FAILED'}")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
