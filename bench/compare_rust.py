#!/usr/bin/env python3
"""Streaming-pcapng benchmark: nanom vs stable Rust nom, with a verified-equal-output gate.

Runs parsers over the SAME pcapng file through a bounded refilling buffer (streaming,
never the whole file resident), each emitting the aggregate (packets, Sigma caplen,
Sigma origlen, opts, fnv1a checksum).

nanom safety profiles (see docs/BENCH_RUST_NOM.md):
  minimal — opt-out baseline: NANOM_GENERATION=0, NANOM_GUARD_VIEWS=0
  full    — safety-first (CI default): NANOM_GENERATION=1, NANOM_GUARD_VIEWS=1,
            wire_arena on the refill buffer

It first ASSERTS all engines produced the identical aggregate, then prints timings.

usage: compare_rust.py [--iters N] [--file PATH] [--build]
                       [--safety minimal|full|both] [--max-overhead RATIO]
"""
import argparse
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
RUST = ROOT / "bench" / "rust_nom"
DEFAULT_FIX = ROOT / "examples" / "nanotins_parity" / "testdata" / "SRL_front_left_51_short.pcapng"

RESULT_RE = re.compile(r"RESULT (.+)")

SAFETY_PROFILES = {
    "minimal": {
        "defines": [
            "-DNANOM_GENERATION=0",
            "-DNANOM_GUARD_VIEWS=0",
            '-DNANOM_SAFETY_PROFILE="minimal"',
        ],
        "desc": "opt-out baseline (no generation, no view guards)",
    },
    "full": {
        "defines": [
            "-DNANOM_GENERATION=1",
            "-DNANOM_GUARD_VIEWS=1",
            '-DNANOM_SAFETY_PROFILE="full"',
        ],
        "desc": "safety-first: generation + view guards + wire_arena",
    },
}


def sh(cmd, **kw):
    return subprocess.run(cmd, check=True, text=True, capture_output=True, **kw)


def nm_bin(profile: str) -> pathlib.Path:
    return pathlib.Path(f"/tmp/nanom_streaming_bench_{profile}")


def build_nanom(profile: str, cxx: str = "g++-13") -> None:
    cfg = SAFETY_PROFILES[profile]
    out = nm_bin(profile)
    out.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        cxx,
        "-std=c++23",
        "-O3",
        "-march=native",
        "-DNDEBUG",
        *cfg["defines"],
        "-I",
        str(ROOT / "include"),
        "-I",
        str(ROOT / "examples" / "nanotins_parity"),
        str(ROOT / "bench" / "streaming_pcapng_bench.cpp"),
        "-o",
        str(out),
    ]
    sh(cmd)
    print(f"built nanom [{profile}]: {' '.join(cmd)}", file=sys.stderr)


def build_rust() -> None:
    sh(["cargo", "build", "--release"], cwd=RUST)


def build(profiles: list[str], cxx: str = "g++-13") -> None:
    for p in profiles:
        build_nanom(p, cxx=cxx)
    build_rust()


def parse_result(line: str) -> dict:
    m = RESULT_RE.search(line)
    if not m:
        raise SystemExit(f"no RESULT line in:\n{line}")
    out = {}
    for kv in m.group(1).split():
        k, v = kv.split("=", 1)
        out[k] = v.strip('"')
    return out


def run(cmd) -> dict:
    return parse_result(sh(cmd).stdout)


def lock_versions() -> dict:
    text = (RUST / "Cargo.lock").read_text()
    vers = {}
    for name in ("nom", "pcap-parser"):
        m = re.search(rf'name = "{re.escape(name)}"\nversion = "([^"]+)"', text)
        vers[name] = m.group(1) if m else "?"
    return vers


def verify_equal(results: dict, keys: tuple[str, ...]) -> dict:
    ref = {k: results[next(iter(results))][k] for k in keys}
    for eng, r in results.items():
        got = {k: r[k] for k in keys}
        if got != ref:
            print(f"MISMATCH: {eng} parsed differently: {got} != {ref}", file=sys.stderr)
            raise SystemExit(1)
    return ref


def print_table(fname: str, iters: int, vers: dict, rows: list[tuple[str, str, dict]]) -> None:
    ref = rows[0][2]
    print(
        f"file: {fname} ({int(ref['file_bytes'])} bytes, {ref['packets']} packets), "
        f"iters={iters}, best-of-5; nom {vers['nom']}, pcap-parser {vers['pcap-parser']}\n"
    )
    print("| parser | work | ns/packet | throughput | output |")
    print("|---|---|---:|---:|---|")
    for label, work, r in rows:
        print(
            f"| {label} | {work} | {float(r['ns_per_pkt']):.0f} | "
            f"{float(r['mbps']) / 1024:.1f} GiB/s | identical |"
        )


def main(argv) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=5000)
    ap.add_argument("--file", default=str(DEFAULT_FIX))
    ap.add_argument("--build", action="store_true", help="build the C++ + Rust binaries first")
    ap.add_argument(
        "--safety",
        choices=("minimal", "full", "both"),
        default="both",
        help="nanom safety profile(s) to benchmark (default: both)",
    )
    ap.add_argument(
        "--max-overhead",
        type=float,
        default=None,
        metavar="RATIO",
        help="fail if full/minimal ns_per_pkt ratio exceeds RATIO (implies --safety both)",
    )
    ap.add_argument("--cxx", default="g++-13")
    a = ap.parse_args(argv[1:])

    if a.max_overhead is not None and a.safety != "both":
        print("--max-overhead requires --safety both", file=sys.stderr)
        return 2

    profiles = ["minimal", "full"] if a.safety == "both" else [a.safety]
    rust_bin = RUST / "target" / "release" / "rust_nom_bench"

    need_build = a.build or not rust_bin.exists()
    for p in profiles:
        if not nm_bin(p).exists():
            need_build = True
    if need_build:
        build(profiles, cxx=a.cxx)

    fx = str(a.file)
    it = str(a.iters)
    keys = ("packets", "sum_caplen", "sum_origlen", "opts", "checksum")

    nanom_results = {p: run([str(nm_bin(p)), fx, it]) for p in profiles}
    rust_results = {
        "rust-nom-min": run([str(rust_bin), fx, it, "min"]),
        "rust-pcap-parser": run([str(rust_bin), fx, it, "full"]),
    }

    all_results = {**{f"nanom-{p}": r for p, r in nanom_results.items()}, **rust_results}
    ref = verify_equal(all_results, keys)
    print(
        f"verified: all parsers agree — packets={ref['packets']} opts={ref['opts']} "
        f"sum_caplen={ref['sum_caplen']} checksum={ref['checksum']}\n",
        file=sys.stderr,
    )

    vers = lock_versions()
    fname = pathlib.Path(fx).name

    rows = []
    for p in profiles:
        desc = SAFETY_PROFILES[p]["desc"]
        rows.append((f"**nanom** (`{p}`)", desc, nanom_results[p]))
    rows.append(
        (
            "**Rust nom** (hand-written)",
            "EPB fields + all options (equal work)",
            rust_results["rust-nom-min"],
        )
    )
    rows.append(
        (
            "Rust `pcap-parser` lib",
            "same, + allocates options",
            rust_results["rust-pcap-parser"],
        )
    )
    print_table(fname, a.iters, vers, rows)

    nm_min = nanom_results.get("minimal") or nanom_results[profiles[0]]
    rnm = rust_results["rust-nom-min"]
    ratio = float(rnm["ns_per_pkt"]) / float(nm_min["ns_per_pkt"])
    print(
        f"\nEqual-work head-to-head (minimal nanom): **nanom {float(nm_min['ns_per_pkt']):.0f} ns/pkt vs "
        f"Rust nom {float(rnm['ns_per_pkt']):.0f} ns/pkt** (~{ratio:.2f}x — parity)."
    )

    if "full" in nanom_results and "minimal" in nanom_results:
        nm_full = nanom_results["full"]
        overhead = float(nm_full["ns_per_pkt"]) / float(nm_min["ns_per_pkt"])
        delta = float(nm_full["ns_per_pkt"]) - float(nm_min["ns_per_pkt"])
        sign = "+" if delta >= 0 else ""
        print(
            f"Full safety overhead vs minimal: **{float(nm_full['ns_per_pkt']):.0f} ns/pkt "
            f"({sign}{delta:.0f} ns/pkt, ~{overhead:.2f}x)** — "
            f"{SAFETY_PROFILES['full']['desc']}."
        )
        if a.max_overhead is not None:
            if overhead > a.max_overhead:
                print(
                    f"\nPERF BUDGET EXCEEDED: full/minimal ratio {overhead:.3f} > "
                    f"{a.max_overhead:.3f}",
                    file=sys.stderr,
                )
                return 1
            print(
                f"\nperf budget OK: full/minimal ratio {overhead:.3f} <= {a.max_overhead:.3f}",
                file=sys.stderr,
            )
    elif a.max_overhead is not None:
        print("--max-overhead requires both minimal and full profiles", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
