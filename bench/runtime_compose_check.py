#!/usr/bin/env python3
"""Runtime-composed parsing: nanom nm::dyn vs nanom static vs Rust nom 8, verified-equal output.

Generates spec-conforming data (runtime_compose_gen.py), runs every given parser over it, ASSERTS
they all report the same message count and hash, then prints their timings. Used as a ctest
(small message count) and by hand for real numbers (see docs/RUNTIME_COMPOSE.md).

usage: runtime_compose_check.py --dyn EXE [--static EXE] [--rust EXE] [--messages N] [--reps R]
                                [--spec FILE] [--data FILE]
"""
import argparse
import pathlib
import re
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
LINE = re.compile(r"msgs=(\d+) hash=([0-9a-f]{16})\s+([0-9.]+) ns/msg")


def run(label, exe, spec, data, reps):
    out = subprocess.run([exe, str(spec), str(data), str(reps)], capture_output=True, text=True)
    m = LINE.search(out.stdout)
    if out.returncode != 0 or not m:
        sys.exit(f"{label}: failed (exit {out.returncode})\n{out.stdout}{out.stderr}")
    return int(m.group(1)), m.group(2), float(m.group(3))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dyn", required=True)
    ap.add_argument("--static")
    ap.add_argument("--rust")
    ap.add_argument("--messages", type=int, default=1_000_000)
    ap.add_argument("--reps", type=int, default=7)
    ap.add_argument("--spec", default=str(HERE / "runtime_compose_spec.txt"))
    ap.add_argument("--data", help="reuse/write the data file here instead of a temp dir")
    a = ap.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        data = pathlib.Path(a.data) if a.data else pathlib.Path(tmp) / "data.bin"
        if not data.exists():
            subprocess.run([sys.executable, str(HERE / "runtime_compose_gen.py"), a.spec, str(data),
                            str(a.messages)], check=True, stdout=subprocess.DEVNULL)
        rows = [("nanom nm::dyn (runtime)", a.dyn)]
        if a.static:
            rows.append(("nanom static (build time)", a.static))
        if a.rust:
            rows.append(("Rust nom 8 Rc<dyn Fn> (runtime)", a.rust))
        results = [(label, *run(label, exe, a.spec, data, a.reps)) for label, exe in rows]

    ref = results[0]
    for label, n, h, _ in results:
        if (n, h) != (ref[1], ref[2]):
            sys.exit(f"MISMATCH: {label} msgs={n} hash={h} vs {ref[0]} msgs={ref[1]} hash={ref[2]}")
    print(f"all {len(results)} parsers agree: msgs={ref[1]} hash={ref[2]}")
    for label, _, _, ns in results:
        print(f"  {label:34s} {ns:8.1f} ns/msg")


if __name__ == "__main__":
    main()
