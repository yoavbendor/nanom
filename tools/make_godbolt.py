#!/usr/bin/env python3
"""Build a self-contained Compiler Explorer session for the nanom tour, and mint a one-click permalink.

The reader shouldn't have to assemble anything: this inlines the generated single-file header
(tools/amalgamate.py) and the try/godbolt.cpp tour into ONE editor pane, writes it to a paste-ready
file, and — if godbolt.org is reachable — POSTs it to Compiler Explorer's shortener API and prints the
permanent https://godbolt.org/z/... link to drop into the README's "Try it" line.

Everything except the final POST is offline: the combined source is always written, so if the network
is blocked (e.g. a CI sandbox) you still get a single file to paste into https://godbolt.org by hand.

usage: python3 tools/make_godbolt.py [--compiler g142] [--std c++23] [--out try/godbolt_tour.cpp]
       (compiler ids come from https://godbolt.org/api/compilers/c++ ; g142 = GCC 14.2)
"""
import argparse
import json
import pathlib
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
SHORTENER = "https://godbolt.org/api/shortener"


def build_source() -> str:
    """Amalgamated header + the tour with its local include stripped = one self-contained TU."""
    single = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "amalgamate.py")],
        check=True, capture_output=True, text=True).stdout
    tour_lines = (ROOT / "try" / "godbolt.cpp").read_text().splitlines()
    tour = "\n".join(ln for ln in tour_lines if ln.strip() != '#include "nanom-single.hpp"')
    return (single.rstrip() + "\n\n"
            "// ---- try/godbolt.cpp (the 60-second tour) --------------------------------------------\n"
            + tour.lstrip() + "\n")


def clientstate(source: str, compiler: str, std: str) -> dict:
    """Minimal Compiler Explorer clientstate: one compile pane + one execution pane."""
    opts = f"-std={std} -O2"
    comp = {"id": compiler, "options": opts, "libs": [], "tools": []}
    return {"sessions": [{
        "id": 1, "language": "c++", "source": source,
        "compilers": [comp],
        "executors": [{"compiler": {"id": compiler, "options": opts}, "arguments": "", "stdin": ""}],
    }]}


def shorten(state: dict) -> str:
    req = urllib.request.Request(
        SHORTENER, data=json.dumps(state).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 (fixed, trusted host)
        return json.load(r)["url"]


def main(argv) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--compiler", default="g142", help="godbolt compiler id (default g142 = GCC 14.2)")
    ap.add_argument("--std", default="c++23")
    ap.add_argument("--out", default=str(ROOT / "try" / "godbolt_tour.cpp"))
    a = ap.parse_args(argv[1:])

    source = build_source()
    out = pathlib.Path(a.out)
    out.write_text(source)
    print(f"wrote paste-ready single-file tour: {a.out} ({len(source):,} bytes)", file=sys.stderr)

    try:
        url = shorten(clientstate(source, a.compiler, a.std))
    except (urllib.error.URLError, OSError, KeyError, TimeoutError) as e:
        print(f"\ncould not reach the Compiler Explorer shortener ({e}).", file=sys.stderr)
        print("Open https://godbolt.org, paste the file above, set the compiler to a C++23 gcc/clang "
              f"with `-std={a.std}`, add an execution pane, then Share -> Short Link.", file=sys.stderr)
        return 0

    print(url)  # stdout: the permalink, ready to paste into the README's "Try it" line
    print(f"\none-click permalink minted — put it in README.md:\n  [Try it live in Compiler Explorer]({url})",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
