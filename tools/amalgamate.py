#!/usr/bin/env python3
"""Amalgamate nanom's layered headers into one drop-in `nanom-single.hpp`.

The modular headers under include/nanom/ are the source of truth; this produces a *generated
convenience artifact* (for Compiler Explorer "try it" links, llms-full.txt, and single-file drop-in).
It expands the local `#include "..."` chain of nanom.hpp in dependency order, emits each header body
exactly once (guarded by the set of already-included files), and hoists every distinct `#include <...>`
system header to the top. Local include guards are dropped (the whole thing lives under one guard).

usage: python3 tools/amalgamate.py [--out nanom-single.hpp]   (default: stdout)
"""
import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
INC = ROOT / "include" / "nanom"
LOCAL_INC = re.compile(r'^\s*#\s*include\s*"([^"]+)"')
SYS_INC = re.compile(r'^\s*#\s*include\s*<([^>]+)>')
GUARD_IFNDEF = re.compile(r"^\s*#\s*ifndef\s+NANOM\w*_HPP_INCLUDED\s*$")
GUARD_DEFINE = re.compile(r"^\s*#\s*define\s+NANOM\w*_HPP_INCLUDED\s*$")
COND_OPEN = re.compile(r"^\s*#\s*(if|ifdef|ifndef)\b")
COND_CLOSE = re.compile(r"^\s*#\s*endif\b")


def expand(path: pathlib.Path, seen: set, sys_headers: list, out: list):
    """Emit `path`'s body, recursively inlining local includes, once per file."""
    key = path.name
    if key in seen:
        return
    seen.add(key)
    lines = path.read_text().splitlines()
    # find the file's own include-guard #ifndef/#define pair (first two guard lines) + trailing #endif
    guard_line = None
    for i, ln in enumerate(lines):
        if GUARD_IFNDEF.match(ln) and i + 1 < len(lines) and GUARD_DEFINE.match(lines[i + 1]):
            guard_line = i
            break
    endif_idx = None
    if guard_line is not None:
        for j in range(len(lines) - 1, guard_line, -1):
            if re.match(r"^\s*#\s*endif\b", lines[j]):
                endif_idx = j
                break

    depth = 0  # preprocessor-conditional nesting (the file's own guard is stripped, so not counted)
    for i, ln in enumerate(lines):
        if guard_line is not None and (i == guard_line or i == guard_line + 1 or i == endif_idx):
            continue  # strip the per-file guard (#ifndef / #define / matching #endif)
        m = LOCAL_INC.match(ln)
        if m:
            expand((path.parent / m.group(1)).resolve(), seen, sys_headers, out)
            continue
        s = SYS_INC.match(ln)
        if s:
            if depth == 0:
                if s.group(1) not in sys_headers:
                    sys_headers.append(s.group(1))
                continue  # unconditional include -> hoisted to the top; drop here
            out.append(ln)  # conditional include (e.g. #if __has_include(<meta>)) -> keep in place
            continue
        if COND_OPEN.match(ln):
            depth += 1
        elif COND_CLOSE.match(ln):
            depth = max(0, depth - 1)
        out.append(ln)


def main(argv) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="-")
    a = ap.parse_args(argv[1:])

    seen: set = set()
    sys_headers: list = []
    body: list = []
    expand(INC / "nanom.hpp", seen, sys_headers, body)

    banner = [
        "// ============================================================================",
        "// nanom-single.hpp — GENERATED single-file amalgamation of the nanom headers.",
        "// Do NOT edit: the source of truth is include/nanom/*.hpp; regenerate with",
        "//   python3 tools/amalgamate.py --out nanom-single.hpp",
        "// Provided as a drop-in / Compiler-Explorer convenience. https://github.com/yoavbendor/nanom",
        "// SPDX-License-Identifier: Apache-2.0",
        "// ============================================================================",
        "#ifndef NANOM_SINGLE_HPP_INCLUDED",
        "#define NANOM_SINGLE_HPP_INCLUDED",
        "",
    ]
    sysblock = [f"#include <{h}>" for h in sys_headers]
    # collapse >1 consecutive blank lines for tidiness
    text_body = "\n".join(body)
    text_body = re.sub(r"\n{3,}", "\n\n", text_body)
    result = "\n".join(banner + sysblock + ["", text_body, "", "#endif  // NANOM_SINGLE_HPP_INCLUDED", ""])

    if a.out == "-":
        sys.stdout.write(result)
    else:
        pathlib.Path(a.out).write_text(result)
        print(f"wrote {a.out}: {result.count(chr(10))} lines, {len(sys_headers)} system includes",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
