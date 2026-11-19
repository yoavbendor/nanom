#!/usr/bin/env python3
"""Generate messages conforming to a runtime-compose spec (bench/runtime_compose_spec.txt).

The spec grammar is the one the benchmark parsers read (see bench/runtime_compose_bench.cpp):
  u8 | u16be | u32le | u64be | str8 | lit(N) | seq(n,...) | alt(n,...) | rep(n) | tag(N:n,...)
Deterministic (seeded), so every run of the same arguments writes the same bytes.

usage: runtime_compose_gen.py <spec.txt> <out.bin> <messages> [seed]
"""
import random
import struct
import sys


def parse_spec(src):
    pos = 0

    def peek():
        return src[pos]

    def eat(s):
        nonlocal pos
        if not src.startswith(s, pos):
            raise SystemExit(f"spec: expected {s!r} at {src[pos:pos + 20]!r}")
        pos += len(s)

    def name():
        nonlocal pos
        s = pos
        while pos < len(src) and src[pos].isalnum():
            pos += 1
        return src[s:pos]

    def node():
        n = name()
        if n in ("u8", "u16be", "u32le", "u64be", "str8"):
            return (n,)
        eat("(")
        if n == "lit":
            v = int(name())
            eat(")")
            return ("lit", v)
        if n in ("seq", "alt", "rep"):
            kids = [node()]
            while peek() == ",":
                eat(",")
                kids.append(node())
            eat(")")
            return (n, kids)
        if n == "tag":
            arms = []
            while True:
                t = int(name())
                eat(":")
                arms.append((t, node()))
                if peek() == ",":
                    eat(",")
                    continue
                break
            eat(")")
            return ("tag", arms)
        raise SystemExit("spec: unknown node " + n)

    return node()


def gen(n, r, out):
    k = n[0]
    if k == "u8":
        out += bytes([r.randrange(256)])
    elif k == "u16be":
        out += struct.pack(">H", r.randrange(65536))
    elif k == "u32le":
        out += struct.pack("<I", r.getrandbits(32))
    elif k == "u64be":
        out += struct.pack(">Q", r.getrandbits(64))
    elif k == "str8":
        s = bytes(r.randrange(256) for _ in range(r.randrange(24)))
        out += bytes([len(s)]) + s
    elif k == "lit":
        out += bytes([n[1]])
    elif k == "seq":
        for c in n[1]:
            gen(c, r, out)
    elif k == "rep":  # the spec's rep has one child
        c = r.randrange(5)
        out += bytes([c])
        for _ in range(c):
            gen(n[1][0], r, out)
    elif k == "alt":  # branches are written so any choice parses as itself
        gen(r.choice(n[1]), r, out)
    elif k == "tag":
        t, b = r.choice(n[1])
        out += bytes([t])
        gen(b, r, out)


def main():
    if len(sys.argv) < 4:
        raise SystemExit(__doc__)
    ast = parse_spec(open(sys.argv[1]).read().strip())
    r = random.Random(int(sys.argv[4]) if len(sys.argv) > 4 else 42)
    out = bytearray()
    n = int(sys.argv[3])
    for _ in range(n):
        gen(ast, r, out)
    with open(sys.argv[2], "wb") as f:
        f.write(out)
    print(n, "messages,", len(out), "bytes")


if __name__ == "__main__":
    main()
