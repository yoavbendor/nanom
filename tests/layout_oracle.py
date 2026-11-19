#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent oracle for nanom-layout (stdlib only: json, struct, int.from_bytes).

1. Generates a realistic layout description the way a debugger-driven exporter would: C structs
   laid out with C/GCC rules (alignment, bit-field packing), nested names with `::` components,
   std::atomic internals (`long>._M_i`), `_vptr` pointers, arrays of structs and scalars
   (`array_item_N`, including a 1-based and a gappy one), every type family, bit-fields, a ~59 KB
   "devices" record with thousands of scalars, the 20-byte GFI repeated twice per record, a tiny
   3-byte bit-field record, a 9-byte-straddling packed field, and an enum file.
2. Writes random raw files (enum fields biased toward named values).
3. Decodes them here, from the description alone, with its own implementation of the documented
   rules (stride, bit order, sign extension, name tree, implicit arrays, formatting).
4. Runs the C++ CLI (record path, column path with both schedules, big-endian, projections,
   partial-record handling, strict/lenient unknown types) and diffs every record value by value,
   in key order. Exit 0 = identical.

usage: layout_oracle.py path/to/nanom_layout [--keep DIR] [--seed N]
"""
import json
import os
import random
import struct
import subprocess
import sys
import tempfile

# ----------------------------------------------------------------------------------------------
# 1. description generator (C layout rules)
# ----------------------------------------------------------------------------------------------

SCALARS = [  # (type string, bits, C alignment bytes)
    ("UChar", 8, 1), ("Char", 8, 1), ("Short", 16, 2), ("UShort", 16, 2), ("Int", 32, 4),
    ("UInt", 32, 4), ("Long", 64, 8), ("ULong", 64, 8), ("LongLong", 64, 8),
    ("ULongLong", 64, 8), ("Float", 32, 4), ("Double", 64, 8), ("Real*4", 32, 4),
    ("Real*8", 64, 8), ("Logical*1", 8, 1), ("Logical*4", 32, 4), ("Integer*2", 16, 2),
    ("Integer*4", 32, 4), ("*Void", 64, 8), ("*Char", 64, 8), ("Bool", 8, 1),
    ("SChar", 8, 1), ("Integer*8", 64, 8),
]
BITFIELD_TYPES = [("UInt", 32), ("Int", 32), ("UChar", 8), ("UShort", 16), ("ULongLong", 64),
                  ("Short", 16)]


def align_up(x, a):
    return (x + a - 1) // a * a


class Gen:
    def __init__(self, rnd, enum_refs):
        self.rnd = rnd
        self.enum_refs = enum_refs  # refs that have definitions
        self.counter = 0

    def name(self, prefix="_m"):
        self.counter += 1
        return f"{prefix}{self.counter}"

    # A struct is a list of members; laying it out returns (size_bytes, align, [(bitoff, path, type, width)])
    def scalar_member(self):
        r = self.rnd.random()
        if r < 0.08:
            ref = self.rnd.choice(self.enum_refs)
            return ("scalar", self.name("_state"), f"Enum ref = {ref}", 32, 4)
        t, bits, a = self.rnd.choice(SCALARS)
        return ("scalar", self.name(), t, bits, a)

    def struct(self, depth, nmembers):
        members = []
        for _ in range(nmembers):
            r = self.rnd.random()
            if depth > 0 and r < 0.10:
                members.append(("struct", self.rnd.choice(["Diagnostics::DeviceStatus", self.name("_sub"),
                                                           "MEIO::Counter"]),
                                self.struct(depth - 1, self.rnd.randint(2, 6))))
            elif r < 0.14:  # std::atomic<T>
                t, bits, a = self.rnd.choice([("Long", 64, 8), ("Int", 32, 4), ("ULongLong", 64, 8)])
                inner = {"Long": "long>", "Int": "int>", "ULongLong": "unsigned long long>"}[t]
                members.append(("struct", self.name("_cnt"),
                                [("struct", inner, [("scalar", "_M_i", t, bits, a)])]))
            elif r < 0.17:  # vptr
                members.append(("struct", "_vptr", [("scalar", "MapContainer", "*Void", 64, 8)]))
            elif r < 0.22:  # bit-field run
                t, unit = self.rnd.choice(BITFIELD_TYPES)
                fields = []
                for _ in range(self.rnd.randint(2, 5)):
                    w = self.rnd.randint(1, min(unit, 13) if unit < 64 else 40)
                    fields.append((self.name("_bf"), w))
                kind = "enum" if self.rnd.random() < 0.2 and unit == 32 else t
                members.append(("bitfields", kind, unit, fields))
            elif r < 0.25 and depth > 0:  # scalar array
                t, bits, a = self.rnd.choice([("UChar", 8, 1), ("Float", 32, 4), ("Int", 32, 4)])
                members.append(("sarray", self.name("_arr"), t, bits, a, self.rnd.randint(2, 6)))
            else:
                members.append(self.scalar_member())
        return members


def layout(members, base_bits, path, out):
    """C/GCC layout of `members` starting at base_bits (struct-aligned). Returns (size, align)."""
    cur = 0
    align = 1
    for m in members:
        kind = m[0]
        if kind == "scalar":
            _, nm, t, bits, a = m
            cur = align_up(cur, a * 8)
            out.append((base_bits + cur, path + [nm], t, bits))
            cur += bits
            align = max(align, a)
        elif kind == "struct":
            _, nm, sub = m
            tmp = []
            size, a = layout(sub, 0, [], tmp)
            cur = align_up(cur, a * 8)
            for (o, p, t, w) in tmp:
                out.append((base_bits + cur + o, path + [nm] + p, t, w))
            cur += size * 8
            align = max(align, a)
        elif kind == "bitfields":
            _, t, unit, fields = m
            ua = unit // 8
            tname = "Enum ref = 7" if t == "enum" else t
            for nm, w in fields:
                if (cur % unit) + w > unit:
                    cur = align_up(cur, unit)
                out.append((base_bits + cur, path + [nm], tname, w))
                cur += w
            align = max(align, ua if t != "enum" else 4)
        elif kind == "sarray":
            _, nm, t, bits, a, n = m
            cur = align_up(cur, a * 8)
            for i in range(n):
                out.append((base_bits + cur, path + [nm, f"array_item_{i}"], t, bits))
                cur += bits
            align = max(align, a)
        elif kind == "aarray":  # array of structs: (name, sub, n, first_index, skip)
            _, nm, sub, n, first, skip = m
            tmp = []
            size, a = layout(sub, 0, [], tmp)
            cur = align_up(cur, a * 8)
            for i in range(n):
                if i + first not in skip:
                    for (o, p, t, w) in tmp:
                        out.append((base_bits + cur + o, path + [nm, f"array_item_{i + first}"] + p, t, w))
                cur += size * 8
            align = max(align, a)
    size = align_up((cur + 7) // 8, align)
    return size, align


def make_description(rnd):
    lines = []
    enums = {}

    def emit(raw, scalars):
        for (o, p, t, w) in scalars:
            lines.append({"raw_file": raw, "scalar_name": ".".join(p), "bit_offset": o,
                          "bit_width": w, "type": t})

    # GFI: the user's sample, twice per record
    gfi = "/dev/vdiZ/pacemaker/gfi.raw"
    for k in range(2):
        base = 160 * k
        for (o, nm, w, t) in [(0, "grab_index", 32, "UInt"), (32, "slow_index", 32, "UInt"),
                              (64, "tapi_index", 32, "UInt"), (96, "brain_type", 32, "Enum ref = 1"),
                              (128, "BlackDummy", 8, "Logical*1")]:
            lines.append({"raw_file": gfi, "scalar_name": "GFI." + nm, "bit_offset": base + o,
                          "bit_width": w, "type": t})
    enums[gfi] = {"Enum ref = 1": {"-1": "UNDEF", "0": "IMG1", "1": "IMG2", "2": "IMG3", "3": "IMG4",
                                   "4": "IMG5", "5": "IMG6"}}

    # devices: ~59 KB, thousands of scalars
    dev = "/proc/app/devices.raw"
    g = Gen(rnd, [161, 162, 7])
    uart_elem = [("struct", "_cntMEVSA_UARTLog",
                  [("struct", "_total", [("struct", "int>", [("scalar", "_M_i", "UInt", 32, 4)])]),
                   ("scalar", "_inCurrentFrame", "UChar", 8, 1)]),
                 ("struct", "Diagnostics::DeviceStatus",
                  [("scalar", "_deviceId", "Int", 32, 4), ("scalar", "_cslEnabled", "Logical*1", 8, 1),
                   ("scalar", "_state", "Enum ref = 161", 32, 4)])] + g.struct(2, 150)
    top = [
        ("struct", "_board", [("struct", "Diagnostics::DeviceStatus",
                                [("scalar", "_cslEnabled", "Logical*1", 8, 1),
                                 ("scalar", "_state", "Enum ref = 161", 32, 4)])]),
        ("aarray", "_uartWrite", uart_elem, 20, 1, set()),       # array_item_1.. (1-based)
        ("aarray", "_sensors", g.struct(2, 110), 12, 0, {3, 7}),  # gaps -> null
    ] + g.struct(3, 1900)
    scal = []
    size, _ = layout(top, 0, ["MEIO::IOAppDevices"], scal)
    emit(dev, scal)
    enums[dev] = {"Enum ref = 161": {str(i - 1): f"DEV_STATE_{i}" for i in range(9)},
                  "Enum ref = 162": {"0": "OFF", "1": "ON", "0x10": "HEX_SIXTEEN"},
                  "Enum ref = 7": {"0": "ZERO", "1": "ONE", "2": "TWO", "5": "FIVE"}}

    # currentFrame: the sample's names + a packed 9-byte-straddling field and wide bit-fields
    cf = "/proc/app/currentFrame.raw"
    for (o, nm, w, t) in [
            (0, "MEIO::InputFrame.frameID", 32, "Int"),
            (32, "MEIO::InputFrame.flags.valid", 1, "Bool"),
            (33, "MEIO::InputFrame.flags.mode", 3, "Enum ref = 3"),
            (36, "MEIO::InputFrame.flags.code", 5, "Int"),
            (44, "MEIO::InputFrame.packed.wide", 64, "ULongLong"),      # straddles 9 bytes
            (108, "MEIO::InputFrame.packed.swide", 63, "LongLong"),     # straddles 9 bytes
            (128, "MEIO::InputFrame.vids._vptr.MapContainer", 64, "*Void"),
            (192, "MEIO::InputFrame.vids.count", 16, "UShort"),
            (208, "MEIO::InputFrame.vids.delta", 16, "Short"),
            (224, "MEIO::InputFrame.gain", 32, "Real*4"),
            (256, "MEIO::InputFrame.scale", 64, "Real*8"),
            (320, "MEIO::InputFrame.tiny", 7, "SChar"),
            (327, "MEIO::InputFrame.odd", 33, "ULongLong"),
            (512, "MEIO::InputFrame.vids.defaultMappedType._value.lastFSTimestamp.long>._M_i", 64, "ULongLong"),
            (576, "MEIO::InputFrame.tail", 8, "Logical*1")]:
        lines.append({"raw_file": cf, "scalar_name": nm, "bit_offset": o, "bit_width": w, "type": t})
    enums[cf] = {"Enum ref = 3": {"0": "IDLE", "1": "RUN", "-1": "ERR"}}

    # tiny: a 3-byte record of bit-fields (loads narrower than 8 bytes)
    tiny = "/proc/app/tiny.raw"
    for (o, nm, w, t) in [(0, "T.a", 3, "UChar"), (3, "T.b", 5, "Char"), (8, "T.c", 12, "UShort"),
                          (20, "T.d", 4, "Logical*1"), (16, "T.overlay", 8, "UChar")]:  # union-style overlap
        lines.append({"raw_file": tiny, "scalar_name": nm, "bit_offset": o, "bit_width": w, "type": t})
    return lines, enums, size


# ----------------------------------------------------------------------------------------------
# 2. the oracle's own reading of the description
# ----------------------------------------------------------------------------------------------

def squash(t):
    return "".join(c for c in t.lower() if c not in " \t_")


INT_BASES = {"char": 1, "short": 2, "int": 4, "integer": 4, "long": 8, "longlong": 8}


def family_of(t):
    """(family, declared size bytes or 0)."""
    s = squash(t)
    if s.startswith("enumref="):
        return "enum", 0
    if s.startswith("*") or s.endswith("*"):
        return "ptr", 0
    if s.startswith("logical*"):
        return "bool", int(s[8:])
    if s in ("bool", "boolean"):
        return "bool", 1
    if s in ("float",):
        return "float", 4
    if s in ("double",):
        return "float", 8
    if s.startswith("real*"):
        return "float", int(s[5:])
    if s == "schar":
        return "int", 1
    if s.startswith("integer*"):
        return "int", int(s[8:])
    if s in INT_BASES:
        return "int", INT_BASES[s]
    if s.startswith("u") and s[1:] in INT_BASES:
        return "uint", INT_BASES[s[1:]]
    return None, 0


def natural(o, w):
    return o % 8 == 0 and w in (8, 16, 32, 64)


def pow2_bytes(bits):
    b = (bits + 7) // 8
    return 1 if b <= 1 else 2 if b <= 2 else 4 if b <= 4 else 8


def stride_rule(fields):
    end = max(f["bit_offset"] + f["bit_width"] for f in fields)
    used = (end + 7) // 8
    a = 1
    for f in fields:
        fam, size = family_of(f["type"])
        if natural(f["bit_offset"], f["bit_width"]):
            fa = f["bit_width"] // 8
        elif fam == "enum":
            fa = 4
        elif size:
            fa = min(size, 8)
        else:
            fa = pow2_bytes(f["bit_width"])
        a = max(a, fa)
    return align_up(used, a)


class F32:
    """Expected float32 value (compared after rounding the C++ text to float32)."""
    def __init__(self, bits):
        self.bits = bits


class F64:
    def __init__(self, bits):
        self.bits = bits


def decode_value(rec, f, enums, big):
    o, w = f["bit_offset"], f["bit_width"]
    start, end = o // 8, (o + w + 7) // 8
    chunk = rec[start:end]
    if big:
        v = int.from_bytes(chunk, "big") >> ((end - start) * 8 - (o % 8) - w)
    else:
        v = int.from_bytes(chunk, "little") >> (o % 8)
    v &= (1 << w) - 1
    fam, _ = family_of(f["type"])
    table = None
    if fam == "enum":
        ref = int(squash(f["type"])[8:], 0)
        table = enums.get(f["raw_file"], {}).get(f"Enum ref = {ref}")
    signed = fam == "int" or (fam == "enum" and (natural(o, w) or (table is not None and any(int(k, 0) < 0 for k in table))))
    if signed and v >> (w - 1):
        v -= 1 << w
    if fam == "bool":
        return v != 0
    if fam == "float":
        return F32(v) if w == 32 else F64(v)
    if fam == "ptr":
        return "0x%x" % v
    if fam == "enum" and table is not None:
        for k, name in table.items():
            if int(k, 0) == v:
                return name
    return v


def build_tree(fields):
    """Returns the expansion as a nested structure of ('obj', [(key, child)]) / ('arr', [child])
    / ('leaf', field_index) / ('null',)."""
    occ = {}
    order = sorted(range(len(fields)), key=lambda i: (fields[i]["bit_offset"], fields[i]["line"]))
    for i in order:
        occ.setdefault(fields[i]["scalar_name"], []).append(i)
    trie = {"kids": {}, "inst": [], "comp": None, "parent": None}
    for name, insts in occ.items():
        node = trie
        for c in name.split("."):
            if c not in node["kids"]:
                node["kids"][c] = {"kids": {}, "inst": [], "comp": c, "parent": node}
            node = node["kids"][c]
        node["inst"] = insts
    # trie kids must keep first-appearance order of the description (not of occ): rebuild order
    first_seen = {}
    for i, f in enumerate(fields):
        path = f["scalar_name"].split(".")
        for d in range(1, len(path) + 1):
            first_seen.setdefault(tuple(path[:d]), i)

    def sorted_kids(node, prefix):
        return sorted(node["kids"].items(), key=lambda kv: first_seen[tuple(prefix + [kv[0]])])

    def uniform(node, prefix):
        if node["kids"]:
            us = {uniform(k, prefix + [c]) for c, k in node["kids"].items()}
            node["u"] = us.pop() if len(us) == 1 else 0
        else:
            node["u"] = len(node["inst"])
        return node["u"]

    uniform(trie, [])
    trie["u"] = -1

    def is_item(c):
        return c.startswith("array_item_") and c[11:].isdigit() and len(c) > 11

    def expand(node, prefix, inst):
        rep = node["u"] > 1 and node["parent"]["u"] != node["u"]
        if rep and inst is None:
            return ("arr", [body(node, prefix, k) for k in range(node["u"])])
        return body(node, prefix, inst)

    def body(node, prefix, inst):
        if not node["kids"]:
            return ("leaf", node["inst"][inst or 0])
        kids = sorted_kids(node, prefix)
        if all(is_item(c) for c, _ in kids):
            items = sorted((int(c[11:]), c, k) for c, k in kids)
            out, nxt = [], items[0][0]
            for idx, c, k in items:
                while nxt < idx:
                    out.append(("null",))
                    nxt += 1
                out.append(expand(k, prefix + [c], inst))
                nxt = idx + 1
            return ("arr", out)
        return ("obj", [(c, expand(k, prefix + [c], inst)) for c, k in kids])

    return ("obj", [(c, expand(k, [c], None)) for c, k in sorted_kids(trie, [])])


def render(tree, values, selected):
    """tree + per-field values -> JSON-like value with ordered pairs; None if nothing selected."""
    kind = tree[0]
    if kind == "leaf":
        return ("has", values[tree[1]]) if tree[1] in selected else None
    if kind == "null":
        return None
    if kind == "obj":
        pairs = []
        for k, c in tree[1]:
            r = render(c, values, selected)
            if r is not None:
                pairs.append((k, r[1]))
        return ("has", pairs) if pairs else None
    rs = [render(c, values, selected) for c in tree[1]]
    last = max((i for i, r in enumerate(rs) if r is not None), default=-1)
    if last < 0:
        return None
    return ("has", [r[1] if r is not None else None for r in rs[:last + 1]])


def same(exp, act, path):
    if isinstance(exp, F32):
        if isinstance(act, bool) or not isinstance(act, (int, float)) and act is not None:
            return f"{path}: expected float32, got {act!r}"
        f = struct.unpack("<f", exp.bits.to_bytes(4, "little"))[0]
        if f != f or f in (float("inf"), float("-inf")):
            return None if act is None else f"{path}: expected null (non-finite), got {act!r}"
        if act is None or struct.pack("<f", float(act)) != exp.bits.to_bytes(4, "little"):
            return f"{path}: expected float32 {f!r}, got {act!r}"
        return None
    if isinstance(exp, F64):
        f = struct.unpack("<d", exp.bits.to_bytes(8, "little"))[0]
        if f != f or f in (float("inf"), float("-inf")):
            return None if act is None else f"{path}: expected null (non-finite), got {act!r}"
        if act is None or isinstance(act, bool) or struct.pack("<d", float(act)) != struct.pack("<d", f):
            return f"{path}: expected double {f!r}, got {act!r}"
        return None
    if type(exp) is not type(act):
        return f"{path}: expected {exp!r} ({type(exp).__name__}), got {act!r} ({type(act).__name__})"
    if isinstance(exp, list):
        if len(exp) != len(act):
            return f"{path}: expected {len(exp)} entries, got {len(act)}"
        for i, (e, a) in enumerate(zip(exp, act)):
            if isinstance(e, tuple):  # object pair
                if not isinstance(a, tuple) or e[0] != a[0]:
                    return f"{path}: key #{i}: expected {e[0]!r}, got {a[0] if isinstance(a, tuple) else a!r}"
                r = same(e[1], a[1], f"{path}.{e[0]}")
            else:
                r = same(e, a, f"{path}[{i}]")
            if r:
                return r
        return None
    return None if exp == act else f"{path}: expected {exp!r}, got {act!r}"


# ----------------------------------------------------------------------------------------------
# 3. raw data, CLI runs, diff
# ----------------------------------------------------------------------------------------------

def put_bits(rec, o, w, v, big):
    start, end = o // 8, (o + w + 7) // 8
    nb = end - start
    if big:
        sh = nb * 8 - (o % 8) - w
        cur = int.from_bytes(rec[start:end], "big")
        cur = (cur & ~(((1 << w) - 1) << sh)) | ((v & ((1 << w) - 1)) << sh)
        rec[start:end] = cur.to_bytes(nb, "big")
    else:
        sh = o % 8
        cur = int.from_bytes(rec[start:end], "little")
        cur = (cur & ~(((1 << w) - 1) << sh)) | ((v & ((1 << w) - 1)) << sh)
        rec[start:end] = cur.to_bytes(nb, "little")


def make_raw(rnd, fields, enums, stride, n, big):
    out = bytearray()
    for _ in range(n):
        rec = bytearray(rnd.getrandbits(8) for _ in range(stride)) if stride < 4096 else \
            bytearray(rnd.getrandbits(8 * stride).to_bytes(stride, "little"))
        for f in fields:
            fam, _ = family_of(f["type"])
            if fam == "enum" and rnd.random() < 0.75:
                ref = int(squash(f["type"])[8:], 0)
                table = enums.get(f["raw_file"], {}).get(f"Enum ref = {ref}")
                if table:
                    put_bits(rec, f["bit_offset"], f["bit_width"], int(rnd.choice(list(table)), 0), big)
            elif fam == "bool" and rnd.random() < 0.5:
                put_bits(rec, f["bit_offset"], f["bit_width"], rnd.choice([0, 1]), big)
            elif fam == "float" and rnd.random() < 0.5:
                w = f["bit_width"]
                val = rnd.choice([0.0, -0.0, 1.5, 0.1, -3.25e10, 1e-30, 100.0, float("inf")])
                bits = int.from_bytes(struct.pack("<f" if w == 32 else "<d", val), "little")
                put_bits(rec, f["bit_offset"], w, bits, big)
        out += rec
    return bytes(out)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    cli = sys.argv[1]
    seed = 20261118
    keep = None
    args = sys.argv[2:]
    while args:
        a = args.pop(0)
        if a == "--seed":
            seed = int(args.pop(0))
        elif a == "--keep":
            keep = args.pop(0)
    rnd = random.Random(seed)
    lines, enums, dev_size = make_description(rnd)
    for i, l in enumerate(lines):
        l["line"] = i + 1
    work = keep or tempfile.mkdtemp(prefix="nanom_layout_oracle_")
    os.makedirs(work, exist_ok=True)
    desc_path = os.path.join(work, "desc.jsonl")
    with open(desc_path, "w") as fh:
        for l in lines:  # vary formatting: key order, spaces, extra keys
            d = {k: v for k, v in l.items() if k != "line"}
            if l["line"] % 3 == 0:
                d = dict(reversed(list(d.items())))
                d["comment"] = {"x": [1, 2.5, None, True]}
            fh.write(json.dumps(d, separators=(",", ":") if l["line"] % 2 else (", ", ": ")) + "\n")
    enums_path = os.path.join(work, "enums.json")
    with open(enums_path, "w") as fh:
        json.dump(enums, fh, indent=2)

    by_file = {}
    for l in lines:
        by_file.setdefault(l["raw_file"], []).append(l)
    failures = 0
    total_values = 0

    def run(args, expect_ok=True):
        p = subprocess.run([cli] + args, capture_output=True)
        if expect_ok and p.returncode != 0:
            raise RuntimeError(f"CLI failed ({p.returncode}): {' '.join(args)}\n{p.stderr.decode()}")
        return p

    counts = {"/dev/vdiZ/pacemaker/gfi.raw": 3000, "/proc/app/devices.raw": 24,
              "/proc/app/currentFrame.raw": 500, "/proc/app/tiny.raw": 700}
    for raw, fields in by_file.items():
        stride = stride_rule(fields)
        if raw == "/proc/app/devices.raw":
            assert stride == dev_size, f"stride rule {stride} != C layout {dev_size}"
            print(f"devices: {len(fields)} scalars, record {stride} bytes "
                  f"({sum(1 for f in fields if not natural(f['bit_offset'], f['bit_width']))} bit-fields)")
        tree = build_tree(fields)
        for big in (False, True):
            n = counts[raw]
            data = make_raw(rnd, fields, enums, stride, n, big)
            raw_path = os.path.join(work, os.path.basename(raw) + (".be" if big else ".le"))
            with open(raw_path, "wb") as fh:
                fh.write(data)
            values_per_rec = [[decode_value(data[r * stride:(r + 1) * stride], f, enums, big) for f in fields]
                              for r in range(n)]
            prefix = {"/dev/vdiZ/pacemaker/gfi.raw": "GFI[1]",
                      "/proc/app/devices.raw": "MEIO::IOAppDevices._uartWrite.",
                      "/proc/app/currentFrame.raw": "MEIO::InputFrame.vids",
                      "/proc/app/tiny.raw": "T.c"}[raw]
            sel_all = set(range(len(fields)))
            # projection: same matching rule as documented (subtree / prefix on name or column)
            sel_proj = set()
            for i, f in enumerate(fields):
                nm = f["scalar_name"]
                if raw == "/dev/vdiZ/pacemaker/gfi.raw":
                    hit = f["bit_offset"] >= 160  # GFI[1] = second occurrence
                elif prefix.endswith("."):
                    hit = nm.startswith(prefix)
                else:
                    hit = nm == prefix or nm.startswith(prefix + ".") or nm.startswith(prefix + "[")
                if hit:
                    sel_proj.add(i)
            base = ["--layout", desc_path, "--enums", enums_path, "--raw-file-name", raw, "--input", raw_path]
            if big:
                base.append("--big-endian")
            variants = [("record path", [], sel_all),
                        ("columns field-major", ["--via-columns", "--strategy", "field"], sel_all),
                        ("columns record-major", ["--via-columns", "--strategy", "record"], sel_all),
                        (f"projection {prefix}", ["--select", prefix], sel_proj),
                        (f"projection {prefix} via columns", ["--select", prefix, "--via-columns"], sel_proj)]
            for label, extra, sel in variants:
                out = run(base + extra).stdout.decode().splitlines()
                tag = f"{os.path.basename(raw)} {'BE' if big else 'LE'} {label}"
                if len(out) != n:
                    print(f"FAIL {tag}: {len(out)} lines, expected {n}")
                    failures += 1
                    continue
                for r, line in enumerate(out):
                    exp = render(tree, values_per_rec[r], sel)
                    exp = exp[1] if exp else []
                    act = json.loads(line, object_pairs_hook=lambda p: list(p))
                    diff = same(exp, act, f"record {r}")
                    total_values += len(sel)
                    if diff:
                        print(f"FAIL {tag}: {diff}")
                        failures += 1
                        break
                else:
                    print(f"ok   {tag}: {n} records x {len(sel)} values")
            # --records slice
            out = run(base + ["--records", f"{n // 3}:{n // 3 + 5}"]).stdout.decode().splitlines()
            ok = len(out) == min(5, n - n // 3) and all(
                same(render(tree, values_per_rec[n // 3 + i], sel_all)[1],
                     json.loads(l, object_pairs_hook=lambda p: list(p)), "slice") is None
                for i, l in enumerate(out))
            print(("ok   " if ok else "FAIL ") + f"{os.path.basename(raw)} --records slice")
            failures += not ok

        # partial trailing record: error by default, ignored with --allow-partial
        part = os.path.join(work, "partial.raw")
        with open(part, "wb") as fh:
            fh.write(bytes(stride * 3 + max(1, stride // 2)))
        base = ["--layout", desc_path, "--raw-file-name", raw, "--input", part]
        p = run(base, expect_ok=False)
        ok = p.returncode != 0 and b"trailing" in p.stderr
        p2 = run(base + ["--allow-partial"], expect_ok=False)
        ok = ok and p2.returncode == 0 and len(p2.stdout.decode().splitlines()) == 3
        print(("ok   " if ok else "FAIL ") + f"{os.path.basename(raw)} partial trailing record")
        failures += not ok

    # unknown type: strict error with line number, lenient decodes raw unsigned bits
    odd = os.path.join(work, "odd.jsonl")
    with open(odd, "w") as fh:
        fh.write('{"raw_file":"o","scalar_name":"Q.a","bit_offset":0,"bit_width":16,"type":"UInt"}\n')
        fh.write('\n{"raw_file":"o","scalar_name":"Q.q","bit_offset":16,"bit_width":16,"type":"Quaternion"}\n')
    oraw = os.path.join(work, "odd.raw")
    with open(oraw, "wb") as fh:
        fh.write(bytes([1, 2, 0xff, 0xfe]))
    p = run(["--layout", odd, "--input", oraw], expect_ok=False)
    ok = p.returncode != 0 and b":3:" in p.stderr and b"Quaternion" in p.stderr
    p = run(["--layout", odd, "--input", oraw, "--lenient"], expect_ok=False)
    ok = ok and p.returncode == 0 and json.loads(p.stdout) == {"Q": {"a": 0x0201, "q": 0xfeff}}
    print(("ok   " if ok else "FAIL ") + "unknown type: strict error with line, lenient raw bits")
    failures += not ok

    if not keep:
        import shutil
        shutil.rmtree(work, ignore_errors=True)
    print(f"{'FAILED' if failures else 'PASSED'}: {total_values} values compared, {failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
