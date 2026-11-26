#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""AUTOSAR signals and E2E of nanom-layout against independent implementations.

* cantools (DBC signal packing): random CAN-FD PDUs with Intel and Motorola signals of every width
  1..64 at random start bits, signed/unsigned, factor/offset, a multiplexor with multiplexed
  groups. The DBC text is loaded by cantools; the same signals are written as a nanom description.
    - decode: cantools-encoded PDUs -> `nanom_layout --format jsonl` (raw) and `--physical`,
      value by value against cantools.decode (multiplexed signals of other groups must be null);
    - encode: `nanom_layout --encode --raw-values` bytes == cantools.encode(scaling=False), and
      physical values (exactly representable) == cantools.encode(scaling=True).
* autosar-e2e (the `e2e` package): `nanom_layout --encode ... --e2e pXX` protects random PDUs
  (random lengths, offsets, data IDs / data-ID lists, P01/P11 modes); the oracle must accept every
  PDU (e2e_pXX_check) and re-protecting it with the oracle (same counter) must not change a byte.
  `--format e2e-check` must classify oracle-protected sequences (ok / repeated / ok_some_lost /
  wrong_sequence / wrong_crc) as expected.

Exit 77 (ctest: skipped) when cantools or e2e is not installed.
usage: layout_autosar_oracle.py path/to/nanom_layout
"""
import json
import os
import random
import subprocess
import sys
import tempfile

try:
    import cantools
    import e2e
    from e2e import p01, p02, p04, p05, p06, p07, p11
except ImportError as ex:  # pragma: no cover
    print(f"skipped: {ex}")
    sys.exit(77)

CLI = sys.argv[1] if len(sys.argv) > 1 else "./nanom_layout"
R = random.Random(int(os.environ.get("SEED", "20261126")))
TMP = tempfile.mkdtemp(prefix="nanom_autosar_")
failures = 0
checked = 0


def fail(msg):
    global failures
    failures += 1
    if failures <= 20:
        print("FAIL", msg)


def run(args, stdin=None):
    p = subprocess.run([CLI] + args, capture_output=True, input=stdin)
    if p.returncode != 0:
        raise RuntimeError(f"{' '.join(args)}: {p.stderr.decode()}")
    return p.stdout


def msb_linear(b):
    return b // 8 * 8 + 7 - b % 8


def bits_of(order, start, w):
    """Physical (byte, bit) cells a signal occupies."""
    if order == "intel":
        return [((start + i) // 8, (start + i) % 8) for i in range(w)]
    lin = msb_linear(start)
    return [((lin + i) // 8, 7 - (lin + i) % 8) for i in range(w)]


def place(n, used, w):
    for _ in range(200):
        order = R.choice(["intel", "motorola"])
        if order == "intel":
            if 8 * n - w < 0:
                return None
            start = R.randrange(0, 8 * n - w + 1)
        else:
            lin = R.randrange(0, 8 * n - w + 1)
            start = msb_linear(lin)
        cells = bits_of(order, start, w)
        if any(c in used for c in cells) or any(c[0] >= n for c in cells):
            continue
        used.update(cells)
        return order, start
    return None


def make_message(idx):
    n = R.choice([8, 8, 12, 16, 24, 32, 48, 64])
    used = set()
    sigs = []
    mux = None
    if R.random() < 0.5:
        w = R.randrange(2, 9)
        pl = place(n, used, w)
        if pl:
            mux = dict(name="Mux", order=pl[0], start=pl[1], w=w, signed=False, factor=1, offset=0, mux=True)
            sigs.append(mux)
    for k in range(R.randrange(1, 12)):
        w = R.choice([1, 2, 3, 4, 5, 7, 8, 9, 12, 15, 16, 17, 24, 31, 32, 33, 40, 48, 63, 64]
                     if R.random() < 0.7 else [R.randrange(1, 65)])
        pl = place(n, used, w)
        if not pl:
            continue
        signed = R.random() < 0.4 and w > 1
        scaled = R.random() < 0.6
        factor = R.choice([1, 0.5, 0.25, 0.1, 2, 10, 0.03125]) if scaled else 1
        offset = R.choice([0, -10, 40, -0.5, 1000]) if scaled else 0
        s = dict(name=f"S{k}", order=pl[0], start=pl[1], w=w, signed=signed, factor=factor, offset=offset,
                 scaled=scaled)
        if mux and R.random() < 0.5:
            s["mux_value"] = R.randrange(0, 1 << min(mux["w"], 3))
        sigs.append(s)
    return n, sigs, mux


def dbc_text(msgs):
    out = ['VERSION ""', "NS_ :", "BS_:", "BU_: N"]
    for i, (n, sigs, mux) in enumerate(msgs):
        out.append(f"BO_ {100 + i} M{i}: {n} N")
        for s in sigs:
            m = " M" if s.get("mux") else (f" m{s['mux_value']}" if "mux_value" in s else "")
            bo = "1" if s["order"] == "intel" else "0"
            sg = "-" if s["signed"] else "+"
            out.append(f' SG_ {s["name"]}{m} : {s["start"]}|{s["w"]}@{bo}{sg} ({s["factor"]},{s["offset"]}) [0|0] "u" N')
    return "\n".join(out) + "\n"


def nanom_desc(i, n, sigs):
    lines = []
    for s in sigs:
        d = {"raw_file": f"M{i}", "scalar_name": s["name"], "bit_offset": s["start"], "bit_width": s["w"],
             "byte_order": s["order"], "signed": s["signed"], "pdu_length": n}
        if s.get("scaled"):
            d["factor"] = s["factor"]
            d["offset"] = s["offset"]
        if s.get("mux"):
            d["multiplexor"] = True
        if "mux_value" in s:
            d["mux_value"] = s["mux_value"]
        lines.append(json.dumps(d))
    return "\n".join(lines) + "\n"


def rand_raw(s):
    w = s["w"]
    if s["signed"]:
        return R.randrange(-(1 << (w - 1)), 1 << (w - 1))
    return R.randrange(0, 1 << w)


def test_signals(nmsg=60, npdu=40):
    global checked
    msgs = [make_message(i) for i in range(nmsg)]
    db = cantools.database.load_string(dbc_text(msgs), "dbc")
    for i, (n, sigs, mux) in enumerate(msgs):
        msg = db.get_message_by_name(f"M{i}")
        desc = os.path.join(TMP, f"m{i}.jsonl")
        with open(desc, "w") as f:
            f.write(nanom_desc(i, n, sigs))
        pdus, raws = [], []
        for _ in range(npdu):
            raw = {}
            ids = sorted({s["mux_value"] for s in sigs if "mux_value" in s})
            # cantools only encodes multiplexor values that select a defined group
            sel = (R.choice(ids) if ids else R.randrange(0, 1 << mux["w"])) if mux else None
            for s in sigs:
                if s.get("mux"):
                    raw[s["name"]] = sel
                elif "mux_value" in s and s["mux_value"] != sel:
                    continue
                else:
                    raw[s["name"]] = rand_raw(s)
            data = msg.encode(raw, scaling=False, strict=False, padding=False)
            pdus.append(bytes(data))
            raws.append(raw)
        raw_path = os.path.join(TMP, f"m{i}.raw")
        with open(raw_path, "wb") as f:
            f.write(b"".join(pdus))
        # decode: raw integers
        out = run(["--layout", desc, "--input", raw_path]).decode().splitlines()
        phys = run(["--layout", desc, "--input", raw_path, "--physical"]).decode().splitlines()
        for r in range(npdu):
            mine = json.loads(out[r])
            mine_p = json.loads(phys[r])
            ref = msg.decode(pdus[r], decode_choices=False, scaling=False)
            ref_p = msg.decode(pdus[r], decode_choices=False, scaling=True)
            for s in sigs:
                nm = s["name"]
                checked += 1
                if nm not in ref:
                    if mine.get(nm, "absent") is not None:
                        fail(f"M{i} pdu {r} {nm}: expected null (other mux group), got {mine.get(nm)}")
                    continue
                if mine[nm] != ref[nm]:
                    fail(f"M{i} pdu {r} {nm} ({s}): raw {mine[nm]} != cantools {ref[nm]}")
                want = ref_p[nm]
                got = mine_p[nm]
                if s.get("scaled"):
                    if got is None or abs(got - want) > 1e-9 * max(1.0, abs(want)):
                        fail(f"M{i} pdu {r} {nm}: physical {got} != cantools {want}")
                elif got != want:
                    fail(f"M{i} pdu {r} {nm}: {got} != cantools {want}")
        # encode: raw values -> bytes identical to cantools
        vals = os.path.join(TMP, f"m{i}.values.jsonl")
        with open(vals, "w") as f:
            for raw in raws:
                f.write(json.dumps({k: v for k, v in raw.items() if abs(v) < 2 ** 53}) + "\n")
        exact = all(all(abs(v) < 2 ** 53 for v in raw.values()) for raw in raws)
        enc_path = os.path.join(TMP, f"m{i}.enc")
        run(["--layout", desc, "--encode", vals, "--raw-values", "-o", enc_path])
        got = open(enc_path, "rb").read()
        if exact:
            checked += 1
            if got != b"".join(pdus):
                for r in range(npdu):
                    a, b = got[r * n:(r + 1) * n], pdus[r]
                    if a != b:
                        fail(f"M{i} encode pdu {r}: {a.hex()} != cantools {b.hex()} values {raws[r]}")
                        break
        # encode: physical values (exact binary fractions: no rounding question) -> same bytes
        with open(vals, "w") as f:
            for raw in raws:
                d = {}
                for s in sigs:
                    if s["name"] in raw:
                        d[s["name"]] = raw[s["name"]] * s["factor"] + s["offset"]
                f.write(json.dumps(d) + "\n")
        exact_phys = all(s["factor"] in (1, 0.5, 0.25, 2, 0.03125) and float(s["offset"]).is_integer() or
                         s["offset"] == -0.5 and s["factor"] in (1, 0.5, 0.25, 0.03125) for s in sigs) and \
            all(s["w"] <= 48 for s in sigs)
        if exact_phys:
            run(["--layout", desc, "--encode", vals, "-o", enc_path])
            got = open(enc_path, "rb").read()
            checked += 1
            for r in range(npdu):
                ref = bytes(msg.encode({k: v for k, v in raws[r].items()}, scaling=False, strict=False,
                                       padding=False))
                if got[r * n:(r + 1) * n] != ref:
                    fail(f"M{i} physical encode pdu {r}: {got[r * n:(r + 1) * n].hex()} != {ref.hex()}")
                    break


PROFILES = {
    # name: (oracle protect, oracle check, header bytes, counter range, data id bits)
    "p01": (p01.e2e_p01_protect, p01.e2e_p01_check, 2, 15, 16),
    "p02": (p02.e2e_p02_protect, p02.e2e_p02_check, 2, 16, 0),
    "p04": (p04.e2e_p04_protect, p04.e2e_p04_check, 12, 1 << 16, 32),
    "p05": (p05.e2e_p05_protect, p05.e2e_p05_check, 3, 256, 16),
    "p06": (p06.e2e_p06_protect, p06.e2e_p06_check, 5, 256, 16),
    "p07": (p07.e2e_p07_protect, p07.e2e_p07_check, 20, 1 << 32, 32),
    "p11": (p11.e2e_p11_protect, p11.e2e_p11_check, 2, 15, 16),
}
MODES = {"p01": ["both", "alt", "low", "nibble"], "p11": ["both", "nibble"]}


def oracle_kwargs(prof, mode, off):
    kw = {}
    if prof in ("p01", "p11"):
        m = p01 if prof == "p01" else p11
        kw["data_id_mode"] = getattr(m, f"E2E_{prof.upper()}_DATAID_{mode.upper()}")
    if prof != "p02":
        kw["offset"] = off
    return kw


def test_e2e(rounds=60):
    global checked
    for prof, (protect, check, hdr, rng, idbits) in PROFILES.items():
        for _ in range(rounds):
            mode = R.choice(MODES.get(prof, ["both"]))
            n = R.randrange(hdr + (1 if prof in ("p01", "p11") and mode == "nibble" else 0), hdr + 40)
            off = 0 if prof == "p02" else R.randrange(0, n - hdr + 1)
            if prof in ("p01", "p11") and off + 2 > n:
                off = n - 2
            did = R.randrange(1 << idbits) if idbits else 0
            if prof in ("p01", "p11") and mode == "nibble":
                did &= 0x0FFF  # the nibble carries bits 8..11 of the 16-bit data ID
            lst = bytes(R.randrange(256) for _ in range(16))
            desc = os.path.join(TMP, "e2e.jsonl")
            with open(desc, "w") as f:
                f.write(json.dumps({"raw_file": "E", "scalar_name": "Last", "bit_offset": 8 * (n - 1),
                                    "bit_width": 8, "byte_order": "intel", "pdu_length": n}) + "\n")
            k = R.randrange(1, 20)
            vals = os.path.join(TMP, "e2e.values.jsonl")
            with open(vals, "w") as f:
                f.write("{}\n" * k)
            tmpl = bytes(R.randrange(256) for _ in range(n))
            args = ["--layout", desc, "--encode", vals, "--pdu-template", tmpl.hex(), "--e2e", prof,
                    "--e2e-offset", str(8 * off), "-o", os.path.join(TMP, "e2e.raw")]
            args += ["--data-id-list", lst.hex()] if prof == "p02" else ["--data-id", str(did)]
            if prof in MODES:
                args += ["--e2e-mode", mode]
            run(args)
            data = open(os.path.join(TMP, "e2e.raw"), "rb").read()
            idarg = lst if prof == "p02" else did
            for r in range(k):
                pdu = bytearray(data[r * n:(r + 1) * n])
                checked += 1
                kw = oracle_kwargs(prof, mode, off)
                if not check(bytearray(pdu), idarg, **kw):
                    fail(f"{prof} {mode} n={n} off={off} id={did:#x} pdu {r}: oracle check rejects {pdu.hex()}")
                    continue
                again = bytearray(pdu)
                protect(again, idarg, increment_counter=False, **kw)
                if again != pdu:
                    fail(f"{prof} {mode} n={n} off={off}: oracle re-protect changes {pdu.hex()} -> {again.hex()}")
        # receiver: oracle-protected sequence with a repeat, a gap, a jump and a corrupted PDU
        n = hdr + 8
        did = R.randrange(1 << idbits) if idbits else 0
        lst = bytes(range(16))
        idarg = lst if prof == "p02" else did
        kw = oracle_kwargs(prof, "both", 0)
        cur = bytearray(n)  # counter fields start at 0
        seq, want = [], []

        def emit(steps, expect, corrupt=False):
            nonlocal cur
            for _ in range(steps):
                protect(cur, idarg, increment_counter=True, **kw)
            pdu = bytearray(cur)
            if corrupt:
                pdu[-1] ^= 0x40
            seq.append(bytes(pdu))
            want.append(expect)
        # the oracle starts counting at 1 (it increments before protecting); our checker's first
        # expected counter is 0, so a first counter of 1 reads as ok_some_lost(1) with max delta 2
        emit(1, "ok_some_lost")
        emit(1, "ok")
        emit(0, "repeated")
        emit(2, "ok_some_lost")
        emit(1, "ok")
        emit(5, "wrong_sequence")
        emit(1, "ok")
        emit(1, "wrong_crc", corrupt=True)
        emit(1, "ok_some_lost")
        raw = os.path.join(TMP, "seq.raw")
        with open(raw, "wb") as f:
            f.write(b"".join(seq))
        desc = os.path.join(TMP, "seq.jsonl")
        with open(desc, "w") as f:
            f.write(json.dumps({"raw_file": "E", "scalar_name": "Last", "bit_offset": 8 * (n - 1), "bit_width": 8,
                                "byte_order": "intel", "pdu_length": n}) + "\n")
        args = ["--layout", desc, "--input", raw, "--format", "e2e-check", "--e2e", prof, "--e2e-max-delta", "2"]
        args += ["--data-id-list", lst.hex()] if prof == "p02" else ["--data-id", str(did)]
        got = run(args).decode().split()
        checked += 1
        if got != want:
            fail(f"{prof} receiver: {got} != {want}")


test_signals()
test_e2e()
print(f"layout_autosar_oracle: {checked} checks, {failures} failures")
sys.exit(1 if failures else 0)
