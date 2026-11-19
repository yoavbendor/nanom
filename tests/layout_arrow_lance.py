#!/usr/bin/env python3
"""Enum columns through Arrow into Lance: nanom::layout::export_arrow -> pyarrow -> pylance.

Loads tests/layout_arrow_capi.cpp (a shared library) with ctypes, has it decode a generated raw
file and export it through the Arrow C Data Interface, imports the struct into pyarrow, and checks:

  * enum fields with a table are dictionary<int8|int16, string> (smallest index that fits); names in raw-value order, unnamed raw
    values appended as decimal text (ascending); the field metadata maps index -> raw value
  * every value agrees with an independent Python decode (int.from_bytes), little and big endian,
    including natural enums with -1, unsigned and signed enum bit-fields, an 8-bit enum, and an
    enum without a table (stays a plain int16)
  * --enums-as integer / both equivalents (enum_mode 1 / 2)
  * the batch written with lance.write_dataset reads back as dictionary columns with the names
    intact and the metadata preserved, and a filter by name selects the right rows. Lance refuses
    '.' in top-level field names; export_arrow's default separator ('/') already avoids it, so the
    exported batch goes into Lance unchanged.

usage: layout_arrow_lance.py /path/to/libnanom_layout_arrow_capi.so
Exits 0 on success, 1 on a mismatch, 77 (ctest "skipped") when pyarrow or pylance is missing.
"""
import ctypes
import json
import os
import random
import sys
import tempfile

try:
    import pyarrow as pa
    import pyarrow.compute as pc
    import lance
except ImportError as e:
    print(f"{e.name} not installed: skipping (configure with -DNANOM_PYARROW_PYTHON=/path/to/python)")
    sys.exit(77)

RAW = "/dev/x/rec.raw"
STRIDE = 16
FIELDS = [  # name, bit_offset, bit_width, type
    ("Rec.id", 0, 32, "UInt"),
    ("Rec.mode", 32, 32, "Enum ref = 1"),        # natural 32-bit enum: signed, -1 = UNDEF
    ("Rec.flags.kind", 64, 3, "Enum ref = 2"),   # bit-field, table without negatives: unsigned
    ("Rec.flags.sk", 67, 4, "Enum ref = 3"),     # bit-field, table with a negative: signed
    ("Rec.small", 72, 8, "Enum ref = 4"),        # natural 8-bit enum
    ("Rec.noTable", 80, 16, "Enum ref = 99"),    # no table: plain integer
    ("Rec.x", 96, 32, "Int"),
]
ENUMS = {RAW: {
    "Enum ref = 1": {"-1": "UNDEF", "0": "IMG1", "1": "IMG2", "2": "IMG3", "3": "IMG4", "4": "IMG5", "5": "IMG6"},
    "Enum ref = 2": {"0": "A", "1": "B", "2": "C", "5": "F"},
    "Enum ref = 3": {"-1": "NEG", "0": "ZERO", "3": "THREE"},
    "Enum ref = 4": {"0": "OFF", "1": "ON", "100": "HUNDRED", "-2": "M2"},
}}
TABLE = {f[0]: ENUMS[RAW].get(f[3]) for f in FIELDS}
SIGNED = {"Rec.mode": True, "Rec.flags.kind": False, "Rec.flags.sk": True, "Rec.small": True, "Rec.noTable": True,
          "Rec.x": True, "Rec.id": False}

failures = 0


def check(cond, what):
    global failures
    if not cond:
        failures += 1
        print("FAIL:", what)


def put_bits(rec, o, w, v, big):
    v &= (1 << w) - 1
    start, end = o // 8, (o + w + 7) // 8
    nb = end - start
    if big:
        cur = int.from_bytes(rec[start:end], "big")
        sh = nb * 8 - (o % 8) - w
        cur = (cur & ~(((1 << w) - 1) << sh)) | (v << sh)
        rec[start:end] = cur.to_bytes(nb, "big")
    else:
        cur = int.from_bytes(rec[start:end], "little")
        sh = o % 8
        cur = (cur & ~(((1 << w) - 1) << sh)) | (v << sh)
        rec[start:end] = cur.to_bytes(nb, "little")


def get_bits(rec, o, w, signed, big):
    start, end = o // 8, (o + w + 7) // 8
    if big:
        v = int.from_bytes(rec[start:end], "big") >> ((end - start) * 8 - (o % 8) - w)
    else:
        v = int.from_bytes(rec[start:end], "little") >> (o % 8)
    v &= (1 << w) - 1
    if signed and v >> (w - 1):
        v -= 1 << w
    return v


def make_data(rnd, n, big):
    recs = bytearray()
    for r in range(n):
        rec = bytearray(rnd.getrandbits(8) for _ in range(STRIDE))
        for name, o, w, t in FIELDS:
            tab = TABLE[name]
            if tab and rnd.random() < 0.85:
                put_bits(rec, o, w, int(rnd.choice(list(tab))), big)
            elif name == "Rec.mode":
                put_bits(rec, o, w, rnd.choice([77, -9, 1000]), big)  # unnamed values
        recs += rec
    return bytes(recs)


def export(lib, desc, enums, raw, mode, big):
    schema = ctypes.create_string_buffer(72)   # struct ArrowSchema
    array = ctypes.create_string_buffer(80)    # struct ArrowArray
    err = ctypes.create_string_buffer(1024)
    rc = lib.nanom_layout_export_arrow(desc.encode(), enums.encode(), RAW.encode(), raw.encode(), mode,
                                       int(big), schema, array, err, len(err))
    if rc != 0:
        print("export failed:", err.value.decode())
        sys.exit(1)
    return pa.RecordBatch._import_from_c(ctypes.addressof(array), ctypes.addressof(schema))


def expected_dictionary(name, raws):
    tab = TABLE[name]
    named = sorted(((int(k), v) for k, v in tab.items()), key=lambda kv: kv[0])
    known = {k for k, _ in named}
    extra = sorted({v for v in raws if v not in known})
    return [v for _, v in named] + [str(v) for v in extra], [k for k, _ in named] + extra


def check_batch(batch, data, n, big, mode):
    names = batch.schema.names
    expect_cols = []
    for name, o, w, t in FIELDS:
        expect_cols.append(name)
        if mode == 2 and TABLE[name]:
            expect_cols.append(name + "#raw")
    check(names == expect_cols, f"columns {names}")
    for name, o, w, t in FIELDS:
        raws = [get_bits(data[r * STRIDE:(r + 1) * STRIDE], o, w, SIGNED[name], big) for r in range(n)]
        field = batch.schema.field(name)
        col = batch.column(name)
        md = {k.decode(): v.decode() for k, v in (field.metadata or {}).items()}
        tab = TABLE[name]
        if tab and mode != 1:
            check(pa.types.is_dictionary(field.type), f"{name} is {field.type}")
            dvals, draws = expected_dictionary(name, raws)
            itype = pa.int8() if len(dvals) <= 128 else pa.int16()  # Rec.small: random bytes -> > 128
            check(field.type.index_type == itype and field.type.value_type == pa.string(), f"{name} {field.type}")
            check(col.dictionary.to_pylist() == dvals, f"{name} dictionary {col.dictionary.to_pylist()} vs {dvals}")
            check(json.loads(md["nanom.enum.values"]) == draws, f"{name} values {md.get('nanom.enum.values')}")
            check(md["nanom.enum.named"] == str(len(tab)), f"{name} named")
            check(md["nanom.layout.type"] == t, f"{name} type")
            want = [tab.get(str(v), str(v)) for v in raws]
            check(col.to_pylist() == want, f"{name} names differ")
            # index -> raw via the metadata reproduces the raw column
            back = [draws[i] for i in col.indices.to_pylist()]
            check(back == raws, f"{name} index->raw")
            if mode == 2:
                check(batch.column(name + "#raw").to_pylist() == raws, f"{name}#raw values")
        else:
            check(not pa.types.is_dictionary(field.type), f"{name} should be plain, is {field.type}")
            check(col.to_pylist() == raws, f"{name} values")
            if t.startswith("Enum"):
                check(md.get("nanom.layout.type") == t, f"{name} metadata {md}")
                if tab and mode == 1:
                    check(json.loads(md["nanom.enum.names"]) == tab, f"{name} names metadata")
    check(batch.schema.field("Rec.noTable").type == pa.int16(), "noTable stays int16")


def lance_roundtrip(batch, work, tag):
    t = pa.Table.from_batches([batch])
    path = os.path.join(work, tag + ".lance")
    lance.write_dataset(t, path)
    ds = lance.dataset(path)
    back = ds.to_table()
    for f in t.schema:
        g = back.schema.field(f.name)
        check(g.type == f.type, f"lance {tag} {f.name}: {g.type} vs {f.type}")
        check((g.metadata or {}) == (f.metadata or {}), f"lance {tag} {f.name} metadata")
        check(back.column(f.name).to_pylist() == t.column(f.name).to_pylist(), f"lance {tag} {f.name} values")
    for col, name in (("Rec/mode", "UNDEF"), ("Rec/mode", "77"), ("Rec/flags/kind", "C"), ("Rec/flags/sk", "NEG")):
        got = ds.to_table(filter=f"`{col}` = '{name}'", columns=["Rec/id"]).column("Rec/id").to_pylist()
        want = [i for i, v in zip(t.column("Rec/id").to_pylist(), t.column(col).to_pylist()) if v == name]
        check(got == want and len(want) > 0, f"lance {tag} filter {col} = {name}: {len(got)} vs {len(want)} rows")
    return ds


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    lib = ctypes.CDLL(sys.argv[1])
    lib.nanom_layout_export_arrow.restype = ctypes.c_int
    lib.nanom_layout_export_arrow.argtypes = [ctypes.c_char_p] * 4 + [ctypes.c_int, ctypes.c_int] + \
        [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
    rnd = random.Random(1234)
    n = 3000
    with tempfile.TemporaryDirectory() as work:
        desc = os.path.join(work, "desc.jsonl")
        with open(desc, "w") as f:
            for name, o, w, t in FIELDS:
                f.write(json.dumps({"raw_file": RAW, "scalar_name": name, "bit_offset": o, "bit_width": w, "type": t}) + "\n")
        enums = os.path.join(work, "enums.json")
        with open(enums, "w") as f:
            json.dump(ENUMS, f)
        for big in (False, True):
            data = make_data(rnd, n, big)
            raw = os.path.join(work, "be.raw" if big else "le.raw")
            with open(raw, "wb") as f:
                f.write(data)
            for mode in (0, 1, 2):
                native = export(lib, desc, enums, raw, mode, big)
                # export_arrow's default separator: '.' between name components becomes '/'
                check(all("." not in c for c in native.schema.names), f"no '.' in Arrow names: {native.schema.names}")
                check(native.schema.names[0] == "Rec/id" and "Rec/flags/kind" in native.schema.names, "'/' names")
                batch = native.rename_columns([c.replace("/", ".") for c in native.schema.names])
                check(batch.num_rows == n, "rows")
                check_batch(batch, data, n, big, mode)
                if mode != 1:
                    lance_roundtrip(native, work, f"{'be' if big else 'le'}{mode}")
        # empty input: dictionary columns with the table only
        empty = os.path.join(work, "empty.raw")
        open(empty, "wb").close()
        batch = export(lib, desc, enums, empty, 0, False)
        check(batch.num_rows == 0 and batch.column("Rec/mode").dictionary.to_pylist() ==
              ["UNDEF", "IMG1", "IMG2", "IMG3", "IMG4", "IMG5", "IMG6"], "empty input")
        stats = lance.dataset(os.path.join(work, "le0.lance")).schema
        print("lance schema (le, dictionary):", ", ".join(f"{f.name}: {f.type}" for f in stats))
    if failures:
        print(f"{failures} failure(s)")
        return 1
    print("layout Arrow/Lance enum check: all passed (2 byte orders x 3 enum modes, %d rows each)" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
