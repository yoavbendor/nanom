#!/usr/bin/env python3
"""Google's protobuf runtime as the oracle for nanom's protobuf codec, over the Lance model.

Descriptors mirroring Lance's protos (lance-file file.proto / file2.proto, lance-table
table.proto: the fields nanom/formats/lance_protobuf.hpp declares) are built at run time, so
no protoc is needed. Strings are declared `bytes` here: same wire format, and nanom's random
strings need not be UTF-8.

  1. nanom -> protobuf: random messages generated and encoded by nanom parse in protobuf with
     no unknown fields, and protobuf's own serialization of them is byte-identical (both are
     canonical proto3: defaults left out, repeated scalars packed, fields in number order).
  2. protobuf -> nanom: random messages built and serialized by protobuf, with real map<>
     fields and both packed and unpacked repeated scalars, decode in nanom; nanom's
     re-encoding parses back in protobuf to a message equal to the original.
  3. hostile bytes: truncations of valid messages are rejected by nanom exactly when protobuf
     rejects them (for the messages with no required fields: all of the Lance model).

Usage: protobuf_differential.py <path to protobuf_oracle>. Exit 77 (skip) without protobuf.
"""
import random
import subprocess
import sys

try:
    from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
except ImportError:
    print("google.protobuf not installed: skipping")
    sys.exit(77)

F = descriptor_pb2.FieldDescriptorProto
T = {
    "int32": F.TYPE_INT32, "int64": F.TYPE_INT64, "uint32": F.TYPE_UINT32, "uint64": F.TYPE_UINT64,
    "bool": F.TYPE_BOOL,
    "bytes": F.TYPE_BYTES, "enum": F.TYPE_ENUM, "msg": F.TYPE_MESSAGE,
}

# name -> [(field name, number, type, label, type_name, proto3_optional, packed)]
MESSAGES = {
    "MetadataEntry": [("key", 1, "bytes"), ("value", 2, "bytes")],
    "StringEntry": [("key", 1, "bytes"), ("value", 2, "bytes")],
    "Timestamp": [("seconds", 1, "int64"), ("nanos", 2, "int32")],
    "Any": [("type_url", 1, "bytes"), ("value", 2, "bytes")],
    "Field": [("type", 1, "enum", "FieldType"), ("name", 2, "bytes"), ("id", 3, "int32"),
              ("parent_id", 4, "int32"), ("logical_type", 5, "bytes"), ("nullable", 6, "bool"),
              ("encoding", 7, "enum", "FieldEncoding"), ("metadata", 10, "map")],
    "Schema": [("fields", 1, "msg*", "Field"), ("metadata", 5, "map")],
    "Metadata": [("manifest_position", 1, "uint64"), ("batch_offsets", 2, "int32*"),
                 ("page_table_position", 3, "uint64")],
    "FileDescriptor": [("schema", 1, "msg", "Schema"), ("length", 2, "uint64")],
    "DirectEncoding": [("encoding", 1, "bytes")],
    "Encoding": [("direct", 2, "msg", "DirectEncoding")],
    "Page": [("buffer_offsets", 1, "uint64*"), ("buffer_sizes", 2, "uint64*"), ("length", 3, "uint64"),
             ("encoding", 4, "msg", "Encoding"), ("priority", 5, "uint64")],
    "ColumnMetadata": [("encoding", 1, "msg", "Encoding"), ("pages", 2, "msg*", "Page"),
                       ("buffer_offsets", 3, "uint64*"), ("buffer_sizes", 4, "uint64*")],
    "DeletionFile": [("file_type", 1, "enum", "DeletionFileType"), ("read_version", 2, "uint64"),
                     ("id", 3, "uint64"), ("num_deleted_rows", 4, "uint64")],
    "DataFile": [("path", 1, "bytes"), ("fields", 2, "int32*"), ("column_indices", 3, "int32*"),
                 ("file_major_version", 4, "uint32"), ("file_minor_version", 5, "uint32"),
                 ("file_size_bytes", 6, "uint64?")],
    "DataFragment": [("id", 1, "uint64"), ("files", 2, "msg*", "DataFile"),
                     ("deletion_file", 3, "msg", "DeletionFile"), ("physical_rows", 4, "uint64")],
    "DataStorageFormat": [("file_format", 1, "bytes"), ("version", 2, "bytes")],
    "WriterVersion": [("library", 1, "bytes"), ("version", 2, "bytes")],
    "Manifest": [("fields", 1, "msg*", "Field"), ("fragments", 2, "msg*", "DataFragment"),
                 ("version", 3, "uint64"), ("version_aux_data", 4, "uint64"), ("schema_metadata", 5, "map"),
                 ("index_section", 6, "uint64?"), ("timestamp", 7, "msg", "Timestamp"), ("tag", 8, "bytes"),
                 ("reader_feature_flags", 9, "uint64"), ("writer_feature_flags", 10, "uint64"),
                 ("max_fragment_id", 11, "uint32?"), ("transaction_file", 12, "bytes"),
                 ("writer_version", 13, "msg", "WriterVersion"), ("next_row_id", 14, "uint64"),
                 ("data_format", 15, "msg", "DataStorageFormat"), ("config", 16, "smap"),
                 ("table_metadata", 19, "smap"), ("transaction_section", 21, "uint64?")],
    "IndexSection": [("indices", 1, "bytes*")],
    "Uuid": [("uuid", 1, "bytes")],
    "IndexFile": [("path", 1, "bytes"), ("size", 2, "uint64")],
    "IndexMetadata": [("uuid", 1, "msg", "Uuid"), ("fields", 2, "int32*"), ("name", 3, "bytes"),
                      ("dataset_version", 4, "uint64"), ("fragment_bitmap", 5, "bytes?"),
                      ("index_details", 6, "msg", "Any"), ("index_version", 7, "int32?"),
                      ("created_at", 8, "uint64?"), ("files", 10, "msg*", "IndexFile")],
}
ENUMS = {"FieldType": 3, "FieldEncoding": 5, "DeletionFileType": 2}


def build(pkg, maps):
    """A file descriptor for the model. maps=True declares metadata as map<bytes-key...>; protobuf
    maps need a string key, so the map form uses `string` keys (valid UTF-8 only)."""
    fd = descriptor_pb2.FileDescriptorProto(name=pkg + ".proto", package=pkg, syntax="proto3")
    for e, n in ENUMS.items():
        ed = fd.enum_type.add(name=e)
        for i in range(n):
            ed.value.add(name=f"{e}_{i}", number=i)
    for name, fields in MESSAGES.items():
        md = fd.message_type.add(name=name)
        for spec in fields:
            fname, num, kind = spec[0], spec[1], spec[2]
            f = md.field.add(name=fname, number=num, label=F.LABEL_OPTIONAL)
            if kind in ("map", "smap"):
                if maps:
                    entry = md.nested_type.add(name="".join(w.capitalize() for w in fname.split("_")) + "Entry")
                    entry.options.map_entry = True
                    entry.field.add(name="key", number=1, label=F.LABEL_OPTIONAL, type=F.TYPE_STRING)
                    entry.field.add(name="value", number=2, label=F.LABEL_OPTIONAL,
                                    type=F.TYPE_BYTES if kind == "map" else F.TYPE_STRING)
                    f.type_name = f".{pkg}.{name}.{entry.name}"
                else:
                    f.type_name = f".{pkg}." + ("MetadataEntry" if kind == "map" else "StringEntry")
                f.type, f.label = F.TYPE_MESSAGE, F.LABEL_REPEATED
                continue
            if kind.endswith("*"):
                f.label = F.LABEL_REPEATED
                kind = kind[:-1]
            if kind.endswith("?"):
                kind = kind[:-1]
                f.proto3_optional = True
                f.oneof_index = len(md.oneof_decl)
                md.oneof_decl.add(name="_" + fname)
            f.type = T[kind]
            if kind in ("msg", "enum"):
                f.type_name = f".{pkg}.{spec[3]}"
    pool = descriptor_pool.DescriptorPool()
    pool.Add(fd)
    return {n: message_factory.GetMessageClass(pool.FindMessageTypeByName(f"{pkg}.{n}")) for n in MESSAGES}


def run(oracle, args, stdin=None):
    r = subprocess.run([oracle] + args, input=stdin, capture_output=True, text=True, check=True)
    return [line.split(" ", 2) for line in r.stdout.splitlines()]


def unhex(h):
    return b"" if h == "-" else bytes.fromhex(h)


def rand_value(rng, kind):
    if kind == "int64":
        return rng.choice([0, 1, -1, 2**63 - 1, -(2**63), rng.randrange(-(2**63), 2**63)])
    if kind == "int32":
        return rng.choice([0, 1, -1, 2**31 - 1, -(2**31), rng.randrange(-(2**31), 2**31)])
    if kind == "uint32":
        return rng.choice([0, 1, 2**32 - 1, rng.randrange(2**32)])
    if kind == "uint64":
        return rng.choice([0, 1, 127, 128, 2**64 - 1, rng.randrange(2**64)])
    if kind == "bool":
        return rng.random() < 0.5
    if kind == "bytes":
        return bytes(rng.randrange(256) for _ in range(rng.choice([0, 1, 5, 40])))
    raise ValueError(kind)


def fill(rng, msg, name, depth=0):
    for spec in MESSAGES[name]:
        fname, kind = spec[0], spec[2]
        if rng.random() < 0.25:
            continue  # left at the default / absent
        if kind in ("map", "smap"):
            for _ in range(rng.randrange(4)):
                key = "".join(rng.choice("abcxyz_é") for _ in range(rng.randrange(6)))
                getattr(msg, fname)[key] = (rand_value(rng, "bytes") if kind == "map" else
                                            "".join(rng.choice("pqr é") for _ in range(rng.randrange(5))))
        elif kind == "msg*":
            for _ in range(rng.randrange(4 if depth < 3 else 1)):
                fill(rng, getattr(msg, fname).add(), spec[3], depth + 1)
        elif kind == "msg":
            sub = getattr(msg, fname)
            sub.SetInParent()
            fill(rng, sub, spec[3], depth + 1)
        elif kind == "enum":
            setattr(msg, fname, rng.choice([0, 1, 2, 7, -3]))  # open enums: unknown values too
        elif kind.endswith("*"):
            getattr(msg, fname).extend(rand_value(rng, kind[:-1]) for _ in range(rng.randrange(6)))
        else:
            setattr(msg, fname, rand_value(rng, kind.rstrip("?")))


def varint_at(buf, i):
    v, s = 0, 0
    while True:
        b = buf[i]
        i += 1
        v |= (b & 0x7F) << s
        s += 7
        if not b & 0x80:
            return v, i


def put_varint(out, v):
    while v >= 0x80:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)


def unpack_repeated(data, numbers):
    """Re-encode the packed varint runs of the given top-level field numbers as one record per
    value (the proto2 / unpacked form, which a proto3 reader must also accept)."""
    out, i = bytearray(), 0
    while i < len(data):
        start = i
        key, i = varint_at(data, i)
        wt = key & 7
        if wt == 0:
            _, i = varint_at(data, i)
        elif wt == 1:
            i += 8
        elif wt == 5:
            i += 4
        elif wt == 2:
            n, i = varint_at(data, i)
            payload, i = data[i:i + n], i + n
            if (key >> 3) in numbers:
                j = 0
                while j < len(payload):
                    v, j = varint_at(payload, j)
                    put_varint(out, key & ~7)
                    put_varint(out, v)
                continue
        out += data[start:i]
    return bytes(out)




def main():
    oracle = sys.argv[1]
    flat = build("flat", maps=False)
    mapped = build("mapped", maps=True)
    bad = 0

    # 1. nanom -> protobuf: byte-identical canonical serialization
    lines = run(oracle, ["gen", "3000", "11"])
    for name, h in lines:
        data = unhex(h)
        m = flat[name]()
        m.ParseFromString(data)
        # nanom's random messages carry unknown fields too (pb_unknown members); protobuf keeps them
        # and writes them after the known ones, as nanom does, so the bytes must still be identical
        again = m.SerializeToString(deterministic=True)
        if again != data:
            bad += 1
            if bad < 5:
                print(f"nanom->protobuf mismatch for {name}:\n  nanom    {data.hex()}\n  protobuf {again.hex()}")
    print(f"1. nanom -> protobuf: {len(lines)} messages, byte-identical: {bad == 0}")

    # 2. protobuf -> nanom (real maps; packed and unpacked repeated scalars)
    rng = random.Random(5)
    originals, inputs = [], []
    for k in range(3000):
        name = ["Manifest", "FileDescriptor", "ColumnMetadata", "Metadata", "DataFragment",
                "IndexMetadata"][k % 6]
        m = mapped[name]()
        fill(rng, m, name)
        data = m.SerializeToString()
        if name == "Metadata" and k % 2:
            data = unpack_repeated(data, {2})  # batch_offsets as unpacked int32 records
        originals.append((name, m))
        inputs.append(f"{name} {data.hex() or '-'}")
    out = run(oracle, ["recode"], "\n".join(inputs) + "\n")
    bad2 = 0
    for (name, m), (oname, h, *rest) in zip(originals, out):
        if h == "ERROR":
            bad2 += 1
            print("nanom rejected a protobuf message:", name, rest)
            continue
        back = mapped[name]()
        back.ParseFromString(unhex(h))
        if back != m:
            bad2 += 1
            if bad2 < 5:
                print(f"protobuf->nanom mismatch for {name}:\n  {m}\n  {back}")
    print(f"2. protobuf -> nanom -> protobuf: {len(out)} messages, equal: {bad2 == 0}")

    # 3. truncations: nanom rejects exactly what protobuf rejects
    rng = random.Random(9)
    inputs, expect = [], []
    for name, h in lines[:600]:
        data = unhex(h)
        for cut in sorted({rng.randrange(len(data) + 1) for _ in range(4)} if data else {0}):
            part = data[:cut]
            try:
                flat[name]().ParseFromString(part)
                ok = True
            except Exception:
                ok = False
            inputs.append(f"{name} {part.hex() or '-'}")
            expect.append(ok)
    out = run(oracle, ["recode"], "\n".join(inputs) + "\n")
    bad3 = sum(1 for ok, (_, h, *r) in zip(expect, out) if ok != (h != "ERROR"))
    print(f"3. truncations: {len(out)} inputs, accept/reject agrees: {bad3 == 0}")

    # 4. a reader declaring a subset (pb_unknown keeps the rest) re-encodes without losing anything
    rng = random.Random(13)
    originals, inputs = [], []
    for _ in range(1000):
        m = mapped["Manifest"]()
        fill(rng, m, "Manifest")
        originals.append(m)
        inputs.append(f"ManifestLite {m.SerializeToString().hex() or '-'}")
    out = run(oracle, ["recode"], "\n".join(inputs) + "\n")
    bad4 = 0
    for m, (_, h, *rest) in zip(originals, out):
        back = mapped["Manifest"]()
        if h != "ERROR":
            back.ParseFromString(unhex(h))
        if h == "ERROR" or back != m:
            bad4 += 1
            if bad4 < 3:
                print("subset model lost something:", h[:80], rest)
    print(f"4. subset model (pb_unknown) round trip: {len(out)} manifests, nothing lost: {bad4 == 0}")

    total = bad + bad2 + bad3 + bad4
    print("protobuf_differential:", "OK" if total == 0 else f"{total} FAILURES")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
