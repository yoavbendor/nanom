#!/usr/bin/env python3
"""Differential test: nanom's reflected Parquet Thrift model vs pyarrow, on real files.

Writes a matrix of Parquet files with pyarrow (codecs, dictionary on/off, data page v1/v2, many row
groups, nested and logical types, key/value metadata, page index), runs examples/parquet_meta on
each, and checks every decoded fact against pyarrow's own reading of the same footer:

  * file: num_rows, created_by, key/value metadata, row-group count
  * schema: leaf names, physical types, logical-type kinds
  * column chunks: path, physical type, codec, num_values, sizes, page offsets, encodings,
    statistics null counts
  * pages: walking every page header of every chunk lands exactly on the chunk end, and the data
    pages' num_values sum to the chunk's num_values; the OffsetIndex page count matches.

usage: parquet_differential.py /path/to/parquet_meta
Exits 0 on agreement, 1 on any mismatch, 77 (ctest "skipped") when pyarrow is unavailable.
"""
import datetime
import decimal
import json
import os
import subprocess
import sys
import tempfile

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
except ImportError:
    print("pyarrow not installed: skipping")
    sys.exit(77)

PHYSICAL = {"BOOLEAN": 0, "INT32": 1, "INT64": 2, "INT96": 3, "FLOAT": 4, "DOUBLE": 5,
            "BYTE_ARRAY": 6, "FIXED_LEN_BYTE_ARRAY": 7}
# pyarrow reports LZ4_RAW (id 7, what it writes) under the name "LZ4"
CODEC = {"UNCOMPRESSED": {0}, "SNAPPY": {1}, "GZIP": {2}, "LZO": {3}, "BROTLI": {4}, "LZ4": {5, 7},
         "ZSTD": {6}, "LZ4_RAW": {7}}
ENCODING = {"PLAIN": 0, "PLAIN_DICTIONARY": 2, "RLE": 3, "BIT_PACKED": 4,
            "DELTA_BINARY_PACKED": 5, "DELTA_LENGTH_BYTE_ARRAY": 6, "DELTA_BYTE_ARRAY": 7,
            "RLE_DICTIONARY": 8, "BYTE_STREAM_SPLIT": 9}
# pyarrow's LogicalType.type names -> the LogicalType union member nanom decodes
LOGICAL = {"STRING": "STRING", "DATE": "DATE", "TIMESTAMP": "TIMESTAMP", "DECIMAL": "DECIMAL",
           "INT": "INTEGER", "TIME": "TIME", "LIST": "LIST", "MAP": "MAP", "JSON": "JSON",
           "UUID": "UUID", "FLOAT16": "FLOAT16", "NULL": "UNKNOWN", "ENUM": "ENUM", "BSON": "BSON"}


def make_table(n):
    return pa.table({
        "id": pa.array(range(n), pa.int64()),
        "small": pa.array([i % 7 for i in range(n)], pa.int8()),
        "u32": pa.array([i * 3 for i in range(n)], pa.uint32()),
        "f": pa.array([i * 0.5 if i % 5 else None for i in range(n)], pa.float64()),
        "name": pa.array([f"name-{i % 13}" if i % 4 else None for i in range(n)], pa.string()),
        "flag": pa.array([i % 3 == 0 for i in range(n)], pa.bool_()),
        "ts": pa.array([datetime.datetime(2026, 1, 1) + datetime.timedelta(seconds=i)
                        for i in range(n)], pa.timestamp("us", tz="UTC")),
        "day": pa.array([datetime.date(2026, 1, 1) + datetime.timedelta(days=i % 30)
                         for i in range(n)], pa.date32()),
        "dec": pa.array([decimal.Decimal(i) / 100 for i in range(n)], pa.decimal128(12, 2)),
        "mac": pa.array([bytes([i % 256] * 6) for i in range(n)], pa.binary(6)),
        "tags": pa.array([[f"t{j}" for j in range(i % 4)] for i in range(n)],
                         pa.list_(pa.string())),
        "pt": pa.array([{"x": i, "y": -i} for i in range(n)],
                       pa.struct([("x", pa.int32()), ("y", pa.int32())])),
    })


CONFIGS = [
    dict(compression="none"),
    dict(compression="snappy"),
    dict(compression="zstd", use_dictionary=False),
    dict(compression="gzip", data_page_version="2.0"),
    dict(compression="snappy", row_group_size=97, data_page_size=512, write_page_index=True),
    dict(compression="lz4", write_statistics=False),
    dict(compression="none", use_byte_stream_split=["f"], use_dictionary=["name"]),
    dict(compression="none", column_encoding={"id": "DELTA_BINARY_PACKED"}, use_dictionary=False),
]


def check(cond, msg, errors):
    if not cond:
        errors.append(msg)


def compare(path, got, errors):
    md = pq.ParquetFile(path).metadata
    where = os.path.basename(path)
    check(got["num_rows"] == md.num_rows, f"{where}: num_rows", errors)
    check(got["created_by"] == md.created_by, f"{where}: created_by", errors)
    kv = {k.decode(): v.decode() for k, v in (md.metadata or {}).items()}
    check(got["key_value_metadata"] == kv, f"{where}: key_value_metadata", errors)

    leaves = [e for e in got["schema"][1:] if e["num_children"] is None]
    check(len(leaves) == md.num_columns, f"{where}: leaf count", errors)
    for i, e in enumerate(leaves[:md.num_columns]):
        col = md.schema.column(i)
        check(e["name"] == col.name, f"{where}: leaf {i} name", errors)
        check(e["type"] == PHYSICAL[col.physical_type], f"{where}: leaf {i} type", errors)
        lt = col.logical_type.type.upper()
        want = None if lt == "NONE" else LOGICAL.get(lt, lt)
        check(e["logical"] == want, f"{where}: leaf {i} logical {lt} vs {e['logical']}", errors)

    check(len(got["row_groups"]) == md.num_row_groups, f"{where}: row group count", errors)
    for r, grg in enumerate(got["row_groups"]):
        rg = md.row_group(r)
        check(grg["num_rows"] == rg.num_rows, f"{where}: rg{r} num_rows", errors)
        check(grg["total_byte_size"] == rg.total_byte_size, f"{where}: rg{r} total_byte_size", errors)
        check(len(grg["columns"]) == rg.num_columns, f"{where}: rg{r} column count", errors)
        for c, gc in enumerate(grg["columns"]):
            cc = rg.column(c)
            tag = f"{where}: rg{r} col{c}"
            check(".".join(gc["path"]) == cc.path_in_schema, f"{tag} path", errors)
            check(gc["type"] == PHYSICAL[cc.physical_type], f"{tag} type", errors)
            check(gc["codec"] in CODEC[cc.compression], f"{tag} codec", errors)
            check(gc["num_values"] == cc.num_values, f"{tag} num_values", errors)
            check(gc["total_compressed_size"] == cc.total_compressed_size, f"{tag} compressed", errors)
            check(gc["total_uncompressed_size"] == cc.total_uncompressed_size, f"{tag} uncompressed",
                  errors)
            check(gc["data_page_offset"] == cc.data_page_offset, f"{tag} data_page_offset", errors)
            if cc.has_dictionary_page:
                check(gc["dictionary_page_offset"] == cc.dictionary_page_offset, f"{tag} dict offset",
                      errors)
            check(sorted(gc["encodings"]) == sorted(ENCODING[e] for e in cc.encodings),
                  f"{tag} encodings {gc['encodings']} vs {cc.encodings}", errors)
            if cc.is_stats_set and cc.statistics.has_null_count:
                check("stats" in gc and gc["stats"]["null_count"] == cc.statistics.null_count,
                      f"{tag} null_count", errors)
            # the page walk must account for every value in the chunk
            check(gc["pages"]["values"] == cc.num_values,
                  f"{tag} page values {gc['pages']['values']} vs {cc.num_values}", errors)
            check(gc["pages"]["dictionary"] == (1 if cc.has_dictionary_page else 0),
                  f"{tag} dictionary pages", errors)
            if cc.has_offset_index:
                check(gc.get("offset_index_pages") == gc["pages"]["data"], f"{tag} offset index",
                      errors)


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    tool = sys.argv[1]
    errors = []
    files = 0
    with tempfile.TemporaryDirectory() as d:
        for i, cfg in enumerate(CONFIGS):
            table = make_table(1000)
            table = table.replace_schema_metadata({"origin": "nanom-differential", "case": str(i)})
            path = os.path.join(d, f"case{i}.parquet")
            try:
                pq.write_table(table, path, **cfg)
            except (TypeError, ValueError, pa.ArrowException) as e:
                print(f"case{i}: pyarrow cannot write {cfg} ({e}); skipped")
                continue
            res = subprocess.run([tool, path], capture_output=True, text=True)
            if res.returncode != 0:
                errors.append(f"case{i} {cfg}: parquet_meta failed: {res.stderr.strip()}")
                continue
            compare(path, json.loads(res.stdout), errors)
            files += 1
    for e in errors:
        print("MISMATCH", e)
    print(f"parquet differential: {files} files, {len(errors)} mismatches")
    return 1 if errors or files == 0 else 0


if __name__ == "__main__":
    sys.exit(main())
