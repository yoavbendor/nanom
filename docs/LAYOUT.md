# Raw records from a JSON layout description

`#include <nanom/layout.hpp>` decodes binary files that hold "one structure after the other", given a
JSON Lines description of the structure's scalars:

```json
{"raw_file":"/dev/vdiZ/pacemaker/gfi.raw","scalar_name":"GFI.grab_index","bit_offset":0,"bit_width":32,"type":"UInt"}
{"raw_file":"/dev/vdiZ/pacemaker/gfi.raw","scalar_name":"GFI.brain_type","bit_offset":96,"bit_width":32,"type":"Enum ref = 1"}
{"raw_file":"/proc/app/devices.raw","scalar_name":"MEIO::IOAppDevices._uartWrite.array_item_1._cntMEVSA_UARTLog._total.int>._M_i","bit_offset":471872,"bit_width":32,"type":"UInt"}
```

and an optional enum file `{ raw_file: { "Enum ref = N": { "value": "NAME", ... } } }`.

```cpp
namespace lay = nanom::layout;
auto desc  = lay::load_description("desc.jsonl").value();        // JSON Lines, untrusted-safe
auto enums = lay::load_enums("enums.json").value();               // optional
auto plan  = lay::plan::compile(desc, "/dev/vdiZ/pacemaker/gfi.raw", &enums).value();
auto t     = lay::decode(plan, bytes).value();                    // one typed column per scalar
std::span<const uint32_t> grab = t.column<uint32_t>("GFI[1].grab_index");
auto brain = plan.find("GFI.brain_type").value();                 // precomputed handle
for (auto rec : plan.records(bytes)) use(rec.get<int>(brain));    // random access, no strings
lay::export_jsonl(plan, bytes, sink, plan.select({"GFI[1]"}).value());  // nested JSON Lines
```

`bytes` is any `std::span<const std::byte>` (the CLI mmaps the file); nothing is copied. Loaders
return `nanom::expected<T, layout_error>` — `std::expected` where the toolchain has it (`.value()` as
above); on toolchains using nanom's minimal fallback, test it and use `*` / `->`.

## Pieces

| header | what |
|---|---|
| `layout/json.hpp` | a small JSON DOM reader written with nanom's own combinators (`chr`, `alt`, `delimited`, `separated_list0`, `fold_many0`, `recognize`, `cut`); depth-limited, every value keeps its byte offset for line:column errors |
| `layout/desc.hpp` | `load_description` / `parse_description` (JSONL or one JSON array; whitespace, key order, extra keys, blank and `#`/`//` lines tolerated), `classify_type`, `load_enums` / `parse_enums`, `layout_error` (`source:line:column: message`) |
| `layout/plan.hpp` | `plan::compile`: stride, per-field load (`access`), storage type, sign extension, enum table, the name tree, `find` → `field_handle`, `select`, `records` → `record_set` / `record` |
| `layout/decode.hpp` | `decoder` (compiled op list per selection), `decode` → library-owned `table`, `decode_into` → caller buffers, `decode_options` (record range, partial-record policy, schedule) |
| `layout/export.hpp` | `jsonl_writer`, `csv_writer`, `export_jsonl`, `export_csv` |
| `layout/arrow.hpp` | `export_arrow(table&&, ArrowSchema*, ArrowArray*)` — Arrow C Data Interface, struct of columns, zero-copy for numeric columns |

## The rules (assumptions to confirm are marked ⚠)

**Types.** Matching ignores case, blanks and underscores. Families: unsigned (`UInt UChar UShort
ULong ULongLong Byte unsigned uint8_t UInteger*N`), signed (`Int Char SChar Short Long LongLong
Integer*N`), float (`Float Double Real*4 Real*8`, width must be 32/64), bool (`Logical*N Bool
Boolean` — nonzero is true), pointer (`*Anything` or `Anything*`, printed as `"0x…"`), enum (`Enum
ref = N`). The name also implies a declared storage size (UChar=1 … ULongLong=8, Logical*4=4) used
for alignment and a width sanity check. Unknown types are an error with line and column in strict
mode (default) and raw unsigned bits plus a warning in lenient mode. ⚠ `Char` is signed (x86);
`Long` is 8 bytes (LP64) for alignment purposes only — the width in the description always wins.

**Bits.** Little-endian (default): bit `bit_offset` is bit `bit_offset % 8` (LSB = 0) of byte
`bit_offset / 8`, and a field spans consecutive bits upward — GCC/x86 bit-field order. Big-endian
(`compile_options::order`, CLI `--big-endian`): bits are numbered MSB-first within big-endian bytes
(GCC on big-endian targets), so byte-aligned 8/16/32/64-bit fields are plain big-endian loads.
Widths 1..64; a field may straddle 9 bytes (packed structs).

**Signedness.** Signed families are sign-extended from `bit_width`. Enums are signed (`-1 = UNDEF`)
when byte-aligned 8/16/32/64; an enum **bit-field** is signed only if its enum table has a negative
value (GCC gives an enum without negatives an unsigned underlying type). ⚠

**Stride (record size).** Default: `ceil(max(bit_offset + bit_width) / 8)` rounded up to the
largest field alignment — the C struct rule. A byte-aligned 8/16/32/64-bit field aligns to its
width; a bit-field to its declared type's size (`UInt:3` → 4; enum bit-fields → 4); capped at 8.
GFI: 37 bytes used, alignment 4 → 40. Override for every raw_file (`compile_options::stride`, CLI
`--stride`) or per raw_file (`compile_options::stride_by_file`, CLI `--stride-for NAME=N`). A stride
below the bytes the fields cover is an error. ⚠ If the description omits trailing members (padding
the exporter did not list), the default stride is too small — the trailing-partial-record error is
how you notice; pass the real size.

**Trailing partial record.** `records()` never hands it out; `decode`/`export_*` return an error
naming the whole-record count and the leftover bytes unless `decode_options::allow_partial` (CLI
`--allow-partial`) — then it is ignored and reported (`table::tail_bytes()`).

**Names.** Split on `.` only: `MEIO::IOAppDevices._board.Diagnostics::DeviceStatus._state` →
`MEIO::IOAppDevices` / `_board` / `Diagnostics::DeviceStatus` / `_state`;
`…lastFSTimestamp.long>._M_i` keeps `long>` as a component. Empty components are an error (strict).
A name that is both a scalar and a parent of other scalars is an error in strict mode; lenient emits
the scalar as `"_value"` inside the object.

**Arrays.** If *all* children of a node are `array_item_N`, the node is a JSON array ordered by N,
starting at the smallest N present; missing indices in between are `null` (`array_item_0`,
`array_item_2` → `[x, null, y]`; `array_item_1..9` → 9 elements). ⚠ The column names keep the
original `array_item_N` text, so N is never lost.

**Repeated names = implicit arrays.** When the same `scalar_name` appears at several offsets, its
k-th occurrence is the k-th in (bit_offset, line) order. The array is placed at the *highest*
component whose whole subtree repeats the same number of times: GFI's five names each appear twice,
so `GFI` becomes `"GFI":[{…},{…}]` and columns are named `GFI[0].grab_index` … `GFI[1].BlackDummy`.
If only one leaf repeats, the array is that leaf (`"x":[1,2]`, column `A.x[0]`). `plan::find` and
selections accept both the column name and the plain scalar name (first occurrence). ⚠

**Selections** (`plan::select`, CLI `--select`, repeatable): a pattern with `*`/`?` is a glob over
the whole name; otherwise it matches exactly or as a subtree (`A.b` selects `A.b.c` and `A.b[1].c`);
a pattern ending in `.`, `:` or `[` is a plain prefix. Both scalar and column names are tested. A
pattern that selects nothing is an error (typos must not silently produce empty output). Projected
JSON keeps array positions: unselected elements before the last selected one are `null`.

**JSON output.** One object per record following the tree; enum values print their name (number
when unnamed); pointers `"0x1f…"`; booleans `true/false`; floats in shortest round-trip form,
always with a `.` or exponent (`1.0`, `-0.0`); NaN/Inf → `null`. CSV: header of column names, one
row per record, the same values unquoted (`nan`, `inf` for non-finite floats).

## Safety

The description and the enum file are untrusted: depth-limited JSON (64), control characters and
bad escapes refused, `bit_width` 1..64, offsets beyond `max_record_bytes` (1 GiB default) refused,
duplicates refused, floats must be 32/64 bits. `plan::compile` then proves that every field's load
(`access::off + load_bytes() <= stride`, including the 8-byte windows used for bit-fields, which are
slid back inside short records) stays inside the record, and records only exist for whole
`stride`-byte slices of the input. The hot loops therefore run without checks and still cannot read
out of bounds. Union-style overlapping fields are allowed. `decode_into` checks every caller buffer
size before the unchecked run. Unit tests run under ASan/UBSan; the oracle also runs against an
ASan/UBSan build of the CLI.

## How the decode is organized (and why)

`plan::compile` gives every field one `access`: a byte offset, a load mode (`n8/n16/n32/n64` for
byte-aligned natural fields; `bits64` = one 8-byte load + shift, the window slid back so it never
passes the record end; `bits72` for 9-byte straddlers; `small` for records shorter than 8 bytes), a
shift, the width and the sign flag. A `decoder` (built per selection) maps each field to a function
pointer specialized on (mode, byte order, sign, column type): the per-value inner loop is a straight
load / shift / store with no branch.

Two schedules run the same kernels:

* **field-major** (default): records go in blocks (~1 MiB, at least 32 records); inside a block each
  field runs its own strided loop over the block's records and writes its column sequentially.
* **record-major**: per record, one pass over each kernel bucket, one element written into every
  column.

Field-major wins everywhere, and by 2.7x on the devices record: record-major writes one element into
each of 8000 columns per record, i.e. 8000 different pages per record (TLB and cache-line churn).
The same is true of the hand-written static decoder, so the benchmark reports its record-major and
field-major forms and uses the faster as the ceiling. The block floor of 32 records matters for huge
records (59 KB): with only 8 records per block (an L2-sized block) per-field loop overhead dominated
(5.6 ns/value vs 1.9 ns/value at ≥ 32 records).

## Benchmarks

`bench/layout_bench.cpp` defines both layouts once as constexpr tables; the bench writes the JSON
description nanom loads at run time *and* instantiates a static decoder in which every offset, shift,
mask and type is a compile-time constant (what a generator emitting a C++ struct + loads gives).
`naive interpreter` is the obvious runtime approach: per record, per field, `switch` on the type,
generic bit assembly, `switch` on the column width. All columns are compared byte-for-byte against
the static decoder before timing counts. Output buffers are preallocated and pre-touched
(`decode_into`), except the `decode()` row, which includes allocating and first-touching the table.

Machine: 4-core Xeon @ 2.1 GHz VM (48 KB L1d, 2 MB L2 per core), GCC 13.3 `-O2`, single thread,
shared with two other agents' builds; numbers move ±15% between invocations.

GCC 13.3 `-O2`, best of 3 invocations x 7 runs:

| layout | contender | ms | input GB/s | records/s | ns/value | vs static |
|---|---|---:|---:|---:|---:|---:|
| gfi (4 M x 40 B, 10 fields) | static decoder, record-major | 32.1 | 4.98 | 124 M | 0.80 | **1.00** |
| | static decoder, field-major | 35.1 | 4.56 | 114 M | 0.88 | 1.09 |
| | naive interpreter | 87.8 | 1.82 | 46 M | 2.19 | 2.73 |
| | **nanom (field-major = automatic)** | 37.2 | 4.30 | 108 M | 0.93 | **1.16** |
| | nanom record-major | 50.8 | 3.15 | 79 M | 1.27 | 1.58 |
| | nanom `decode()` incl. allocation + page faults | 81.3 | 1.97 | 49 M | 2.03 | 2.53 |
| | nanom projection, 1 of 10 fields | 13.1 | (12.2) | 305 M | 3.3 per selected value | — |
| | nanom JSON Lines export (200 k records) | 37.1 | — | 5.4 M | 18.5 | 1.28 GB/s of JSON |
| | memcpy of the input | 25.4 | 6.30 | 158 M | — | — |
| devices (2000 x 69 KB, 8000 fields) | static decoder, record-major | 70.0 | 1.97 | 28.6 k | 4.37 | 1.94 |
| | static decoder, field-major | 36.0 | 3.83 | 55.5 k | 2.25 | **1.00** |
| | naive interpreter | 97.4 | 1.42 | 20.5 k | 6.09 | 2.70 |
| | **nanom (field-major = automatic)** | 35.9 | 3.84 | 55.6 k | 2.25 | **1.00** |
| | nanom record-major | 86.2 | 1.60 | 23.2 k | 5.39 | 2.39 |
| | nanom `decode()` incl. allocation + page faults | 50.6 | 2.73 | 39.6 k | 3.16 | 1.40 |
| | nanom projection, 100 of 8000 fields (1.25%) | 0.164 | (842) | 12.2 M | 0.82 per selected value | 0.46% of full |
| | nanom JSON Lines export (100 records) | 24.6 | — | 4.1 k | 30.7 | 0.61 GB/s of JSON |
| | memcpy of the input | 18.0 | 7.68 | 111 k | — | — |

Clang 18 `-O2` (one invocation x 7): gfi nanom 0.90 ns/value vs static 0.82 (1.10x); devices 2.66
vs 2.32 (1.15x).

Reading it: the full columnar decode is memory-bound — the devices run reads 138 MB and writes
~67 MB of columns in 36 ms, i.e. ~5.7 GB/s of traffic against ~15 GB/s for memcpy's read+write; the
GFI run reads 160 MB and writes 136 MB. nanom's runtime plan matches the compile-time decoder on the
huge record and is within 1.1-1.2x on the 40-byte one, where the static code keeps all ten column
pointers in registers and runs one loop. The naive interpreter (what you get by writing the obvious
`switch` per field) is 2.7x slower than both.

`ns/value` = time / (records × fields decoded). GB/s = input bytes of the records processed / time.
For projection, GB/s is "effective" (the whole records count as processed although only the selected
fields' cache lines are read) — the point is that 1.25% of the fields cost ~1% of the full decode.

Instruction counts (callgrind, `valgrind --tool=callgrind ./nm_layout_bench 0.01 R --only X`,
R = 11 minus R = 1, divided by 10 — i.e. one run: 40 000 GFI records / 20 devices records):

| contender | gfi: Ir / run | Ir / value | devices: Ir / run | Ir / value |
|---|---:|---:|---:|---:|
| static decoder, record-major | 960 k | 2.4 | 484 k | 3.0 |
| static decoder, field-major | 2.40 M | 6.0 | 1.00 M | 6.3 |
| naive interpreter | 13.7 M | 34.2 | 5.68 M | 35.5 |
| nanom field-major (default) | 2.40 M | 6.0 | 1.25 M | 7.8 |
| nanom record-major | 4.72 M | 11.8 | 1.67 M | 10.4 |
| nanom projection (1/10, 100/8000) | 240 k | 6.0 per selected | 15.9 k | 8.0 per selected |
| nanom JSON Lines export | 108 M | 270 | 47.9 M | 300 |

The static record-major loop executes the fewest instructions (2-3 per value: load, store, and the
compiler fuses the address arithmetic) but loses on time for big records — instructions are not the
bottleneck, memory is. nanom's field-major kernel executes exactly as many instructions as the static
field-major loop on GFI (6.0/value: the per-value loop body is identical) and 1.25x on devices (the
per-field call + block setup amortized over 32 records).

Description handling: the 8000-line (1.3 MB) devices description is parsed (JSON via combinators),
validated and compiled in ~34 ms.

## CLI

```
nanom_layout --layout desc.jsonl [--enums enums.json] [--raw-file-name NAME] --input file.raw
             [--stride N] [--stride-for NAME=N] [--select PATTERN]... [--records A:B]
             [--format jsonl|csv|summary|fields] [--big-endian] [--lenient] [--allow-partial]
             [--via-columns] [--strategy auto|field|record] [-o OUT]
nanom_layout --layout desc.jsonl --list
```

`--raw-file-name` may be omitted when the description has one raw_file. `summary` prints stride,
record count, field counts per family and the first record; `fields` prints the compiled plan
(column, offset, width, type, family, storage, byte, shift). `--via-columns` exports JSON from the
columnar path instead of the record path (the oracle uses it to check the kernels).

## Tests

* `tests/test_layout.cpp` (ctest `nanom_layout_tests`, also `_strict` and `_nogen` builds): JSON
  reader (escapes, surrogates, depth, error offsets), every type family, description errors with
  line:column (missing key, wrong type, width 0/65, absurd offset, empty name, float widths, unknown
  type strict/lenient, duplicates), enum file errors, name splitting (`::`, `long>._M_i`), the tree
  (1-based and gappy `array_item_N`, implicit arrays at struct and leaf level, conflicts), GFI end to
  end (JSON, CSV, columns, handles, stride overrides, partial records, record ranges, caller
  buffers, selections), 300 random layouts (random bit-fields, both byte orders, records < 8 bytes)
  checked bit-by-bit against a reference for the record path and both column schedules, sign
  extension and floats, Arrow export (formats, bitmap, release with a moved-out child).
* `tests/layout_oracle.py` (ctest `layout_oracle`, stdlib only): generates a description with C/GCC
  layout rules — ~10 600 scalars in a 58 KB devices record (nested `::` names, atomics, `_vptr`,
  arrays of structs 1-based and with gaps, scalar arrays, ~1700 bit-fields, every type family), the
  GFI record, a currentFrame record with 9-byte straddling fields, a 3-byte bit-field record with an
  overlapping field — writes random raw files in both byte orders, decodes them independently
  (`int.from_bytes` + `struct`), and diffs the CLI's JSON value by value and in key order: record
  path, both column schedules, projections, `--records`, partial records, strict/lenient unknown
  types. 2.4 million values, identical (also against an ASan/UBSan build of the CLI).

## Open items

* Enum columns export to Arrow as integers; a dictionary-encoded export (names as the dictionary)
  would be the natural next step.
* Multi-threaded decode: blocks are independent, so splitting the record range over threads is
  straightforward (not done; single-thread numbers are already near the copy bandwidth).
* JSON export is ~18-30 ns/value (number formatting dominates); fine for inspection, not the
  throughput path.
