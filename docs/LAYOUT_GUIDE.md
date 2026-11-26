# Guide: JSON structure descriptions → nanom → Arrow tables

This guide is for people **and AI coding agents** who need to turn raw binary dumps of C/C++
structs into Arrow tables (and from there Lance, Parquet, …) using nanom. It tells you which calls
to make, in which order, and why. Everything here is backed by the runnable example
[`examples/layout_to_arrow.cpp`](../examples/layout_to_arrow.cpp) (built and run by ctest as
`example_layout_to_arrow`). The reference with every rule is [LAYOUT.md](LAYOUT.md).

> **Agents: the short version.** Do not write a parser by hand for these files, and do not build a
> combinator per field. Load the description, `plan::compile` it once, then call `decode` (all
> fields) or `decode` with a `select`ion (some fields), then `export_arrow`. Check every
> `expected` result. Tell the plan the struct size (`compile_options::stride`) when you know it.

## 1. What the inputs look like

**The structure description** is JSON Lines, one scalar (leaf field) per line:

```json
{"raw_file":"/dev/vdiZ/pacemaker/gfi.raw","scalar_name":"GFI.brain_type","bit_offset":96,"bit_width":32,"type":"Enum ref = 1"}
{"raw_file":"/proc/app/devices.raw","scalar_name":"MEIO::IOAppDevices._uartWrite.array_item_1._cntTxData._total.int>._M_i","bit_offset":471872,"bit_width":32,"type":"UInt"}
```

* `raw_file` is a **logical name** that groups the scalars of one struct type. One description file
  can describe many raw files; you compile one plan per raw_file. The bytes can come from anywhere
  (the file itself, a copy, a network buffer).
* `scalar_name` is the path to the leaf: components are separated by `.`; a component may contain
  `::` (`Diagnostics::DeviceStatus`) or odd text like `long>` — nanom splits on `.` only.
  `array_item_N` components are array elements.
* `bit_offset` is the bit position **inside one struct** (not inside the file); `bit_width` its size.
* `type` is the C-ish type: `UInt`, `Int`, `UChar`, `ULongLong`, `Logical*1`, `*Void` (pointer),
  `Enum ref = N`, floats… (full list in [LAYOUT.md](LAYOUT.md), "The rules").

**The enum file** (optional) gives names to enum values, per raw_file and enum ref:

```json
{ "/dev/vdiZ/pacemaker/gfi.raw": { "Enum ref = 1": { "-1": "UNDEF", "0": "IMG1", "1": "IMG2" } } }
```

**The raw data** is "one structure after the other": struct 0 at byte 0, struct 1 at byte
`stride`, and so on.

## 2. The four steps (same for both flavors)

```cpp
#include <nanom/layout.hpp>
namespace lay = nanom::layout;

auto desc  = lay::load_description("structs.jsonl");      // 1. parse the description
auto enums = lay::load_enums("enums.json");               //    (optional) the enum names
if (!desc || !enums) { /* desc.error().str(): "file:line:column: message" */ }

lay::compile_options co;
co.stride = 20;                                           //    the struct size, if you know it
auto plan = lay::plan::compile(*desc, "/dev/vdiZ/pacemaker/gfi.raw", &*enums, co);   // 2. compile

auto table = lay::decode(*plan, bytes);                   // 3. decode (flavor A or B, below)

ArrowSchema schema; ArrowArray array;                     // 4. hand it to Arrow
lay::export_arrow(std::move(*table), &schema, &array);
// ... consumer uses &schema / &array (nanoarrow, nano_lance_write_batch, pyarrow, ...)
array.release(&array); schema.release(&schema);          //    the consumer or you release them
```

What each step does and why it is shaped this way:

1. **Load.** The description is untrusted text; the loader is written with nanom's own combinators,
   tolerates whitespace / key order / extra keys, and rejects bad input with `file:line:column`.
2. **Compile.** Turns every scalar into a precomputed load: byte offset, shift, mask, sign
   extension, enum table. It also proves that every field lies inside the stride, which is what
   lets the decode loops run **without bounds checks and still be safe**. Compile once per
   raw_file; reuse the plan for every file and every chunk. It is read-only afterwards.
3. **Decode.** Writes one contiguous, typed, 64-byte-aligned column per field. The input is never
   modified or copied. A trailing partial struct is an error (it almost always means the stride
   is wrong) unless you set `decode_options::allow_partial`.
4. **Export.** Produces an Arrow C Data Interface struct array: one flat child column per field.
   Numeric columns are zero-copy (Arrow points at the table's buffers); booleans become Arrow
   bitmaps; **enum columns become `dictionary<int8|int16|int32, utf8>`** (section 5). The exported
   arrays own everything they point to; release them when the consumer is done.

Every call that can fail returns `nanom::expected<T, layout_error>`. Always test it
(`if (!r) … r.error().str()`). Prefer `*r` / `r->` over `.value()`: with clang + libstdc++ 13 nanom
uses its own minimal `expected`, which has no `.value()`.

## 3. Flavor A — all fields

Use it when you want the whole struct in the table (archiving, a full export to Lance/Parquet).

```cpp
lay::decode_options o;
o.first = 0;            // record range: decode big files in chunks of records
o.count = 100'000;      // (memory = count x total column bytes; the input can be an mmap)
auto table = lay::decode(*plan, bytes, o);
ArrowSchema s; ArrowArray a;
lay::export_arrow(std::move(*table), &s, &a);
```

How it works and why it is fast: decoding every field is mostly sequential reading, so nanom works
**field-major in blocks**: it takes a block of records (~1 MiB of input, at least 32 records), and
for each field runs one tight, specialized loop down the block, writing that field's column
sequentially. The block stays in cache while all fields are read from it. Measured
(single thread, [LAYOUT.md § Benchmarks](LAYOUT.md#benchmarks)): small 40-byte records decode at
4.3 GB/s (1.16x of a hand-written decoder generated for that exact struct at build time); a 69 KB
struct with 8,000 fields decodes at the same speed as that hand-written decoder.

## 4. Flavor B — pick the fields you need

Use it when you want a few fields out of big structs (dashboards, one counter across many records).

```cpp
auto pick = plan->select({
    "GFI.brain_type",                               // exact scalar name
    "MEIO::IOAppDevices._uartWrite.array_item_2",   // a whole subtree
    "MEIO::IOAppDevices._board.",                   // a prefix (ends in '.' or '::')
    "*._deviceId",                                  // a glob (* and ?)
});
if (!pick) { /* a pattern that matches nothing is an error: typos never select nothing */ }
auto table = lay::decode(*plan, bytes, *pick, o);
ArrowSchema s; ArrowArray a;
lay::export_arrow(std::move(*table), &s, &a);
```

How it works and why it is fast: each selected field is one strided load per record, so the
bytes between selected fields are **never read** — with large structs that means whole cache lines
and memory pages are skipped (with an mmapped file, pages holding no selected field are never even
faulted in). The cost is proportional to what you select: 100 of 8,000 fields cost 0.46% of the full
decode.

No Arrow needed? Read fields directly with precomputed handles (no string work per access, ~3 ns):

```cpp
auto brain = plan->find("GFI.brain_type");                // once
for (auto rec : plan->records(bytes)) use(rec.get<int>(*brain));
```

## 5. Enums become dictionary columns

An enum field that has a table in the enum file is exported as `dictionary<intN, utf8>`:

* the dictionary holds the **names**, in raw-value order (`UNDEF, IMG1, …` for `-1, 0, …`);
* raw values found in the data but missing from the table get an entry whose name is the number
  (`"77"`), so nothing is lost;
* the index type is the smallest that fits (`int8` up to 128 entries);
* the field metadata maps index → raw value: `nanom.enum.values = [-1,0,1,…]`, plus
  `nanom.enum.ref`, `nanom.layout.type`, `nanom.layout.storage`.

Why: the names travel with the data. Lance stores Arrow dictionary columns natively (checked with
pylance 2.0/2.1/2.2 and nanolance), reads them back as dictionaries, lets you filter by name
(`brain_type = 'IMG1'`), and they are the most compact form (0.39 bytes/row in Lance 2.1, against
3.7 for `int32` codes containing `-1`). Parquet has native dictionary encoding as well.

Choose with `arrow_options::enums`: `enum_mode::dictionary` (default), `enum_mode::integer` (plain
codes; names in metadata `nanom.enum.names`) or `enum_mode::both` (the dictionary column plus the
codes as `<column>#raw`). Enums without a table stay plain integers.

## 6. Column names: flat, with a separator you choose

The table is flat: one column per scalar. Inside nanom the column name is the scalar name with `.`
(`GFI.brain_type`; implicit arrays get an index: `GFI[1].grab_index`). **In Arrow** the `.` between
components is replaced by `arrow_options::separator`, default `/`:

| scalar / column name | Arrow name (default `/`) |
|---|---|
| `GFI.brain_type` | `GFI/brain_type` |
| `MEIO::InputFrame.vids._value.lastFSTimestamp.long>._M_i` | `MEIO::InputFrame/vids/_value/lastFSTimestamp/long>/_M_i` |

Why: Lance (and some SQL engines) refuse `.` in top-level column names, because `.` addresses
nested fields. Rules for the separator: any non-empty string without `[` or `]`; it should not occur
inside a component (`/` never does in C++ names, which is why it is the default; `::` would be a bad
choice). `"."` keeps the dotted names. In SQL filters quote such names: `` `GFI/brain_type` = 'IMG1' ``.
CLI: `--name-separator S`.

Lookups on the nanom side (`plan->find`, `plan->select`, `table->column<T>(name)`) always use the
canonical dotted names; only the Arrow export renames.

(Nested Arrow structs that follow the name tree are planned for later; the flat form is the
supported one now.)

## 7. Alignment, stride and where each struct starts

This is the one thing to get right, and it is easy when you know your struct sizes.

* **The input buffer needs no alignment.** All loads are unaligned-safe (`memcpy`-based), at any
  byte or bit offset. Bit-fields and packed structs work.
* **The stride (struct size) is what matters.** If you know it, set it — `co.stride = N` for every
  raw_file, or `co.stride_by_file["/proc/app/devices.raw"] = N` per raw_file (CLI `--stride N` /
  `--stride-for NAME=N`). Then alignment is a non-issue.
* **If you don't set it**, nanom infers the C-struct size: the bytes the fields cover, rounded up to
  the largest field alignment (max 8). That is right when the description lists every member up to
  the end of the struct; it is too small when trailing members or tail padding are missing from the
  description. nanom then reports "N whole records plus a partial record of K bytes" — the hint to
  pass the real size. Never silence that with `allow_partial` unless the file really ends with a
  partial struct.
* **Where the structs start.** nanom expects struct 0 at the start of the span you pass. If the
  file has a header, or the structs start at a known offset, pass the span from there:
  `lay::decode(*plan, file.subspan(start), o)`. If several groups of structs start at known,
  irregular offsets, decode each group's span separately (one plan, many decodes), or view single
  structs with `plan->view(file.subspan(start))` and `rec.get<T>(handle)`.
* **Byte and bit order.** Little-endian by default, bit-fields numbered from the least significant
  bit (GCC/x86). Big-endian targets: `co.order = std::endian::big`.

## 8. Safety checklist (why this is safe on untrusted input)

* Description and enum files: parsed with depth limits; widths 0 or >64, absurd offsets, empty name
  components and fields past the stride are rejected at load/compile time with line and column.
* Decoding: the plan proves every field fits in a stride, and `decode` only hands whole structs to
  the loops; so the unchecked loops cannot read out of bounds. `decode_into` (your own buffers)
  checks every buffer size first.
* Exported Arrow arrays keep the decoded data alive until the last child is released (moving a
  child out and releasing the parent is fine).
* Covered by unit tests, an independent Python decoder compared value by value (≈2.4M values), and
  ASan/UBSan runs ([LAYOUT.md § Tests](LAYOUT.md#tests)).

## 9. Performance checklist

* Compile the plan once; reuse it. Loading and compiling an 8,000-line description takes ~30 ms.
* Pick the flavor by what you need: all fields → flavor A; a few fields → flavor B (cost ∝ selection).
* mmap the input (the CLI does) instead of reading it into a vector.
* Bound memory on huge files with `decode_options::first/count` chunks; each chunk exports to its
  own Arrow batch (e.g. one `nano_lance_write_batch` per chunk).
* For your own buffers (reused across chunks, no allocation): build a `lay::decoder dec(*plan, sel)`
  once and call `lay::decode_into(dec, *plan, bytes, outs, o)`.
* Decoding is single-threaded today; the plan is read-only, so disjoint record ranges can be decoded
  on different threads (one `decode` per range).

## 10. The command-line tool

`nanom_layout` does the same without writing code, useful to check a description:

```sh
nanom_layout --layout structs.jsonl --list                       # which raw_files are described
nanom_layout --layout structs.jsonl --raw-file-name /proc/app/devices.raw --format fields
nanom_layout --layout structs.jsonl --enums enums.json --raw-file-name /dev/vdiZ/pacemaker/gfi.raw \
             --input gfi.raw --stride 20 --select GFI.brain_type --format jsonl
nanom_layout ... --format arrow-schema [--enums-as dictionary|integer|both] [--name-separator /]
```

## 11. AUTOSAR I-PDU signals (CAN / CAN FD / Ethernet PDUs)

The same description format describes AUTOSAR/DBC signals: `raw_file` is the PDU, `scalar_name`
the signal, and optional keys add the signal semantics (reference: [LAYOUT.md](LAYOUT.md#autosar-i-pdu-signals)):

```json
{"raw_file":"VehicleSpeed","scalar_name":"Mux","bit_offset":0,"bit_width":4,"byte_order":"intel","multiplexor":true,"pdu_length":8}
{"raw_file":"VehicleSpeed","scalar_name":"Speed","bit_offset":15,"bit_width":16,"byte_order":"motorola","factor":0.01,"unit":"km/h","min":0,"max":655,"mux_value":1}
{"raw_file":"VehicleSpeed","scalar_name":"Temp","bit_offset":32,"bit_width":12,"byte_order":"intel","signed":true,"factor":0.5,"offset":-40,"mux_value":[2,3],"update_bit":63}
```

* `bit_offset` is the DBC/AUTOSAR **start bit**: the LSB for `intel`, the **MSB** (sawtooth
  numbering) for `motorola` — exactly what a DBC `SG_ name : start|len@0+` line says. A COM-style
  description that names the Motorola LSB adds `"motorola_start":"lsb"`.
* `type` may be omitted on such lines (unsigned; `"signed": true` for two's complement).
* `pdu_length` makes the record stride the PDU length.

Decode as usual; ask for physical values and get nullable columns for multiplexed / update-bit
signals:

```cpp
lay::decode_options o;  o.physical = true;          // validity is on by default
auto t = lay::decode(plan, pdus, o).value();
t.physical(c);   // std::span<const double>: raw * factor + offset
t.validity(c);   // 1 byte per row; empty = always valid; t.null_count(c)
lay::export_arrow(std::move(t), &schema, &array);   // Speed (float64, nullable) + Speed#raw (uint16)
```

Encode (crafting PDUs, realtime): get handles once, then write into a buffer; untouched bits stay.

```cpp
auto speed = plan.find("Speed").value(), mux = plan.find("Mux").value();
std::array<std::byte, 8> pdu{};
plan.encode({{mux, 1, /*raw=*/true}, {speed, 88.5}}, pdu);   // checked, all-or-nothing
plan.set(speed, pdu, 90.0);                                  // one signal, checked (~12 ns)
plan.set_bits_unchecked(speed, pdu, 9000);                   // raw bits, no checks (~5 ns)
```

E2E protection (`layout/e2e.hpp`): `e2e::protector tx(cfg); tx.protect(pdu);` on the sender,
`e2e::checker rx(cfg); rx.check(pdu)` on the receiver (`ok`, `repeated`, `ok_some_lost`,
`wrong_sequence`, `wrong_crc`, ...). Profiles 1, 2, 4, 5, 6, 7, 11 are verified against an
independent implementation; profile 22 is implemented from the spec but unverified. CLI:
`nanom_layout --layout pdu.jsonl --encode values.jsonl --e2e p05 --data-id 0x1234 -o pdus.raw`,
`nanom_layout --layout pdu.jsonl --input pdus.raw --physical`, `--format e2e-check`.

## 12. Common mistakes

| mistake | symptom | fix |
|---|---|---|
| stride not set and the description omits tail members | "partial record of K bytes" | `co.stride` / `--stride` |
| data does not start at struct 0 | garbage values, maybe a partial-record error | pass `bytes.subspan(start)` |
| looking up Arrow names (`GFI/x`) in `plan->find` | not found | nanom-side names use `.` |
| `.value()` on clang + libstdc++ 13 | compile error | `*r`, `r->` |
| writing `.` column names to Lance | Lance rejects the schema | keep the default separator `/` |
| a combinator or `nm::dyn` per field | 10–100x slower | use the plan; it is the compiled parser |
| Motorola signal given with its LSB as `bit_offset` | wrong values / "stride smaller than ..." | DBC start bit = MSB, or add `"motorola_start":"lsb"` |
