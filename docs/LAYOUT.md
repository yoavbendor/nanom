# Raw records from a JSON layout description

`#include <nanom/layout.hpp>` decodes binary files that hold "one structure after the other", given a
JSON Lines description of the structure's scalars. **New here? Start with the usage guide
[LAYOUT_GUIDE.md](LAYOUT_GUIDE.md)** (the two flavors, enums as dictionaries, alignment); this page is
the reference.

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
| `layout/e2e.hpp` | AUTOSAR E2E: `e2e::config`, `protect` / `verify`, `protector` (sender counter), `checker` (receiver state machine), profiles 1 2 4 5 6 7 11 22 |
| `layout/arrow.hpp` | `export_arrow(table&&, ArrowSchema*, ArrowArray*, arrow_options)` — Arrow C Data Interface, struct of columns, zero-copy for numeric columns, enum columns as `dictionary<intN, utf8>`; `encode_enum` |

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

## Arrow export and enum columns

`export_arrow(std::move(table), &schema, &array, opts)` hands the table to Arrow through the C Data
Interface: a struct array (`+s`) with one child per column. Numeric columns are zero-copy, booleans
are bit-packed. The table lives until the struct and every child the consumer moved out are released.

**Enum columns become dictionary columns** (`arrow_options::enums`, CLI `--enums-as`), so the names
travel with the data into Lance, Parquet and other formats:

| `enum_mode` | enum field with a (non-empty) table | enum field without one |
|---|---|---|
| `dictionary` (default) | `dictionary<intN, utf8>` under the column name | plain integer |
| `integer` | the raw integer column; the table as metadata `nanom.enum.names` | plain integer |
| `both` | the dictionary column under the column name, then the raw integers as a sibling `<column>#raw` | plain integer |

* **Dictionary** = the table's names ordered by raw value, then — for raw values present in the data
  but missing from the table — their decimal text (the same text the JSON export prints), in
  ascending raw-value order. No value is lost, and the first `nanom.enum.named` entries depend only on
  the enum table, so batches of the same layout agree on them.
* **Index ≠ raw value** (`-1 UNDEF` is index 0). Field metadata on the dictionary column:

  | key | value |
  |---|---|
  | `nanom.enum.values` | JSON array: raw value of each dictionary entry, e.g. `[-1,0,1,2,3,4,5,77]` |
  | `nanom.enum.named` | how many leading entries come from the enum table (the rest are unnamed values) |
  | `nanom.enum.ref` | the enum id, e.g. `1` |
  | `nanom.layout.type` | the description's type string, e.g. `Enum ref = 1` |
  | `nanom.layout.storage` | the raw column's storage (`i32`, `u8` for an unsigned bit-field, ...) |

  `raw = values[index]` rebuilds the integer column exactly. Values of unsigned 64-bit columns are
  printed unsigned. Integer enum columns carry `nanom.layout.type`, `nanom.enum.ref`,
  `nanom.layout.storage` (and `nanom.enum.names`, a `{"raw": "NAME"}` object, in `integer` mode).
* **Index type**: the smallest signed type that holds the dictionary: `int8` up to 128 entries,
  `int16` up to 32 768, else `int32` (`int64` past 2^31). Not marked ordered. Duplicate names (aliases) are kept as
  separate entries.
* **Cost**: the table keeps the plain integer column (the decode kernels are unchanged); `encode_enum`
  translates it at export time. When the data's value range is small (< max(65 536, rows) values) it
  is a min/max pass, a lookup-table build and one gather pass (plus one marking pass only when the
  data holds values outside the table); otherwise a binary search per row. Measured below.
* Lance (pylance 14) stores `dictionary<intN, utf8>` natively, reads it back as dictionary, keeps the
  field metadata and filters by name (`` `Rec/mode` = 'UNDEF' ``). Lance refuses `.` in top-level
  field names, which is why the Arrow names use `arrow_options::separator` (default `/`, CLI
  `--name-separator`): `GFI[0].brain_type` is exported as `GFI[0]/brain_type`, ready for Lance.
  `arrow_column_name(column, separator)` gives the mapping; `"."` keeps the dotted names.

`nanom_layout --format arrow-schema [--enums-as ...]` decodes the input and prints the exported
schema, one JSON line per Arrow column (name, format, dictionary values, metadata). nanom has no
Arrow IPC writer; programs take the C Data structs (pyarrow: `pa.RecordBatch._import_from_c`).

## AUTOSAR I-PDU signals

Optional keys turn a description line into an AUTOSAR / DBC signal of an I-PDU (`raw_file` = the
PDU, `scalar_name` = the signal). Lines without them behave exactly as before; plans that use none
take no new code path (decode kernels, record access and text output are unchanged).

```json
{"raw_file":"Brake","scalar_name":"Mux","bit_offset":0,"bit_width":4,"byte_order":"intel","multiplexor":true,"pdu_length":8}
{"raw_file":"Brake","scalar_name":"Pressure","bit_offset":15,"bit_width":12,"byte_order":"motorola","factor":0.1,"unit":"bar","min":0,"max":250,"mux_value":1}
{"raw_file":"Brake","scalar_name":"Temp","bit_offset":20,"bit_width":10,"byte_order":"intel","signed":true,"factor":0.5,"offset":-40,"mux_value":[2,3],"update_bit":63}
```

| key | value | meaning |
|---|---|---|
| `byte_order` | `"intel"` / `"little"` / `"little_endian"` / `"most_significant_byte_last"`, or `"motorola"` / `"big"` / `"big_endian"` / `"most_significant_byte_first"` | per-signal byte order; `bit_offset` becomes the DBC/AUTOSAR **start bit** (below). Absent: the plan's `compile_options::order` with the original numbering |
| `motorola_start` | `"msb"` (default) / `"lsb"` | Motorola only: `bit_offset` names the MSB (DBC, ARXML system template) or the LSB (some COM configurations); stored as the MSB |
| `start_bit` | integer | alias of `bit_offset` on signal lines |
| `signed` | bool | two's complement (overrides the type's signedness; for enums: the bit-field signedness) |
| `factor`, `offset` | finite numbers (factor ≠ 0) | `physical = raw * factor + offset` |
| `unit` | string | carried into Arrow metadata |
| `min`, `max` | numbers | physical range; `set`/`encode` refuse values outside it |
| `multiplexor` | bool | this signal selects the multiplexed group |
| `mux_value` | integer or array of integers | the signal is valid only when its multiplexor holds one of these |
| `mux_signal` | string | the multiplexor's name (required when the PDU has several multiplexors) |
| `update_bit` | integer | Intel bit position (byte `n/8`, bit `n%8`) of the signal's update bit |
| `pdu_length` | integer bytes | record stride = PDU length (all lines of a PDU must agree; `--stride` still overrides) |

`type` may be omitted on lines that use any of these keys: the smallest C integer that holds
`bit_width` (`UChar` … `ULongLong`; `SChar` … `LongLong` with `"signed": true`). IEEE float signals
use `"type":"Float"` (32 bits) / `"Double"` (64). Errors (unknown byte order, `factor` 0, `min >
max`, a multiplexed multiplexor, an unknown `mux_signal`, several multiplexors without
`mux_signal`, `signed` on a float, factor on a bool, disagreeing `pdu_length`, a Motorola signal
leaving the PDU) carry `source:line:column` like every description error.

**Start bits.** Bits are numbered in the DBC "sawtooth" order — bit `b` is bit `b % 8` (LSB = 0)
of byte `b / 8`:

```
byte                  0                         1                         2                         3
bit                     7  6  5  4  3  2  1  0 | 15 14 13 12 11 10  9  8 | 23 22 21 20 19 18 17 16 | 31 30 29 28 27 26 25 24
Intel start 12, 8b      .  .  .  .  .  .  .  . | i3 i2 i1 i0  .  .  .  . |  .  .  .  . i7 i6 i5 i4 |  .  .  .  .  .  .  .  .
Motorola start 20,10b   .  .  .  .  .  .  .  . |  .  .  .  .  .  .  .  . |  .  .  . m9 m8 m7 m6 m5 | m4 m3 m2 m1 m0  .  .  .
```

(`iK` / `mK` = bit K of the value; K = 0 is the LSB.)

An Intel signal starts at its LSB and occupies bits `start … start+len-1`. A Motorola signal starts
at its MSB and runs towards lower bit numbers inside a byte, continuing at bit 7 of the next byte —
in "MSB-first linear" numbering (`msb_linear(b) = b/8*8 + 7 - b%8`, byte 0 bit 7 = 0) it occupies
`msb_linear(start) … msb_linear(start)+len-1`, which is exactly the big-endian access the plan
already had. So a Motorola signal compiles to the same `access` (one 8/16/32/64-bit load, or an
8-byte window + shift) as a big-endian bit-field; Intel to the little-endian one; the column kernels
and `record::get` are unchanged. Examples checked in `tests/test_layout_autosar.cpp` (hand-computed)
and against cantools: Motorola start 7 / 16 bits holding 0x1234 → bytes `12 34`; Motorola start 20
/ 10 bits holding 0x201 → byte 2 = `10`, byte 3 = `08`; Intel start 36 / 8 bits holding 0xAB →
byte 4 = `b0`, byte 5 = `0a`; `"bit_offset":27,"motorola_start":"lsb"` = start 20.

**Decode.** `decode_options::physical` (CLI `--physical`) adds a `double` column per scaled signal
(`table::physical(c)`, raw × factor + offset); `decode_options::validity` (default on) computes, for
multiplexed signals and signals with an update bit, one validity byte per row (`table::validity(c)`,
`table::null_count(c)`, `table::valid(row, c)`): the row is valid when the update bit is set and the
multiplexor holds one of `mux_value`. Each distinct condition is extracted once (a multiplexor that
is itself a selected column is read from that column). The raw columns are always there and always
hold the bits (an invalid row holds whatever the PDU carried). On a single record:
`record::physical(h)`, `plan::valid(record, h)`.

**Arrow.** Validity becomes the Arrow validity bitmap (`ARROW_FLAG_NULLABLE`, `null_count`).
`arrow_options::signals` (`--signals-as`) picks the scaled-signal columns: `both` (the default when
physical columns were decoded) = `float64` physical under the column name + the raw integers as
`<column>#raw`; `physical` = only the float; `raw` = only the integers. Every signal column carries
metadata `nanom.signal.role` (`raw`/`physical`), `.factor`, `.offset`, `.unit`, `.min`, `.max`,
`.byte_order`, `.start_bit`, `.bit_width`, `.raw_storage`, and where applicable `.multiplexor`,
`.mux_signal`, `.mux_values`, `.update_bit`.

**JSON / CSV.** `text_options{physical, nulls}`: invalid signals print `null` (JSON) / an empty
cell (CSV) unless `nulls` is off (`--no-nulls`); `physical` prints raw × factor + offset as a float.

**Encode** (crafting PDUs; `plan.hpp`):

| call | checks | cost (bench, 64-byte PDU) |
|---|---|---:|
| `plan.set_bits_unchecked(h, pdu, bits)` | none (bits masked to the width; caller guarantees `pdu.size() >= stride()`) | 4.8 ns/signal |
| `plan.set_raw(h, pdu, int64)` / `set_raw_unsigned(h, pdu, uint64)` | buffer size; raw in `[0, 2^w-1]` / `[-2^(w-1), 2^(w-1)-1]` | — |
| `plan.set(h, pdu, physical)` | finite; `min ≤ physical ≤ max`; rounded raw in range | 11.9 ns/signal |
| `plan.encode({{h, value, raw?}, ...}, pdu)` | all of the above for every value **first**, plus: a multiplexed signal needs its multiplexor (among the values, or already in `pdu`) to select it; then writes all — on error `pdu` is unchanged | 22.9 ns/signal (19 values) |

Rounding: `raw = round((physical - offset) / factor)`, nearest with ties away from zero (`std::round`:
2.5 → 3, -2.5 → -3); float signals store `(physical - offset) / factor` as float/double (overflowing
a float is an error). Every write is a read-modify-write of the same window the decoder reads, so
all other bits of the PDU are preserved; a signal with an update bit sets it. `plan::to_raw` /
`plan::raw_bits` give the validated bits without writing. Round trips are tested on 4000 random
signals (1..20-byte PDUs, every load mode, widths 1..64, both byte orders, signed/unsigned, scaled)
against a bit-by-bit DBC reference, and the encoded bytes equal cantools' for 60 random CAN-FD
messages.

### E2E (`layout/e2e.hpp`)

```cpp
namespace e2e = nanom::layout::e2e;
e2e::config c{.prof = e2e::profile::p05, .data_id = 0x1234};   // offsets in bits, as AUTOSAR
e2e::protector tx(c);  tx.protect(pdu);                          // counter 0, 1, 2 ...
e2e::checker   rx(c);  switch (rx.check(pdu)) { case e2e::status::ok: ... }
e2e::protect(c, pdu, counter);  e2e::verify(c, pdu);             // stateless forms
```

| profile | CRC (nanom/checksum.hpp) | header at `offset` | data ID in the CRC | verified |
|---|---|---|---|---|
| P01 | CRC-8 SAE-J1850, register 0, no final xor | CRC byte at `offset`, counter nibble (0..14) at `counter_offset` (default `offset+8`), ID nibble at `nibble_offset` (`offset+12`) | modes `both` (low, high), `low`, `alt` (low on even counters, high on odd), `nibble` (low, 0x00; bits 8..11 sent in the nibble) | yes (all 4 modes, random offsets) |
| P02 | CRC8H2F | CRC byte 0, counter low nibble of byte 1 (0..15) | `data_id_list[counter]` appended | yes |
| P04 | CRC32P4 | 12 bytes BE: length u16, counter u16, data ID u32, CRC u32 | the ID field | yes |
| P05 | CRC-16/CCITT-FALSE | CRC u16 **little-endian**, counter u8 | low byte, high byte appended | yes |
| P06 | CRC-16/CCITT-FALSE | 5 bytes BE: CRC u16, length u16, counter u8 | high byte, low byte appended | yes |
| P07 | CRC-64 (XZ) | 20 bytes BE: CRC u64, length u32, counter u32, data ID u32 | the ID field | yes |
| P11 | as P01 (modes `both`, `nibble`) | as P01 | as P01 | yes (both modes) |
| P22 | CRC8H2F | CRC byte, counter low nibble of the next byte (0..15) | `data_id_list[counter]` appended | **no** (no independent oracle; equals P02 at offset 0) |

The CRC covers every PDU byte except the CRC field (in order), then the appended data-ID bytes.
"Verified" = byte-identical to the `autosar-e2e` 1.0.0 package (an independent C implementation)
on random PDUs, lengths, offsets and data IDs in `tests/layout_autosar_oracle.py`, plus 21 golden
vectors from it frozen into `tests/test_layout_autosar.cpp`. That package only exposes CRC
checking, so the **receive state machine is verified only by nanom's own tests**:

`checker::check(pdu, new_data = true)` → `no_new_data` (no PDU this cycle), `wrong_length` (shorter
than the header, P04/P06/P07 length field ≠ PDU size or outside `min_length`/`max_length`),
`wrong_data_id` (P04/P07 ID field, P01/P11 nibble), `bad_counter` (P01/P11 counter 15),
`wrong_crc`, else the counter evaluation of the R4.2+ profiles: the state starts at the counter
maximum (a first PDU with counter 0 is `ok`), `delta = (received - last) mod (max + 1)`: 0 →
`repeated`, 1 → `ok`, 2..`max_delta_counter` → `ok_some_lost` (`lost()` = delta − 1), larger →
`wrong_sequence`; the state takes the received counter for every non-error status and keeps it on
errors. ⚠ P01/P02 use this evaluation too, not their legacy state machine (`INITIAL`, `SYNC`,
`MaxNoNewOrRepeatedData`, `SyncCounterInit`), and the R4.2 E2E state machine (`E2E_SM`
window/valid/invalid) is not implemented — combine `usable(status)` over a window yourself.

E2E bench (`LAYOUT_BENCH_ONLY_LAYOUT=autosar nm_layout_bench`, GCC 13 -O2, noisy shared VM):

| profile | 8-byte PDU protect / check | 64-byte PDU protect / check |
|---|---:|---:|
| P01 | 9.8 / 10.7 ns | 34.8 / 34.1 ns |
| P02 | 6.2 / 6.3 ns | 33.1 / 31.3 ns |
| P04 | — | 45.1 / 28.7 ns |
| P05 | 11.1 / 11.9 ns | 38.2 / 37.3 ns |
| P06 | 11.1 / 12.0 ns | 62.0 / 37.4 ns |
| P07 | — | 26.4 / 25.4 ns |
| P11 | 10.3 / 11.2 ns | 34.7 / 34.2 ns |
| P22 | 6.6 / 7.1 ns | 33.1 / 30.8 ns |

(The CRC dominates: the 8-bit/16-bit CRCs run one table step per byte on the split spans; the
64-bit CRC and CRC32P4 use slicing-by-8. Protect numbers above check include store-forwarding of
the freshly written header.)

Signal decode bench (1 M PDUs × 64 bytes, 21 signals, 13 scaled, a multiplexor with two groups of
two, two update bits; same machine): decoder kernels 1.0 ns/value (3.0 GB/s); `decode()` raw 38 ms,
\+ validity 68 ms (each update bit is one more strided pass over the 64 MB of PDUs), + physical 118 ms
(13 M doubles allocated and written: page faults). The gfi/devices numbers above are unchanged
(identical kernels; re-measured: field-major and `decode()` within run-to-run noise).

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

Arrow export of the GFI enum columns (`--only arrow`, same machine, 4 M records x 2 enum columns,
best of 5):

| what | ms | ns per enum value |
|---|---:|---:|
| `encode_enum`, every value in the table (dense lookup, dictionary 7) | 8.1 | 1.0 |
| `encode_enum`, 1% unnamed values (extra marking pass, dictionary 57) | 12.1 | 1.5 |
| `encode_enum`, random 32-bit values (sparse path, 4 M distinct "names") | 2502 | 313 |
| `decode()` + `export_arrow`, `enum_mode::integer` | 78.1 | — |
| `decode()` + `export_arrow`, `enum_mode::dictionary` | 99.7 | — |

With realistic enum data the translation costs ~1 ns per enum value; the end-to-end difference
(~21 ms) is that plus allocating and first-touching the index buffers. The sparse row is the
pathological worst case (every row a different unnamed value: sort a copy of the column, build 4 M
decimal names, binary-search every row); real enums never get there.

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
             [--format jsonl|csv|summary|fields|arrow-schema] [--enums-as dictionary|integer|both]
             [--big-endian] [--lenient] [--allow-partial] [--via-columns]
             [--strategy auto|field|record] [-o OUT]
             [--physical] [--no-nulls] [--signals-as raw|physical|both]
             [--e2e p01|p02|p04|p05|p06|p07|p11|p22 --data-id N | --data-id-list HEX32]
             [--e2e-offset BITS] [--e2e-mode both|alt|low|nibble] [--e2e-max-delta N]
             [--format ...|e2e-check]
nanom_layout --layout desc.jsonl --encode values.jsonl [--raw-values] [--pdu-template HEX]
             [--e2e ...] -o pdus.raw
nanom_layout --layout desc.jsonl --list
```

`--encode` reads one JSON object per line (`{"Speed": 88.5, "Mux": 1}`, physical values unless
`--raw-values`), encodes each into a PDU of `stride` bytes (starting from `--pdu-template` or
zeros; `plan::encode` semantics) and writes them back to back; with `--e2e` each PDU is protected
(counter 0, 1, ...). `--format e2e-check` runs a `checker` over the input PDUs and prints one status
name per PDU.

`--raw-file-name` may be omitted when the description has one raw_file. `summary` prints stride,
record count, field counts per family and the first record; `fields` prints the compiled plan
(column, offset, width, type, family, storage, byte, shift); `arrow-schema` the Arrow export (see
above). `--via-columns` exports JSON from the
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
  extension and floats, Arrow export (formats, bitmap, release with a moved-out child), enum
  dictionaries (contents, unnamed values, metadata, `integer`/`both`, empty input, enums without a
  table, enum bit-fields in both byte orders, moved-out dictionary children) and `encode_enum` on
  random columns of every integer storage (dense and sparse paths, int8/int16/int32 indices,
  unsigned 64-bit values).
* `tests/test_layout_autosar.cpp` (ctest `nanom_layout_autosar_tests`, `_strict`, `_nogen`; also
  ASan/UBSan): hand-computed DBC examples (Intel/Motorola, MSB/LSB start), 4000 random encode →
  decode round trips against a bit-by-bit DBC reference (both column schedules and the record
  path, physical round trip), range/rounding rules, encode atomicity, multiplexing and update bits
  (validity, null counts, JSON/CSV nulls, Arrow validity bitmaps, physical + raw columns, metadata,
  `signal_mode`), description errors, 21 E2E golden vectors, P22 = P02, header-field errors, and
  the protector/checker state machine for every profile including the counter wrap.
* `tests/layout_autosar_oracle.py` (ctest `layout_autosar_oracle`; needs `cantools` and
  `autosar-e2e`, else skipped with 77): 60 random CAN-FD messages written as a DBC (loaded by
  cantools) and as a nanom description, 40 PDUs each — CLI decode (raw and `--physical`, nulls for
  other multiplexer groups) vs `cantools.decode`, CLI `--encode` (raw and physical) vs
  `cantools.encode` byte for byte; E2E: 60 random configurations per profile protected by the CLI,
  accepted by the oracle's check and unchanged by the oracle's re-protect; receive sequences
  (ok / repeated / ok_some_lost / wrong_sequence / wrong_crc) through `--format e2e-check`. ~16 000
  checks, 0 differences.
* `tests/layout_arrow_lance.py` (ctest `layout_arrow_lance`, needs pyarrow + pylance): loads
  `tests/layout_arrow_capi.cpp` (a shared library) with ctypes, imports the exported struct into
  pyarrow, checks every enum value against an independent decode (natural enums with -1, unsigned
  and signed enum bit-fields, an 8-bit enum, an enum without a table; both byte orders; all three
  modes), then writes it with pylance and reads it back: dictionary types, names, metadata and
  filters by name intact. Not built under `NANOM_SANITIZER`.
* The `*_differential` tests and `layout_arrow_lance` need pyarrow (etc.) in the interpreter that
  runs them and exit 77 (ctest: skipped) otherwise. `-DNANOM_PYARROW_PYTHON=/path/to/venv/bin/python`
  points them at one that has it; the default is the `Python3` CMake finds.
* `tests/layout_oracle.py` (ctest `layout_oracle`, stdlib only): generates a description with C/GCC
  layout rules — ~10 600 scalars in a 58 KB devices record (nested `::` names, atomics, `_vptr`,
  arrays of structs 1-based and with gaps, scalar arrays, ~1700 bit-fields, every type family), the
  GFI record, a currentFrame record with 9-byte straddling fields, a 3-byte bit-field record with an
  overlapping field — writes random raw files in both byte orders, decodes them independently
  (`int.from_bytes` + `struct`), and diffs the CLI's JSON value by value and in key order: record
  path, both column schedules, projections, `--records`, partial records, strict/lenient unknown
  types; `--format arrow-schema` in the three enum modes (dictionary values and metadata against
  the Python decode). 2.4 million values, identical (also against an ASan/UBSan build of the CLI).

## Open items

* AUTOSAR: no ARXML/DBC importer (write the JSON lines; the oracle test shows the DBC mapping);
  nested multiplexing, signal groups, initial values, `E2E_SM` and the legacy P01/P02 receive state
  machines, P44/P4m/P8 profiles are not implemented; P22 is unverified.

* Nested Arrow structs following the name tree (instead of flat columns with a separator) —
  postponed; flat columns are the supported form.
* Multi-threaded decode: blocks are independent, so splitting the record range over threads is
  straightforward (not done; single-thread numbers are already near the copy bandwidth).
* JSON export is ~18-30 ns/value (number formatting dominates); fine for inspection, not the
  throughput path.
