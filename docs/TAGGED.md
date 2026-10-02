# Tagged messages: Thrift compact (and the Parquet footer)

`nanom/tagged.hpp` extends "the struct IS the schema" from fixed-layout wire structs to
**self-describing, field-numbered** encodings. Columnar file formats keep their metadata in these: the
Parquet footer and page headers are Thrift compact, and Lance's manifests and page layouts are protobuf.
Thrift compact is here. Protobuf, on the same model, is [PROTOBUF.md](PROTOBUF.md).

```cpp
#include <nanom/tagged.hpp>
namespace nm = nanom;

struct KeyValue {
  nm::field<1, std::string_view>                key;    // required: absent = error
  nm::field<2, std::optional<std::string_view>> value;  // optional: absent = nullopt
};
NANOM_DESCRIBE(KeyValue, key, value);   // C++23; under C++26 reflection no registration line at all

auto r = nm::thrift_compact<KeyValue>()(in);             // an ordinary nanom parser
```

Writing the same struct back is a separate header, `nanom/tagged_encode.hpp`, which reading code
never includes (see [Writing](#writing)).

The field id lives in the type (`field<Id, T>`), the same way endianness lives in `be<>`/`le<>`. Both
`describe<T>` providers work unchanged: the `NANOM_DESCRIBE` macro and C++26 P2996 reflection.

## What is decided at compile time

| fact | how |
|---|---|
| field id → member dispatch | consteval table (dense array for ids < 256), one runtime switch into per-field code |
| expected wire type per member | `type_of<T>()`; a field whose wire type does not match is skipped like an unknown field, never reinterpreted (Apache Thrift's semantics; old Parquet writers reused field ids with other types). A required member skipped this way fails the required-field check. |
| required fields | a bitmask checked once, at the struct's STOP byte |
| ids unique, ascending, ≤ 64 fields | `static_assert` |
| unsupported member types (unsigned, float) | `static_assert` with a message naming the supported set |

## Member types

| member type | Thrift wire | notes |
|---|---|---|
| `bool`, `int8_t`, `int16_t`, `int32_t`, `int64_t`, `double` | bool / i8 / i16 / i32 / i64 / double | integers are range-checked into the member's width |
| `enum class E : int32_t` | i32 | open enums: an unknown value round-trips as its number |
| `std::string_view`, `nm::bytes` | binary | zero-copy views into the input; prefer `bytes` under `NANOM_GENERATION` (it carries the attestation) |
| `std::string` | binary | owning copy |
| `nm::list<E>` | list / set | **lazy**: the validated element bytes + count; `for_each`, `at(i)`, `to_vector()`; no allocation |
| `std::vector<E>` | list / set | eager, owning |
| a nested message | struct | decoded in place |
| `nm::lazy<M>` | struct | the validated bytes, decoded on `decode()` |
| `nm::empty_struct` | struct | Thrift `struct Foo {}` (Parquet's `StringType`, …) |
| `std::optional<T>` | as `T` | always optional |

`field<Id, T, nm::presence::defaulted>` lets a non-optional member be absent: it keeps its default value.
This covers Thrift default-requiredness and proto3 implicit presence.

## Hostile-input rules

- Every list or map count is checked against the remaining bytes (`count_fits`) before any reserve. A
  4-byte count can never become a multi-gigabyte allocation.
- Every length prefix is checked against the remaining bytes before a span is formed.
- Nesting is capped at `NANOM_TAGGED_MAX_DEPTH` (64) for decode **and** skip. A 10,000-deep list or
  struct bomb fails cleanly; it does not recurse until the stack overflows.
- Varints are bounded (10 bytes; the last byte may carry only the bits that still fit).
- Unknown fields are skipped structurally under the same limits, for forward compatibility.
- Decoding is `constexpr`: the unit tests decode wire bytes inside `static_assert`, where undefined
  behaviour would be a compile error.

## Parquet model

`nanom/formats/parquet_thrift.hpp` declares parquet.thrift's reader-relevant structs in
`nanom_formats::parquet`:

- `FileMetaData`, `SchemaElement`, `LogicalType`, `RowGroup`, `ColumnChunk`, `ColumnMetaData`,
  `Statistics`
- `PageHeader`, `DataPageHeader`, `DataPageHeaderV2`, `DictionaryPageHeader`
- `OffsetIndex`, `ColumnIndex`

It also provides `locate_footer` and `read_file_metadata`. Repeated members are lazy `nm::list` views, so
`meta.row_groups->at(7)` decodes one row group out of thousands without touching the rest.

The model lives outside `nanom::` on purpose. C++26 reflection auto-describes only types outside the
library namespace, so these structs need no registration there.

## Verification

| check | what it proves |
|---|---|
| `tests/test_tagged.cpp` (+ strict and no-generation builds) | hand-assembled spec vectors, byte-identical re-encoding, rejection of every hostile case above |
| `tests/parquet_differential.py` | pyarrow writes 8 files (codecs, page v1/v2, dictionary, delta, byte-stream-split, nested + logical types, page index); `examples/parquet_meta` decodes every footer fact, walks every page header of every column chunk, and decodes the OffsetIndex; all of it must match pyarrow |
| `fuzz/fuzz_thrift.cpp` | no crash under ASan/UBSan on mutated footers and noise; codec output is a round-trip fixed point. In ctest, and a libFuzzer target |

## Performance

`bench/thrift_bench.cpp` (`nm_thrift_bench file.parquet`) on a pyarrow footer with 1,000 row groups ×
50 columns (5.7 MB of Thrift), best of 20, against `pyarrow.parquet.read_metadata` (Arrow's
Thrift-generated C++) on the same file:

| pattern | nanom | Arrow |
|---|---:|---:|
| open the footer (validate; row groups stay lazy) | **10.2 ms** (559 MB/s) | 43.9 ms (eager decode) |
| decode one row group out of 1,000 | **15.2 ms** | 43.9 ms (must decode all) |
| decode every member of every column chunk | 43.5 ms (869 ns/chunk) | 43.9 ms (877 ns/chunk) |

These come from one run in a shared cloud container, so treat them as indicative. The full walk is at
parity, not ahead. Thrift lists carry no byte length, so a lazy nested list is re-scanned once per
nesting level. Workloads that always decode everything can use the eager `std::vector` mirror, which
decodes in one pass.

## Writing

`nanom/tagged_encode.hpp` encodes the same described structs. The full plan (Parquet, then Lance)
is in [WRITERS.md](WRITERS.md).

```cpp
#include <nanom/tagged_encode.hpp>

const pq::SchemaElement schema[] = {root, col};            // the caller owns the elements
pq::FileMetaData f;
f.version = 1;
f.schema = nm::list<pq::SchemaElement>::of(schema);        // a view, not a copy
f.num_rows = 3;
f.row_groups = nm::list<pq::RowGroup>::of(row_groups);

std::vector<std::byte> out;
auto n = nm::thrift_compact_encode(f, out);               // bytes written, or encode_error
std::array<std::byte, 128> buf;                            // or a fixed buffer, never written past
nm::span_sink s{buf};
auto h = nm::thrift_compact_encode(page_header, s);
const std::size_t size = *nm::thrift_compact_size(f);      // exact size, nothing written
```

| | |
|---|---|
| sinks | `vector_sink`, `span_sink` (a full buffer is an error, never an overrun), `counting_sink`, or any type with `bool put(const std::byte*, std::size_t)` |
| sources | `list<E>::of(span)` and `lazy<M>::of(m)` borrow the caller's values. A list or nested message decoded from a file is written back verbatim, so read-modify-write keeps fields the model does not declare. |
| errors | a string, binary or list longer than the wire's i32; a `lazy<M>` that was never set; a sink that refuses bytes. `encode_error` names the struct and field. |
| tests | `tests/test_tagged_encode.cpp` generates random values of every Parquet model message by reflection and checks: decode(encode(x)) == x, re-encoding is byte-identical, the size is exact, and every too-small buffer fails cleanly. `fuzz/fuzz_thrift.cpp` mutates generated messages. |
