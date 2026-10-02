# Protobuf (and Lance metadata)

`nanom/protobuf.hpp` reads protobuf (the proto3 wire format) into the same reflected
`field<Id, T>` structs that [tagged.hpp](TAGGED.md) reads as Thrift compact.
`nanom/protobuf_encode.hpp` writes them. Lance keeps its manifests, schemas and column metadata
in protobuf. The Lance model is `nanom/formats/lance_protobuf.hpp`.

```cpp
#include <nanom/protobuf.hpp>          // reading only: no encoder is compiled in
namespace nm = nanom;

template <std::uint16_t Id, class T>
using pf = nm::field<Id, T, nm::presence::defaulted>;   // a proto3 implicit-presence field

struct DataFile {
  pf<1, std::string_view>                     path;
  pf<2, std::vector<std::int32_t>>            fields;          // repeated: packed or not, both read
  nm::field<6, std::optional<std::uint64_t>>  file_size_bytes; // proto3 `optional`
};
NANOM_DESCRIBE(DataFile, path, fields, file_size_bytes);

auto r = nm::protobuf<DataFile>()(in);   // the whole input is one message
```

```cpp
#include <nanom/protobuf_encode.hpp>   // writing

std::vector<std::byte> out;
auto n = nm::protobuf_encode(file, out);         // bytes written, or encode_error{what, message, field}
std::array<std::byte, 256> buf;
nm::span_sink s{buf};                            // a fixed buffer: never written past
auto m = nm::protobuf_encode(file, s);
const std::size_t size = *nm::protobuf_size(file);   // exact size, nothing written
```

## Member types

| member | proto type | wire |
|---|---|---|
| `bool`, `int32_t`, `int64_t`, `uint32_t`, `uint64_t` | bool, int32, int64, uint32, uint64 | varint (negative int32 / int64: 10 bytes) |
| an `enum` (int32-backed) | enum, open: unknown values round-trip | varint |
| `nm::pb_sint<int32_t / int64_t>` | sint32, sint64 | zigzag varint |
| `nm::pb_fixed<uint32_t / int32_t / uint64_t / int64_t>` | fixed32, sfixed32, fixed64, sfixed64 | 4 / 8 bytes |
| `float`, `double` | float, double | 4 / 8 bytes |
| `std::string_view`, `nm::bytes`, `std::string` | string, bytes | length-delimited; the first two are views into the input |
| a described message `M` | message | length-delimited |
| `std::vector<E>` | `repeated E` | scalars packed; strings and messages one record each |
| `std::vector<Entry>`, `Entry {1: key, 2: value}` | `map<K, V>` | one record per entry |
| `std::optional<T>` | proto3 `optional`, a oneof member, a message that may be absent | present = written |

## Presence

| declaration | reading | writing |
|---|---|---|
| `field<Id, T, presence::defaulted>` | absent = `T{}` | left out when it holds the default (0, false, +0.0, empty) |
| `field<Id, T>` (required) | absent = error | always written |
| `field<Id, std::optional<T>>` | absent = `nullopt` | written when it holds a value, zero included |
| a message member `M` | absent = `M{}` | always written; use `std::optional<M>` to leave it out |
| `std::vector<E>` | absent = empty | an empty one writes nothing; must be `defaulted` (compile-time check) |

What is written is canonical proto3, the same bytes protoc and prost produce: defaults left out,
repeated scalars packed, fields in number order.

## Protobuf rules on read

- Unknown fields are skipped, whatever their wire type. So is a known field arriving with another
  wire type.
- A repeated scalar is read packed or unpacked, and the two forms may be mixed in one message.
- A message field that occurs twice is merged. For a scalar, the last value wins.

## Hostile input

- Every length is checked against the bytes that remain.
- A varint is at most 10 bytes and 64 bits.
- An integer must fit its member: an `int32` given 2^32 is an error, not a truncation. A bool
  must be 0 or 1.
- Groups (wire types 3 and 4), wire types 6 and 7, and field number 0 are errors.
- Nesting is capped at `max_tagged_depth`. The encoder refuses to write deeper, so whatever it
  writes reads back.
- A packed run is not given an allocation until its bytes are known to be present. The count is
  exact: one value per byte without the continuation bit.

## Lance model

`nanom/formats/lance_protobuf.hpp` (namespace `nanom_formats::lance`) declares the messages that
nanolance reads and writes:

| Lance proto | messages |
|---|---|
| `lance.file` (file.proto) | `Field`, `Schema`, `FileDescriptor`, `Metadata`, `MetadataEntry` (the map entry) |
| `lance.file.v2` (file2.proto, encodings) | `ColumnMetadata`, `Page`, `Encoding`, `DirectEncoding` |
| `lance.table` (table.proto) | `Manifest`, `DataFragment`, `DataFile`, `DeletionFile`, `DataStorageFormat` |

Fields not declared are skipped on read, so newer Lance writers stay readable. nanolance converts
between this model and its own structs (`generated/lance_minimal.pb.cpp` there).

## Verification

| check | what it proves |
|---|---|
| `tests/test_protobuf.cpp` (+ strict build) | golden bytes from the protobuf spec in both directions; the read rules and every hostile case above; encoder errors naming message and field. Plus round-trip properties over messages generated by reflection: a message with every member type, a recursive one, two-byte keys, and every Lance message. The properties are `decode(encode(x)) == x`, a byte-identical re-encode, exact `protobuf_size`, every too-small fixed buffer failing cleanly, and every prefix rejected or read without over-reading. |
| `tests/protobuf_differential.py` | Google's protobuf runtime as the oracle, with descriptors mirroring Lance's protos. nanom's encoding of 3,000 random Lance messages is byte-identical to protobuf's own serialization. 3,000 messages built by protobuf, with real `map<>` fields and unpacked repeated fields, decode in nanom and re-encode equal. Truncations are accepted or rejected exactly as protobuf does. |
| `fuzz/fuzz_protobuf.cpp` | generated and mutated inputs; anything that decodes must re-encode to a fixed point. In ctest, clean under ASan / UBSan, and a libFuzzer target. |
| mutation run | 10 bugs planted in the codec. The tests caught 8, then 9 once a test for a varint overflowing bit 63 was added; the tenth is equivalent. Planted bugs also fail the differential (821 and 27 failures). |

Results with nanolance (byte comparisons against its previous hand-written codec, pylance and
speed) are in [WRITERS.md](WRITERS.md#phase-d-results).
