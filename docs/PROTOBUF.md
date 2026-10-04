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
| `nm::pb_box<M>` | a message that may be absent, held on the heap: for recursive models (`Node` containing a `Node`), which `std::optional` cannot express | present = written |
| `nm::pb_lazy<M>` | a message kept as its wire bytes (length checked) and decoded on demand: `decode_into(m)` / `decode()`; for writing, `pb_lazy<M>::of(m)` points at the caller's message | present = written; read bytes are written back verbatim |
| `nm::empty_struct` | `message X {}` | an empty length-delimited record |
| `nm::pb_unknown` (the first member) | the fields the model does not declare | kept verbatim on read, written after the declared fields |

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

## Decoding in place, lazily

`nm::protobuf<M>()` is an ordinary nanom parser that returns the message. `nm::protobuf_decode(in,
m)` decodes into an existing `m` instead, with no temporary copied or moved, which is the cheap way
to decode a large model. Nested messages are decoded in place too.

A `pb_lazy<M>` member costs nothing until it is used. Reading the parent checks that the child's
length fits and records where its bytes are: no allocation, no recursion, and the parent stays
trivially destructible. `child.decode_into(node)` runs the full, checked decoder on those bytes
when a reader walks into them. That is how the Lance encoding trees are modelled
(`nanom/formats/lance_encodings.hpp`): a page's descriptor is a recursive tree of small messages,
and a reader decodes it one node at a time into a reused stack object.

Two rules follow from keeping bytes:
- A lazy child's contents are checked when it is decoded, not when the parent is.
- A consumer walking a recursive tree of lazies bounds its own depth, because each `decode_into`
  starts its own nesting count.

Protobuf merges a message field that occurs twice; bytes cannot be merged, so a second occurrence of
a `pb_lazy` field is refused (writers emit a message field once).

## Keeping what the model does not declare

A writer that rewrites another writer's message (Lance commits rewrite the manifest of every
earlier version) must not drop the fields it does not know. Declare `nm::pb_unknown unknown;` as the
message's first member (its id is 0, which no protobuf field can have):

```cpp
struct DataFragment {
  nm::pb_unknown            unknown;   // row id sequences, version metadata, ... kept as read
  pf<1, std::uint64_t>      id;
  pf<2, std::vector<DataFile>> files;
};
```

Reading appends each field the model does not declare, or that arrives with another wire type
than the model's, key and value, in the order read. Writing emits them after the declared fields,
exactly as Google's protobuf runtime does, so a canonical message reads and re-encodes to the same
bytes. A model without `pb_unknown` compiles to the same code as before: the bookkeeping is
`if constexpr`. Thrift models cannot declare it (a compile-time error).

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
| `lance.table` (table.proto) | `Manifest` (every field nanolance reads or writes, the feature flags, timestamp, writer version, config and table metadata among them), `DataFragment`, `DataFile`, `DeletionFile`, `DataStorageFormat`, `WriterVersion`, `IndexSection`, `IndexMetadata`, `IndexFile`, `Uuid` |
| `google.protobuf` | `Timestamp`, `Any` |
| `lance.encodings21` (`formats/lance_encodings.hpp`) | `PageLayout` (MiniBlock / Constant / FullZip layouts), `CompressiveEncoding` (Flat, Variable, OutOfLineBitpacking, InlineBitpacking, Fsst, Rle, ByteStreamSplit, General, FixedSizeList) and the `EncodingAny` wrapper |
| `lance.encodings` (format 2.0, same header) | `ArrayEncoding` (Flat, Nullable, FixedSizeList, List, SimpleStruct, Binary, Dictionary, Fsst, PackedStruct, Bitpacked, FixedSizeBinary, BitpackedForNonNeg, Constant) |

Fields not declared are skipped on read, so newer Lance writers stay readable. The messages a
writer hands back when it commits (Manifest, DataFragment, DataFile, DeletionFile, Field,
IndexMetadata, IndexFile) keep them in `pb_unknown`. `IndexSection` holds each index as raw bytes,
so an index nanolance does not change is copied into the next manifest byte for byte. nanolance converts
between this model and its own structs (`generated/lance_minimal.pb.cpp` there).

## Verification

| check | what it proves |
|---|---|
| `tests/test_protobuf.cpp` (+ strict build) | golden bytes from the protobuf spec in both directions; the read rules and every hostile case above; encoder errors naming message and field. Plus round-trip properties over messages generated by reflection: a message with every member type, a recursive one, two-byte keys, a recursive `pb_box` tree, messages carrying random unknown fields of every wire type, and every Lance message. Golden bytes pin where unknown fields go and that a known field arriving with another wire type is kept; a mutation run on the new paths (5 planted bugs) found one gap, a shallow `pb_box` copy, now covered. The properties are `decode(encode(x)) == x`, a byte-identical re-encode, exact `protobuf_size`, every too-small fixed buffer failing cleanly, and every prefix rejected or read without over-reading. |
| `tests/protobuf_differential.py` | Google's protobuf runtime as the oracle, with descriptors mirroring Lance's protos. nanom's encoding of 3,000 random Lance messages, unknown fields included, is byte-identical to protobuf's own serialization. 3,000 messages built by protobuf, with real `map<>` fields and unpacked repeated fields, decode in nanom and re-encode equal. Truncations are accepted or rejected exactly as protobuf does. |
| subset model (in `protobuf_differential.py`) | 1,000 manifests built by protobuf with every field set read through a model that declares 3 of them plus `pb_unknown`; protobuf reads nanom's re-encoding back to the identical message. With unknown keeping disabled, all 1,000 fail. |
| Lance page descriptors (in nanolance) | The page-layout parser built on this model agrees with nanolance's previous hand-written one on every descriptor of files written by pylance (2.1, 2.2, zstd) and nanolance. On 300,000 mutated descriptors under ASan / UBSan it never accepts what the old parser refused, and never disagrees on what both accept. It refuses 826 more, all malformed: field number 0, two oneof members, a repeated lazy field, trailing garbage. |
| `fuzz/fuzz_protobuf.cpp` | generated and mutated inputs; anything that decodes must re-encode to a fixed point, and every `pb_lazy` child (the Lance encoding trees) is walked into and checked the same way. In ctest, clean under ASan / UBSan, and a libFuzzer target. |
| mutation run | 10 bugs planted in the codec. The tests caught 8, then 9 once a test for a varint overflowing bit 63 was added; the tenth is equivalent. Planted bugs also fail the differential (821 and 27 failures). |

Results with nanolance (byte comparisons against its previous hand-written codec, pylance and
speed) are in [WRITERS.md](WRITERS.md#phase-d-results).
