// SPDX-License-Identifier: Apache-2.0
// nanom/formats/lance_protobuf.hpp — Lance's table and file metadata (protobuf) as reflected nanom
// tagged messages.
//
// The shared model a Lance reader and writer (nanolance) build on: one declaration per protobuf
// message, decoded by nanom/protobuf.hpp and encoded by nanom/protobuf_encode.hpp:
//
//   auto m = nm::protobuf<lance::Manifest>()(nm::from(bytes));     // read
//   nm::protobuf_encode(manifest, out);                              // write
//
// Field numbers and types follow lance-format/lance's protos (lance-table table.proto, lance-file
// file.proto / file2.proto / encodings). Only the fields nanolance reads or writes are declared;
// everything else is skipped structurally on read, so newer writers stay readable. Enums are OPEN
// (int32-backed): a value a newer writer added round-trips as its number.
//
// proto3 rules map to the model like this: implicit-presence fields are presence::defaulted (absent
// = zero / empty, and a zero is not written), `optional` fields and message fields that may be
// absent are std::optional, repeated fields are std::vector (scalars packed on write, both forms
// accepted on read), and a map<K, V> is a std::vector of its {1: key, 2: value} entries.
//
// Zero-copy: strings and bytes are views into the decoded buffer (which must outlive them); for
// writing they point at the caller's strings. Messages a writer must hand back intact when it
// rewrites a manifest (Manifest, DataFragment, DataFile, DeletionFile, Field, IndexMetadata) keep
// the fields they do not declare in a pb_unknown member.
#ifndef NANOM_FORMATS_LANCE_PROTOBUF_HPP_INCLUDED
#define NANOM_FORMATS_LANCE_PROTOBUF_HPP_INCLUDED

#include "../protobuf.hpp"

namespace nanom_formats::lance {
using namespace ::nanom;

/// An implicit-presence proto3 field (absent = default, the default is not written).
template <std::uint16_t Id, class T>
using pf = field<Id, T, presence::defaulted>;

// --- shared --------------------------------------------------------------------------------

/// An entry of a map<string, bytes>.
struct MetadataEntry {
  pf<1, std::string_view> key;
  pf<2, bytes>            value;
};
/// An entry of a map<string, string>.
struct StringEntry {
  pf<1, std::string_view> key;
  pf<2, std::string_view> value;
};
/// google.protobuf.Timestamp.
struct Timestamp {
  pf<1, std::int64_t> seconds;
  pf<2, std::int32_t> nanos;
};
/// google.protobuf.Any: a message of another type, named by URL ("/lance.table.BTreeIndexDetails").
struct Any {
  pf<1, std::string_view> type_url;
  pf<2, bytes>            value;
};

// --- lance.file (file.proto) -----------------------------------------------------------------

enum class FieldType : std::int32_t { PARENT = 0, REPEATED = 1, LEAF = 2 };
enum class FieldEncoding : std::int32_t { NONE = 0, PLAIN = 1, VAR_BINARY = 2, DICTIONARY = 3, RLE = 4 };

/// A schema field. Lance flattens nested types: children name their parent by id, a root field
/// has parent_id -1 (which, being non-zero, is always written; an absent parent_id means 0).
/// What is not declared (dictionary, extension name, storage class, ...) is kept in `unknown`.
struct Field {
  pb_unknown                         unknown;
  pf<1, FieldType>                   type;
  pf<2, std::string_view>            name;
  pf<3, std::int32_t>                id;
  pf<4, std::int32_t>                parent_id;
  pf<5, std::string_view>            logical_type;
  pf<6, bool>                        nullable;
  pf<7, FieldEncoding>               encoding;
  pf<10, std::vector<MetadataEntry>> metadata;
};

struct Schema {
  pf<1, std::vector<Field>>         fields;
  pf<5, std::vector<MetadataEntry>> metadata;
};

/// Lance v1 file metadata (the legacy file format's footer).
struct Metadata {
  pf<1, std::uint64_t>             manifest_position;
  pf<2, std::vector<std::int32_t>> batch_offsets;
  pf<3, std::uint64_t>             page_table_position;
};

/// The schema and row count stored in a Lance file.
struct FileDescriptor {
  field<1, std::optional<Schema>> schema;
  pf<2, std::uint64_t>            length;
};

// --- lance.file.v2 (file2.proto, encodings) ---------------------------------------------------

/// The page / column encoding description, carried inline as an opaque, separately-versioned
/// protobuf (a lance.encodings21 PageLayout / ColumnEncoding, parsed elsewhere).
struct DirectEncoding {
  pf<1, bytes> encoding;
};
/// oneof location { IndirectEncoding indirect = 1; DirectEncoding direct = 2; Empty none = 3; }
struct Encoding {
  field<2, std::optional<DirectEncoding>> direct;
};

struct Page {
  pf<1, std::vector<std::uint64_t>>  buffer_offsets;
  pf<2, std::vector<std::uint64_t>>  buffer_sizes;
  pf<3, std::uint64_t>               length;
  field<4, std::optional<Encoding>>  encoding;
  pf<5, std::uint64_t>               priority;
};

struct ColumnMetadata {
  field<1, std::optional<Encoding>> encoding;
  pf<2, std::vector<Page>>          pages;
  pf<3, std::vector<std::uint64_t>> buffer_offsets;  ///< column-level buffers (format 2.0)
  pf<4, std::vector<std::uint64_t>> buffer_sizes;
};

// --- lance.table (table.proto) ----------------------------------------------------------------

enum class DeletionFileType : std::int32_t { ARROW_ARRAY = 0, BITMAP = 1 };

/// Which rows of a fragment are deleted: _deletions/{fragment_id}-{read_version}-{id}.{arrow|bin}.
struct DeletionFile {
  pb_unknown              unknown;
  pf<1, DeletionFileType> file_type;
  pf<2, std::uint64_t>    read_version;
  pf<3, std::uint64_t>    id;
  pf<4, std::uint64_t>    num_deleted_rows;
};

struct DataFile {
  pb_unknown                             unknown;
  pf<1, std::string_view>                path;
  pf<2, std::vector<std::int32_t>>       fields;  ///< -2: a column the schema dropped
  pf<3, std::vector<std::int32_t>>       column_indices;
  pf<4, std::uint32_t>                   file_major_version;
  pf<5, std::uint32_t>                   file_minor_version;
  field<6, std::optional<std::uint64_t>> file_size_bytes;
};

/// What is not declared (row id sequences, version metadata, ...) is kept in `unknown`.
struct DataFragment {
  pb_unknown                            unknown;
  pf<1, std::uint64_t>                  id;
  pf<2, std::vector<DataFile>>          files;
  field<3, std::optional<DeletionFile>> deletion_file;
  pf<4, std::uint64_t>                  physical_rows;
};

struct DataStorageFormat {
  pf<1, std::string_view> file_format;
  pf<2, std::string_view> version;
};

/// Manifest.writer_version: who committed this version.
struct WriterVersion {
  pf<1, std::string_view> library;
  pf<2, std::string_view> version;
};

/// A dataset version (_versions/{version}.manifest). Fields 4 (version_aux_data), 6
/// (index_section) and 21 (transaction_section) are positions inside the manifest file they were
/// read from: a writer drops or recomputes them, never copies them into another file. What is not
/// declared (base paths, branch, ...) is kept in `unknown`.
struct Manifest {
  pb_unknown                                  unknown;
  pf<1, std::vector<Field>>                   fields;
  pf<2, std::vector<DataFragment>>            fragments;
  pf<3, std::uint64_t>                        version;
  pf<4, std::uint64_t>                        version_aux_data;
  pf<5, std::vector<MetadataEntry>>           schema_metadata;
  field<6, std::optional<std::uint64_t>>      index_section;
  field<7, std::optional<Timestamp>>          timestamp;
  pf<8, std::string_view>                     tag;
  pf<9, std::uint64_t>                        reader_feature_flags;
  pf<10, std::uint64_t>                       writer_feature_flags;
  field<11, std::optional<std::uint32_t>>     max_fragment_id;
  pf<12, std::string_view>                    transaction_file;
  field<13, std::optional<WriterVersion>>     writer_version;
  pf<14, std::uint64_t>                       next_row_id;
  field<15, std::optional<DataStorageFormat>> data_format;
  pf<16, std::vector<StringEntry>>            config;
  pf<19, std::vector<StringEntry>>            table_metadata;
  field<21, std::optional<std::uint64_t>>     transaction_section;
};

/// The manifest file's index section. Each index stays raw bytes here, so an index can be copied
/// into a new manifest byte for byte; decode one with protobuf<IndexMetadata>() to read or change it.
struct IndexSection {
  pf<1, std::vector<bytes>> indices;
};

struct Uuid {
  pf<1, bytes> uuid;  ///< 16 bytes
};
struct IndexFile {
  pb_unknown              unknown;
  pf<1, std::string_view> path;  ///< relative to _indices/<uuid>/
  pf<2, std::uint64_t>    size;
};
/// One index of a dataset version.
struct IndexMetadata {
  pb_unknown                              unknown;
  field<1, std::optional<Uuid>>           uuid;
  pf<2, std::vector<std::int32_t>>        fields;
  pf<3, std::string_view>                 name;
  pf<4, std::uint64_t>                    dataset_version;
  field<5, std::optional<bytes>>          fragment_bitmap;  ///< a Roaring bitmap of fragment ids
  field<6, std::optional<Any>>            index_details;
  field<7, std::optional<std::int32_t>>   index_version;
  field<8, std::optional<std::uint64_t>>  created_at;  ///< milliseconds since the epoch
  pf<10, std::vector<IndexFile>>          files;
};

}  // namespace nanom_formats::lance

NANOM_DESCRIBE(nanom_formats::lance::MetadataEntry, key, value);
NANOM_DESCRIBE(nanom_formats::lance::StringEntry, key, value);
NANOM_DESCRIBE(nanom_formats::lance::Timestamp, seconds, nanos);
NANOM_DESCRIBE(nanom_formats::lance::Any, type_url, value);
NANOM_DESCRIBE(nanom_formats::lance::Field, unknown, type, name, id, parent_id, logical_type, nullable, encoding, metadata);
NANOM_DESCRIBE(nanom_formats::lance::Schema, fields, metadata);
NANOM_DESCRIBE(nanom_formats::lance::Metadata, manifest_position, batch_offsets, page_table_position);
NANOM_DESCRIBE(nanom_formats::lance::FileDescriptor, schema, length);
NANOM_DESCRIBE(nanom_formats::lance::DirectEncoding, encoding);
NANOM_DESCRIBE(nanom_formats::lance::Encoding, direct);
NANOM_DESCRIBE(nanom_formats::lance::Page, buffer_offsets, buffer_sizes, length, encoding, priority);
NANOM_DESCRIBE(nanom_formats::lance::ColumnMetadata, encoding, pages, buffer_offsets, buffer_sizes);
NANOM_DESCRIBE(nanom_formats::lance::DeletionFile, unknown, file_type, read_version, id, num_deleted_rows);
NANOM_DESCRIBE(nanom_formats::lance::DataFile, unknown, path, fields, column_indices, file_major_version, file_minor_version,
               file_size_bytes);
NANOM_DESCRIBE(nanom_formats::lance::DataFragment, unknown, id, files, deletion_file, physical_rows);
NANOM_DESCRIBE(nanom_formats::lance::DataStorageFormat, file_format, version);
NANOM_DESCRIBE(nanom_formats::lance::WriterVersion, library, version);
NANOM_DESCRIBE(nanom_formats::lance::Manifest, unknown, fields, fragments, version, version_aux_data, schema_metadata,
               index_section, timestamp, tag, reader_feature_flags, writer_feature_flags, max_fragment_id,
               transaction_file, writer_version, next_row_id, data_format, config, table_metadata,
               transaction_section);
NANOM_DESCRIBE(nanom_formats::lance::IndexSection, indices);
NANOM_DESCRIBE(nanom_formats::lance::Uuid, uuid);
NANOM_DESCRIBE(nanom_formats::lance::IndexFile, unknown, path, size);
NANOM_DESCRIBE(nanom_formats::lance::IndexMetadata, unknown, uuid, fields, name, dataset_version, fragment_bitmap,
               index_details, index_version, created_at, files);

#endif  // NANOM_FORMATS_LANCE_PROTOBUF_HPP_INCLUDED
