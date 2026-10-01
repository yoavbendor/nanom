// SPDX-License-Identifier: Apache-2.0
// nanom/formats/parquet_thrift.hpp — the Parquet file metadata (parquet.thrift) as reflected
// nanom tagged messages, plus the footer locator.
//
// This is the shared model the Parquet reader (parquet2nanoarrow) and writer (nanoarrow2parquet)
// both build on: one declaration per Thrift struct, decoded and encoded by nanom/tagged.hpp's
// Thrift compact codec. Only the fields a reader needs are declared; everything else (encryption,
// geospatial and size statistics, …) is skipped structurally, so newer writers stay readable.
//
// Field ids and types follow apache/parquet-format's parquet.thrift. Enums are OPEN (int32-backed):
// an enumerator a newer writer added round-trips as its number instead of failing the decode.
//
// The model lives in nanom_formats::parquet, not under nanom::, on purpose: C++26 reflection
// auto-describes only types outside the library's own namespace (see nanom26.hpp), so these structs
// need no registration there; under C++23 the NANOM_DESCRIBE lines at the bottom register them.
//
// Zero-copy: strings and binaries are views into the footer buffer; repeated members are lazy
// nm::list<> views, so e.g. `meta.row_groups->at(7)` decodes one row group out of thousands without
// touching the rest. The footer buffer must outlive every view taken from it.
#ifndef NANOM_FORMATS_PARQUET_THRIFT_HPP_INCLUDED
#define NANOM_FORMATS_PARQUET_THRIFT_HPP_INCLUDED

#include "../tagged.hpp"

namespace nanom_formats::parquet {
using namespace ::nanom;  // the model is plain user-side code: field<>, list<>, bytes, …

template <std::uint16_t Id, class T>
using opt = field<Id, std::optional<T>>;

enum class Type : std::int32_t {
  BOOLEAN = 0, INT32 = 1, INT64 = 2, INT96 = 3, FLOAT = 4, DOUBLE = 5, BYTE_ARRAY = 6,
  FIXED_LEN_BYTE_ARRAY = 7
};
enum class ConvertedType : std::int32_t {
  UTF8 = 0, MAP = 1, MAP_KEY_VALUE = 2, LIST = 3, ENUM = 4, DECIMAL = 5, DATE = 6,
  TIME_MILLIS = 7, TIME_MICROS = 8, TIMESTAMP_MILLIS = 9, TIMESTAMP_MICROS = 10, UINT_8 = 11,
  UINT_16 = 12, UINT_32 = 13, UINT_64 = 14, INT_8 = 15, INT_16 = 16, INT_32 = 17, INT_64 = 18,
  JSON = 19, BSON = 20, INTERVAL = 21
};
enum class FieldRepetitionType : std::int32_t { REQUIRED = 0, OPTIONAL = 1, REPEATED = 2 };
enum class Encoding : std::int32_t {
  PLAIN = 0, PLAIN_DICTIONARY = 2, RLE = 3, BIT_PACKED = 4, DELTA_BINARY_PACKED = 5,
  DELTA_LENGTH_BYTE_ARRAY = 6, DELTA_BYTE_ARRAY = 7, RLE_DICTIONARY = 8, BYTE_STREAM_SPLIT = 9
};
enum class CompressionCodec : std::int32_t {
  UNCOMPRESSED = 0, SNAPPY = 1, GZIP = 2, LZO = 3, BROTLI = 4, LZ4 = 5, ZSTD = 6, LZ4_RAW = 7
};
enum class PageType : std::int32_t {
  DATA_PAGE = 0, INDEX_PAGE = 1, DICTIONARY_PAGE = 2, DATA_PAGE_V2 = 3
};
enum class BoundaryOrder : std::int32_t { UNORDERED = 0, ASCENDING = 1, DESCENDING = 2 };

struct Statistics {
  opt<1, bytes>         max;
  opt<2, bytes>         min;
  opt<3, std::int64_t>  null_count;
  opt<4, std::int64_t>  distinct_count;
  opt<5, bytes>         max_value;
  opt<6, bytes>         min_value;
  opt<7, bool>          is_max_value_exact;
  opt<8, bool>          is_min_value_exact;
};

struct DecimalType {
  field<1, std::int32_t> scale;
  field<2, std::int32_t> precision;
};
/// union TimeUnit { 1: MilliSeconds MILLIS 2: MicroSeconds MICROS 3: NanoSeconds NANOS }
struct TimeUnit {
  opt<1, empty_struct> MILLIS;
  opt<2, empty_struct> MICROS;
  opt<3, empty_struct> NANOS;
};
struct TimestampType {
  field<1, bool>     isAdjustedToUTC;
  field<2, TimeUnit> unit;
};
struct TimeType {
  field<1, bool>     isAdjustedToUTC;
  field<2, TimeUnit> unit;
};
struct IntType {
  field<1, std::int8_t> bitWidth;
  field<2, bool>        isSigned;
};
/// union LogicalType — exactly one member is set by a conforming writer.
struct LogicalType {
  opt<1, empty_struct>  STRING;
  opt<2, empty_struct>  MAP;
  opt<3, empty_struct>  LIST;
  opt<4, empty_struct>  ENUM;
  opt<5, DecimalType>   DECIMAL;
  opt<6, empty_struct>  DATE;
  opt<7, TimeType>      TIME;
  opt<8, TimestampType> TIMESTAMP;
  opt<10, IntType>      INTEGER;
  opt<11, empty_struct> UNKNOWN;
  opt<12, empty_struct> JSON;
  opt<13, empty_struct> BSON;
  opt<14, empty_struct> UUID;
  opt<15, empty_struct> FLOAT16;
};

struct SchemaElement {
  opt<1, Type>                 type;
  opt<2, std::int32_t>         type_length;
  opt<3, FieldRepetitionType>  repetition_type;
  field<4, std::string_view>   name;
  opt<5, std::int32_t>         num_children;
  opt<6, ConvertedType>        converted_type;
  opt<7, std::int32_t>         scale;
  opt<8, std::int32_t>         precision;
  opt<9, std::int32_t>         field_id;
  opt<10, LogicalType>         logicalType;
};

struct KeyValue {
  field<1, std::string_view> key;
  opt<2, std::string_view>   value;
};

struct SortingColumn {
  field<1, std::int32_t> column_idx;
  field<2, bool>         descending;
  field<3, bool>         nulls_first;
};

struct PageEncodingStats {
  field<1, PageType>     page_type;
  field<2, Encoding>     encoding;
  field<3, std::int32_t> count;
};

struct ColumnMetaData {
  field<1, Type>                     type;
  field<2, list<Encoding>>           encodings;
  field<3, list<std::string_view>>   path_in_schema;
  field<4, CompressionCodec>         codec;
  field<5, std::int64_t>             num_values;
  field<6, std::int64_t>             total_uncompressed_size;
  field<7, std::int64_t>             total_compressed_size;
  opt<8, list<KeyValue>>             key_value_metadata;
  field<9, std::int64_t>             data_page_offset;
  opt<10, std::int64_t>              index_page_offset;
  opt<11, std::int64_t>              dictionary_page_offset;
  opt<12, Statistics>                statistics;
  opt<13, list<PageEncodingStats>>   encoding_stats;
  opt<14, std::int64_t>              bloom_filter_offset;
  opt<15, std::int32_t>              bloom_filter_length;
};

struct ColumnChunk {
  opt<1, std::string_view>     file_path;
  field<2, std::int64_t, presence::defaulted> file_offset;  // deprecated; some writers omit it
  opt<3, ColumnMetaData>       meta_data;
  opt<4, std::int64_t>         offset_index_offset;
  opt<5, std::int32_t>         offset_index_length;
  opt<6, std::int64_t>         column_index_offset;
  opt<7, std::int32_t>         column_index_length;
};

struct RowGroup {
  field<1, list<ColumnChunk>>   columns;
  field<2, std::int64_t>        total_byte_size;
  field<3, std::int64_t>        num_rows;
  opt<4, list<SortingColumn>>   sorting_columns;
  opt<5, std::int64_t>          file_offset;
  opt<6, std::int64_t>          total_compressed_size;
  opt<7, std::int16_t>          ordinal;
};

/// union ColumnOrder { 1: TypeDefinedOrder TYPE_ORDER }
struct ColumnOrder {
  opt<1, empty_struct> TYPE_ORDER;
};

struct FileMetaData {
  field<1, std::int32_t>         version;
  field<2, list<SchemaElement>>  schema;
  field<3, std::int64_t>         num_rows;
  field<4, list<RowGroup>>       row_groups;
  opt<5, list<KeyValue>>         key_value_metadata;
  opt<6, std::string_view>       created_by;
  opt<7, list<ColumnOrder>>      column_orders;
};

// ---- page headers (one precedes every page inside a column chunk) -------------------------------

struct DataPageHeader {
  field<1, std::int32_t> num_values;
  field<2, Encoding>     encoding;
  field<3, Encoding>     definition_level_encoding;
  field<4, Encoding>     repetition_level_encoding;
  opt<5, Statistics>     statistics;
};
struct DictionaryPageHeader {
  field<1, std::int32_t> num_values;
  field<2, Encoding>     encoding;
  opt<3, bool>           is_sorted;
};
struct DataPageHeaderV2 {
  field<1, std::int32_t> num_values;
  field<2, std::int32_t> num_nulls;
  field<3, std::int32_t> num_rows;
  field<4, Encoding>     encoding;
  field<5, std::int32_t> definition_levels_byte_length;
  field<6, std::int32_t> repetition_levels_byte_length;
  opt<7, bool>           is_compressed;   // absent means true
  opt<8, Statistics>     statistics;
};
struct PageHeader {
  field<1, PageType>          type;
  field<2, std::int32_t>      uncompressed_page_size;
  field<3, std::int32_t>      compressed_page_size;
  opt<4, std::int32_t>        crc;
  opt<5, DataPageHeader>      data_page_header;
  opt<6, empty_struct>        index_page_header;
  opt<7, DictionaryPageHeader> dictionary_page_header;
  opt<8, DataPageHeaderV2>    data_page_header_v2;
};

// ---- page index (ColumnIndex / OffsetIndex, located by ColumnChunk offsets) --------------------

struct PageLocation {
  field<1, std::int64_t> offset;
  field<2, std::int32_t> compressed_page_size;
  field<3, std::int64_t> first_row_index;
};
struct OffsetIndex {
  field<1, list<PageLocation>> page_locations;
  opt<2, list<std::int64_t>>   unencoded_byte_array_data_bytes;
};
struct ColumnIndex {
  field<1, list<bool>>          null_pages;
  field<2, list<bytes>>         min_values;
  field<3, list<bytes>>         max_values;
  field<4, BoundaryOrder>       boundary_order;
  opt<5, list<std::int64_t>>    null_counts;
};

}  // namespace nanom_formats::parquet

NANOM_DESCRIBE(nanom_formats::parquet::Statistics, max, min, null_count, distinct_count, max_value,
               min_value, is_max_value_exact, is_min_value_exact);
NANOM_DESCRIBE(nanom_formats::parquet::DecimalType, scale, precision);
NANOM_DESCRIBE(nanom_formats::parquet::TimeUnit, MILLIS, MICROS, NANOS);
NANOM_DESCRIBE(nanom_formats::parquet::TimestampType, isAdjustedToUTC, unit);
NANOM_DESCRIBE(nanom_formats::parquet::TimeType, isAdjustedToUTC, unit);
NANOM_DESCRIBE(nanom_formats::parquet::IntType, bitWidth, isSigned);
NANOM_DESCRIBE(nanom_formats::parquet::LogicalType, STRING, MAP, LIST, ENUM, DECIMAL, DATE, TIME,
               TIMESTAMP, INTEGER, UNKNOWN, JSON, BSON, UUID, FLOAT16);
NANOM_DESCRIBE(nanom_formats::parquet::SchemaElement, type, type_length, repetition_type, name,
               num_children, converted_type, scale, precision, field_id, logicalType);
NANOM_DESCRIBE(nanom_formats::parquet::KeyValue, key, value);
NANOM_DESCRIBE(nanom_formats::parquet::SortingColumn, column_idx, descending, nulls_first);
NANOM_DESCRIBE(nanom_formats::parquet::PageEncodingStats, page_type, encoding, count);
NANOM_DESCRIBE(nanom_formats::parquet::ColumnMetaData, type, encodings, path_in_schema, codec, num_values,
               total_uncompressed_size, total_compressed_size, key_value_metadata,
               data_page_offset, index_page_offset, dictionary_page_offset, statistics,
               encoding_stats, bloom_filter_offset, bloom_filter_length);
NANOM_DESCRIBE(nanom_formats::parquet::ColumnChunk, file_path, file_offset, meta_data,
               offset_index_offset, offset_index_length, column_index_offset,
               column_index_length);
NANOM_DESCRIBE(nanom_formats::parquet::RowGroup, columns, total_byte_size, num_rows, sorting_columns,
               file_offset, total_compressed_size, ordinal);
NANOM_DESCRIBE(nanom_formats::parquet::ColumnOrder, TYPE_ORDER);
NANOM_DESCRIBE(nanom_formats::parquet::FileMetaData, version, schema, num_rows, row_groups,
               key_value_metadata, created_by, column_orders);
NANOM_DESCRIBE(nanom_formats::parquet::DataPageHeader, num_values, encoding, definition_level_encoding,
               repetition_level_encoding, statistics);
NANOM_DESCRIBE(nanom_formats::parquet::DictionaryPageHeader, num_values, encoding, is_sorted);
NANOM_DESCRIBE(nanom_formats::parquet::DataPageHeaderV2, num_values, num_nulls, num_rows, encoding,
               definition_levels_byte_length, repetition_levels_byte_length, is_compressed,
               statistics);
NANOM_DESCRIBE(nanom_formats::parquet::PageHeader, type, uncompressed_page_size, compressed_page_size, crc,
               data_page_header, index_page_header, dictionary_page_header, data_page_header_v2);
NANOM_DESCRIBE(nanom_formats::parquet::PageLocation, offset, compressed_page_size, first_row_index);
NANOM_DESCRIBE(nanom_formats::parquet::OffsetIndex, page_locations, unencoded_byte_array_data_bytes);
NANOM_DESCRIBE(nanom_formats::parquet::ColumnIndex, null_pages, min_values, max_values, boundary_order,
               null_counts);

// The footer helpers come after the registrations above: they instantiate the codec for
// FileMetaData, which needs every describe<> specialization to be visible.
namespace nanom_formats::parquet {

inline constexpr std::string_view magic = "PAR1";
inline constexpr std::string_view encrypted_footer_magic = "PARE";

/// Where the footer sits: the 4-byte little-endian length + "PAR1" trailer at the end of the file.
struct footer_location {
  std::uint64_t metadata_offset;  ///< absolute file offset of the Thrift FileMetaData
  std::uint32_t metadata_length;
};

/// Locate the footer from the last 8 bytes of a file of `file_size` bytes (works with a ranged
/// read of just the tail: pass those 8 bytes). Validates the magic and that the metadata (plus the
/// leading "PAR1") fits inside the file.
inline result<footer_location> locate_footer(input tail8, std::uint64_t file_size) {
  if (tail8.size() < 8) return make_incomplete(tail8, 8 - tail8.size());
  const input t = tail8.advance(tail8.size() - 8);
  auto len = le_u32(t);
  if (!len) return unexp(len.error());
  const std::string_view m = as_str(len->rest.take_span(4));
  if (m == encrypted_footer_magic)
    return make_err(t, "a plaintext Parquet footer (encrypted footers are not supported)");
  if (m != magic) return make_err(len->rest, "Parquet magic \"PAR1\"");
  if (file_size < 12 || len->value > file_size - 12)
    return make_err(t, "a Parquet footer length that fits inside the file");
  return done{footer_location{file_size - 8 - len->value, len->value}, t.advance(8)};
}

/// Decode the FileMetaData of a whole Parquet file held in memory (e.g. mmap'd). The returned
/// views point into `file`.
inline result<FileMetaData> read_file_metadata(input file) {
  auto loc = locate_footer(file, file.size());
  if (!loc) return unexp(loc.error());
  if (file.size() < 4 || as_str(file.take_span(4)) != magic)
    return make_err(file, "leading Parquet magic \"PAR1\"");
  const input meta = file.advance(std::size_t(loc->value.metadata_offset));
  const input exact = meta.with_range(meta.first, meta.first + loc->value.metadata_length);
  auto r = thrift_compact<FileMetaData>()(exact);
  if (!r) return r;
  if (!r->rest.empty()) return make_err(r->rest, "FileMetaData to span the whole footer");
  return done{std::move(r->value), meta.advance(meta.size())};
}

}  // namespace nanom_formats::parquet

#endif  // NANOM_FORMATS_PARQUET_THRIFT_HPP_INCLUDED
