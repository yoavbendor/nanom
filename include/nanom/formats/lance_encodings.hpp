// SPDX-License-Identifier: Apache-2.0
// nanom/formats/lance_encodings.hpp — Lance's page encodings (protobuf) as reflected nanom
// messages: the format 2.1+ PageLayout / CompressiveEncoding tree (lance.encodings21) and the
// format 2.0 ArrayEncoding tree (lance.encodings).
//
// Every data page of a Lance file carries one of these, wrapped in an Any-style message
// ({1: type_url, 2: value}), in ColumnMetadata.Page.encoding (nanom/formats/lance_protobuf.hpp):
//
//   auto any = nm::protobuf<lance::EncodingAny>()(page_encoding_bytes);    // the wrapper
//   auto layout = nm::protobuf<lance::PageLayout>()(nm::from(*any->value.value));
//
// Both trees are recursive (an encoding wraps another), so every CompressiveEncoding / ArrayEncoding
// a message refers to is an nm::pb_lazy<>: its bytes are checked to fit when the parent is read,
// and decoded when a reader walks into them (child.decode_into(node)), which keeps a decode free of
// allocations and the decoded structs small however deep the tree. A
// reader walking the tree bounds its depth. A oneof is a set of std::optional members, at most one
// of which a valid message sets. Scalars are
// declared std::uint64_t so a reader decides how to narrow them (Lance's own readers cast).
// Variants not declared here (new ones Lance adds) are kept in `unknown`, so a reader can refuse
// them by field number instead of misreading the page.
//
// Field numbers follow lance-format/lance's protos/encodings_v2_1.proto and encodings_v2_0.proto,
// as nanolance verified them against files written by Lance itself.
#ifndef NANOM_FORMATS_LANCE_ENCODINGS_HPP_INCLUDED
#define NANOM_FORMATS_LANCE_ENCODINGS_HPP_INCLUDED

#include "../protobuf.hpp"

namespace nanom_formats::lance {
using namespace ::nanom;

template <std::uint16_t Id, class T>
using pfe = field<Id, T, presence::defaulted>;

/// The wrapper around a page's encoding: {1: type_url ("/lance.encodings21.PageLayout" or
/// "/lance.encodings.ArrayEncoding"), 2: the encoded message}.
struct EncodingAny {
  pfe<1, std::string_view> type_url;
  field<2, std::optional<bytes>> value;
};

// --- format 2.1+: lance.encodings21 -----------------------------------------------------------

struct CompressiveEncoding;

/// Flat{ bits_per_value }: fixed-width values, as they are.
struct Flat {
  pfe<1, std::uint64_t> bits_per_value;
};
/// Variable{ offsets }: variable-width values, with how their offsets are stored.
struct Variable {
  pfe<1, pb_lazy<CompressiveEncoding>> offsets;
};
/// OutOfLineBitpacking{ uncompressed_bits_per_value, values } (field 4 of CompressiveEncoding; the
/// wrapper Lance puts around definition / repetition levels).
struct OutOfLineBitpacking {
  pfe<1, std::uint64_t>               uncompressed_bits_per_value;
  pfe<3, pb_lazy<CompressiveEncoding>> values;
};
/// InlineBitpacking{ uncompressed_bits_per_value }: FastLanes blocks, the width in each block.
struct InlineBitpacking {
  pfe<1, std::uint64_t> uncompressed_bits_per_value;
};
/// Fsst{ symbol_table, values }.
struct Fsst {
  pfe<1, bytes>                       symbol_table;
  pfe<2, pb_lazy<CompressiveEncoding>> values;
};
/// Rle{ values, run_lengths }.
struct Rle {
  pfe<1, pb_lazy<CompressiveEncoding>> values;
  pfe<2, pb_lazy<CompressiveEncoding>> run_lengths;
};
/// ByteStreamSplit{ values }.
struct ByteStreamSplit {
  pfe<1, pb_lazy<CompressiveEncoding>> values;
};
/// BufferCompression{ scheme (CompressionScheme: 0 none, 1 lz4, 2 zstd), level }.
struct BufferCompression {
  pfe<1, std::uint64_t>                  scheme;
  field<2, std::optional<std::int32_t>>  level;
};
/// General{ compression, values }: a general-purpose compressor over another encoding's buffers.
struct General {
  field<1, std::optional<BufferCompression>> compression;
  pfe<3, pb_lazy<CompressiveEncoding>>        values;
};
/// FixedSizeList{ items_per_value, values, has_validity }: N consecutive values are one row.
struct FixedSizeList21 {
  pfe<1, std::uint64_t>               items_per_value;
  pfe<2, pb_lazy<CompressiveEncoding>> values;
  pfe<3, std::uint64_t>               has_validity;  ///< a bool on the wire; any non-zero is true
};

/// The oneof of compressive encodings. Undeclared variants are kept in `unknown`.
struct CompressiveEncoding {
  pb_unknown                              unknown;
  field<1, std::optional<Flat>>           flat;
  field<2, std::optional<Variable>>       variable;
  field<4, std::optional<OutOfLineBitpacking>> out_of_line_bitpacking;
  field<5, std::optional<InlineBitpacking>>    inline_bitpacking;
  field<6, std::optional<Fsst>>           fsst;
  field<8, std::optional<Rle>>            rle;
  field<9, std::optional<ByteStreamSplit>> byte_stream_split;
  field<10, std::optional<General>>       general;
  field<11, std::optional<FixedSizeList21>> fixed_size_list;
};

/// The values of a page cut into mini-blocks (the usual layout).
struct MiniBlockLayout {
  pfe<1, pb_lazy<CompressiveEncoding>>         rep_compression;
  pfe<2, pb_lazy<CompressiveEncoding>>         def_compression;
  pfe<3, pb_lazy<CompressiveEncoding>>         value_compression;
  pfe<4, pb_lazy<CompressiveEncoding>>         dictionary;
  pfe<5, std::uint64_t>                        num_dictionary_items;
  pfe<6, bytes>                                layers;  ///< packed RepDefLayer values, one byte each
  pfe<7, std::uint64_t>                        num_buffers;
  pfe<8, std::uint64_t>                        repetition_index_depth;
  pfe<9, std::uint64_t>                        num_items;
  pfe<10, std::uint64_t>                       has_large_chunk;  ///< a bool on the wire
};
/// One value for the whole page (inline, or in a buffer), with optional levels.
struct ConstantLayout {
  pfe<5, bytes>                                layers;
  field<6, std::optional<bytes>>               inline_value;
  pfe<7, pb_lazy<CompressiveEncoding>>         rep_compression;
  pfe<8, pb_lazy<CompressiveEncoding>>         def_compression;
  pfe<9, std::uint64_t>                        num_rep_values;
  pfe<10, std::uint64_t>                       num_def_values;
};
/// Large values stored row by row, each behind a control word of levels.
struct FullZipLayout {
  pfe<1, std::uint64_t>                        bits_rep;
  pfe<2, std::uint64_t>                        bits_def;
  pfe<3, std::uint64_t>                        bits_per_value;
  pfe<4, std::uint64_t>                        bits_per_offset;
  pfe<5, std::uint64_t>                        num_items;
  pfe<6, std::uint64_t>                        num_visible_items;
  pfe<7, pb_lazy<CompressiveEncoding>>         value_compression;
  pfe<8, bytes>                                layers;
};
/// The oneof of page layouts. Undeclared ones (BlobLayout 4, SparseLayout 5, ...) stay in `unknown`.
struct PageLayout {
  pb_unknown                              unknown;
  field<1, std::optional<MiniBlockLayout>> mini_block_layout;
  field<2, std::optional<ConstantLayout>>  constant_layout;
  field<3, std::optional<FullZipLayout>>   full_zip_layout;
};

// --- format 2.0: lance.encodings --------------------------------------------------------------

struct ArrayEncoding;

/// Buffer{ buffer_index, buffer_type (0 page, 1 column, 2 file) }.
struct Buffer {
  pfe<1, std::uint64_t> buffer_index;
  pfe<2, std::uint64_t> buffer_type;
};
struct Compression {
  pfe<1, std::string_view> scheme;
};
struct Flat20 {
  pfe<1, std::uint64_t>                  bits_per_value;
  field<2, std::optional<Buffer>>        buffer;
  field<3, std::optional<Compression>>   compression;
};
struct NoNull {
  pfe<1, pb_lazy<ArrayEncoding>> values;
};
struct SomeNull {
  pfe<1, pb_lazy<ArrayEncoding>> validity;
  pfe<2, pb_lazy<ArrayEncoding>> values;
};
using AllNull = empty_struct;
/// Nullable{ oneof: no_nulls, some_nulls, all_nulls }.
struct Nullable {
  pb_unknown                        unknown;  ///< a member this model does not declare
  field<1, std::optional<NoNull>>   no_nulls;
  field<2, std::optional<SomeNull>> some_nulls;
  field<3, std::optional<AllNull>>  all_nulls;
};
struct FixedSizeList20 {
  pfe<1, std::uint64_t>         dimension;
  pfe<2, pb_lazy<ArrayEncoding>> items;
  pfe<3, std::uint64_t>         has_validity;
};
struct List20 {
  pfe<1, pb_lazy<ArrayEncoding>> offsets;
  pfe<2, std::uint64_t>         null_offset_adjustment;
  pfe<3, std::uint64_t>         num_items;
};
using SimpleStruct = empty_struct;
struct Binary {
  pfe<1, pb_lazy<ArrayEncoding>> indices;
  pfe<2, pb_lazy<ArrayEncoding>> bytes;
  pfe<3, std::uint64_t>         null_adjustment;
};
struct Dictionary20 {
  pfe<1, pb_lazy<ArrayEncoding>> indices;
  pfe<2, pb_lazy<ArrayEncoding>> items;
  pfe<3, std::uint64_t>         num_dictionary_items;
};
struct Fsst20 {
  pfe<1, pb_lazy<ArrayEncoding>> binary;
  pfe<2, nanom::bytes>          symbol_table;
};
struct PackedStruct {
  pfe<1, std::vector<ArrayEncoding>> inner;
  field<2, std::optional<Buffer>>    buffer;
};
struct Bitpacked20 {
  pfe<1, std::uint64_t>           compressed_bits_per_value;
  pfe<2, std::uint64_t>           uncompressed_bits_per_value;
  field<3, std::optional<Buffer>> buffer;
  pfe<4, std::uint64_t>           signed_;  ///< a bool on the wire
};
struct FixedSizeBinary {
  pfe<1, pb_lazy<ArrayEncoding>> bytes;
  pfe<2, std::uint64_t>         byte_width;
};
struct BitpackedForNonNeg {
  pfe<1, std::uint64_t>           compressed_bits_per_value;
  pfe<2, std::uint64_t>           uncompressed_bits_per_value;
  field<3, std::optional<Buffer>> buffer;
};
struct Constant20 {
  pfe<1, nanom::bytes> value;
};
/// The oneof of format 2.0 array encodings. Undeclared variants stay in `unknown`.
struct ArrayEncoding {
  pb_unknown                                  unknown;
  field<1, std::optional<Flat20>>             flat;
  field<2, std::optional<Nullable>>           nullable;
  field<3, std::optional<FixedSizeList20>>    fixed_size_list;
  field<4, std::optional<List20>>             list;
  field<5, std::optional<SimpleStruct>>       struct_;
  field<6, std::optional<Binary>>             binary;
  field<7, std::optional<Dictionary20>>       dictionary;
  field<8, std::optional<Fsst20>>             fsst;
  field<9, std::optional<PackedStruct>>       packed_struct;
  field<10, std::optional<Bitpacked20>>       bitpacked;
  field<11, std::optional<FixedSizeBinary>>   fixed_size_binary;
  field<12, std::optional<BitpackedForNonNeg>> bitpacked_for_non_neg;
  field<13, std::optional<Constant20>>        constant;
};

/// A format 2.0 column's own encoding (lance.encodings.ColumnEncoding): which variant it is is all a
/// reader needs; `blob` (field 3) marks a blob column. Other variants stay in `unknown`.
struct ColumnEncoding20 {
  pb_unknown                      unknown;
  field<3, std::optional<bytes>>  blob;
};

/// How many members of a oneof message are set (declared ones, plus length-delimited fields kept
/// in `unknown`, which in these messages are variants this model does not declare). A valid
/// message has at most one.
template <class M>
std::size_t oneof_members(const M& m) {
  std::size_t n = 0;
  detail::for_each_field<M>([&](auto f) {
    using V = typename detail::member_t<decltype(f)::mem_ptr>::value_type;
    const auto& v = (m.*(decltype(f)::mem_ptr)).v;
    if constexpr (std::is_same_v<V, unknown_fields>) {
      n += detail::pb::unknown_len_fields(v);
    } else if constexpr (detail::is_optional_t<V>::value || detail::is_box_t<V>::value) {
      n += v.has_value() ? 1 : 0;
    }
  });
  return n;
}

}  // namespace nanom_formats::lance

NANOM_DESCRIBE(nanom_formats::lance::EncodingAny, type_url, value);
NANOM_DESCRIBE(nanom_formats::lance::Flat, bits_per_value);
NANOM_DESCRIBE(nanom_formats::lance::Variable, offsets);
NANOM_DESCRIBE(nanom_formats::lance::OutOfLineBitpacking, uncompressed_bits_per_value, values);
NANOM_DESCRIBE(nanom_formats::lance::InlineBitpacking, uncompressed_bits_per_value);
NANOM_DESCRIBE(nanom_formats::lance::Fsst, symbol_table, values);
NANOM_DESCRIBE(nanom_formats::lance::Rle, values, run_lengths);
NANOM_DESCRIBE(nanom_formats::lance::ByteStreamSplit, values);
NANOM_DESCRIBE(nanom_formats::lance::BufferCompression, scheme, level);
NANOM_DESCRIBE(nanom_formats::lance::General, compression, values);
NANOM_DESCRIBE(nanom_formats::lance::FixedSizeList21, items_per_value, values, has_validity);
NANOM_DESCRIBE(nanom_formats::lance::CompressiveEncoding, unknown, flat, variable, out_of_line_bitpacking,
               inline_bitpacking, fsst, rle, byte_stream_split, general, fixed_size_list);
NANOM_DESCRIBE(nanom_formats::lance::MiniBlockLayout, rep_compression, def_compression, value_compression, dictionary,
               num_dictionary_items, layers, num_buffers, repetition_index_depth, num_items, has_large_chunk);
NANOM_DESCRIBE(nanom_formats::lance::ConstantLayout, layers, inline_value, rep_compression, def_compression,
               num_rep_values, num_def_values);
NANOM_DESCRIBE(nanom_formats::lance::FullZipLayout, bits_rep, bits_def, bits_per_value, bits_per_offset, num_items,
               num_visible_items, value_compression, layers);
NANOM_DESCRIBE(nanom_formats::lance::PageLayout, unknown, mini_block_layout, constant_layout, full_zip_layout);
NANOM_DESCRIBE(nanom_formats::lance::Buffer, buffer_index, buffer_type);
NANOM_DESCRIBE(nanom_formats::lance::Compression, scheme);
NANOM_DESCRIBE(nanom_formats::lance::Flat20, bits_per_value, buffer, compression);
NANOM_DESCRIBE(nanom_formats::lance::NoNull, values);
NANOM_DESCRIBE(nanom_formats::lance::SomeNull, validity, values);
NANOM_DESCRIBE(nanom_formats::lance::Nullable, unknown, no_nulls, some_nulls, all_nulls);
NANOM_DESCRIBE(nanom_formats::lance::FixedSizeList20, dimension, items, has_validity);
NANOM_DESCRIBE(nanom_formats::lance::List20, offsets, null_offset_adjustment, num_items);
NANOM_DESCRIBE(nanom_formats::lance::Binary, indices, bytes, null_adjustment);
NANOM_DESCRIBE(nanom_formats::lance::Dictionary20, indices, items, num_dictionary_items);
NANOM_DESCRIBE(nanom_formats::lance::Fsst20, binary, symbol_table);
NANOM_DESCRIBE(nanom_formats::lance::PackedStruct, inner, buffer);
NANOM_DESCRIBE(nanom_formats::lance::Bitpacked20, compressed_bits_per_value, uncompressed_bits_per_value, buffer, signed_);
NANOM_DESCRIBE(nanom_formats::lance::FixedSizeBinary, bytes, byte_width);
NANOM_DESCRIBE(nanom_formats::lance::BitpackedForNonNeg, compressed_bits_per_value, uncompressed_bits_per_value, buffer);
NANOM_DESCRIBE(nanom_formats::lance::Constant20, value);
NANOM_DESCRIBE(nanom_formats::lance::ColumnEncoding20, unknown, blob);
NANOM_DESCRIBE(nanom_formats::lance::ArrayEncoding, unknown, flat, nullable, fixed_size_list, list, struct_, binary,
               dictionary, fsst, packed_struct, bitpacked, fixed_size_binary, bitpacked_for_non_neg, constant);

#endif  // NANOM_FORMATS_LANCE_ENCODINGS_HPP_INCLUDED
