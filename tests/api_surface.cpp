// SPDX-License-Identifier: Apache-2.0
// nanom public API surface: one translation unit that names every documented public entity once,
// with the shape the docs give it (README, docs/CHEATSHEET.md, docs/WRITERS.md,
// docs/RUNTIME_COMPOSE.md, docs/LAYOUT_GUIDE.md, docs/NANO_SHARK.md and the header banners).
//
// The point is the compile: a rename, a removal or a signature change of a public entity fails
// HERE, with a static_assert message or an unresolved name that says what moved. It deliberately
// pins only what is documented: no internal types (nothing from a `detail` namespace), no sizes or
// layouts unless the docs promise them, and return types only where the docs name them. Function
// pointers spell exact parameter lists for non-template functions; templates are checked through
// representative calls in unevaluated contexts. It also runs (trivially) under ctest
// (nanom_api_surface), so it is built in every CI configuration.
//
// Organized by header, in the order of the README's "Library layout" table.
#include <nanom/checksum.hpp>
#include <nanom/craft.hpp>
#include <nanom/emit.hpp>
#include <nanom/layout.hpp>
#include <nanom/nanom.hpp>
#include <nanom/sink.hpp>
#include <nanom_shark/nanom_shark.hpp>

#include <concepts>
#include <cstdio>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

namespace nm = nanom;
namespace nc = nanom::craft;
namespace lay = nanom::layout;
namespace e2e = nanom::layout::e2e;

// Spell "same type" checks with a readable failure.
#define API_SAME(what, ...) static_assert(std::is_same_v<__VA_ARGS__>, "nanom API changed: " what)
#define API(what, ...) static_assert((__VA_ARGS__), "nanom API changed: " what)

// Representative described structs (as the README tour writes them).
struct api_hdr {
  nm::be<std::uint16_t> a;
  nm::ubits<4> hi;
  nm::ubits<4, nm::bit_order::msb0> lo;
  nm::le<std::uint32_t> b;
  nm::be_u24_t len24;
  nm::ibits<8> s;
  std::array<std::uint8_t, 2> pad;
};
NANOM_DESCRIBE(api_hdr, a, hi, lo, b, len24, s, pad);

struct api_outer {
  std::uint8_t tag;
  api_hdr inner;
};
NANOM_DESCRIBE(api_outer, tag, inner);

struct plain {  // no computed fields, no narrow bit fields: to_bytes_exact applies
  nm::be<std::uint16_t> x;
  std::array<std::uint8_t, 2> y;
};
NANOM_DESCRIBE(plain, x, y);

struct api_len {
  nm::be<std::uint16_t> length, csum;
};
NANOM_DESCRIBE(api_len, length, csum);
template <>
struct nm::computed<api_len> {
  static constexpr auto fields = std::tuple{
      nm::calc<"length">([](const api_len&, const nm::emit_ctx& c) { return 4 + c.payload.size(); }),
      nm::checksum<"csum">([](std::span<const std::byte> h, const nm::emit_ctx&) { return nm::inet::checksum(h); }),
  };
};

namespace api {

template <class P, class T>
concept parser_of = nm::Parser<P> && std::same_as<nm::parsed_t<P>, T>;

// =====================================================================================
// nanom/nom.hpp — the rust-nom parallel (docs/CHEATSHEET.md)
// =====================================================================================
namespace nom_surface {
API_SAME("from(string_view) -> input", decltype(nm::from(std::string_view{})), nm::input);
API_SAME("from(span) -> input", decltype(nm::from(std::span<const std::byte>{})), nm::input);
#if !NANOM_STRICT  // the strict profile removes the raw-pointer entry (tests/strict_neg proves it)
API_SAME("from(ptr, len)", decltype(nm::from(static_cast<const void*>(nullptr), std::size_t{})), nm::input);
#endif
API_SAME("streaming(input)", decltype(nm::streaming(nm::input{})), nm::input);
API_SAME("result<T> = expected<done<T>, error>", nm::result<int>, nm::expected<nm::done<int>, nm::error>);
API("done{value, rest}", requires(nm::done<int> d) { d.value; d.rest; });
API("error::render / kind / needed", requires(nm::error e, nm::input in) {
  { e.render(in) } -> std::convertible_to<std::string>;
  e.kind;
  e.needed;
});
API("errk::{err, fail, incomplete}", nm::errk::err != nm::errk::fail && nm::errk::fail != nm::errk::incomplete);
API_SAME("as_str(bytes)", decltype(nm::as_str(std::declval<nm::bytes>())), std::string_view);
API("make_err / unexp / unit", requires(nm::input in) { nm::make_err(in, "x"); nm::unexp(nm::error{}); nm::unit{}; });
API("cursor", requires(nm::cursor c) { c.next(nm::u8); c.take(std::size_t{1}); c.rest(); c.empty(); });

// bytes
API("tag", parser_of<decltype(nm::tag("ab")), nm::bytes>);
API("tag_no_case", nm::Parser<decltype(nm::tag_no_case("ab"))>);
API("take", parser_of<decltype(nm::take(std::size_t{3})), nm::bytes>);
constexpr auto is_digit = [](std::uint8_t c) { return c >= '0' && c <= '9'; };
API("take_while / take_till / take_until / is_a / is_not", nm::Parser<decltype(nm::take_while(is_digit))> && nm::Parser<decltype(nm::take_while1(is_digit))> &&
        nm::Parser<decltype(nm::take_while_m_n(1, 2, is_digit))> && nm::Parser<decltype(nm::take_till(is_digit))> &&
        nm::Parser<decltype(nm::take_till1(is_digit))> && nm::Parser<decltype(nm::take_until("x"))> &&
        nm::Parser<decltype(nm::is_a("ab"))> && nm::Parser<decltype(nm::is_not("ab"))>);
// character
API("character parsers", parser_of<decltype(nm::chr('x')), char> && nm::Parser<decltype(nm::satisfy([](char) { return true; }))> &&
        nm::Parser<decltype(nm::one_of("ab"))> && nm::Parser<decltype(nm::none_of("ab"))> &&
        nm::Parser<decltype(nm::anychar)> && nm::Parser<decltype(nm::alpha0)> && nm::Parser<decltype(nm::alpha1)> &&
        nm::Parser<decltype(nm::digit0)> && nm::Parser<decltype(nm::digit1)> && nm::Parser<decltype(nm::hex_digit1)> &&
        nm::Parser<decltype(nm::oct_digit1)> && nm::Parser<decltype(nm::alphanumeric1)> &&
        nm::Parser<decltype(nm::space0)> && nm::Parser<decltype(nm::space1)> && nm::Parser<decltype(nm::multispace0)> &&
        nm::Parser<decltype(nm::multispace1)> && nm::Parser<decltype(nm::newline)> && nm::Parser<decltype(nm::tab)> &&
        nm::Parser<decltype(nm::crlf)> && nm::Parser<decltype(nm::line_ending)> &&
        nm::Parser<decltype(nm::not_line_ending)>);
// sequence / branch
API("seq -> tuple", parser_of<decltype(nm::seq(nm::u8, nm::u8)), std::tuple<std::uint8_t, std::uint8_t>>);
API("pair / separated_pair / preceded / terminated / delimited", nm::Parser<decltype(nm::pair(nm::u8, nm::u8))> && nm::Parser<decltype(nm::separated_pair(nm::u8, nm::u8, nm::u8))> &&
        parser_of<decltype(nm::preceded(nm::u8, nm::be_u16)), std::uint16_t> &&
        parser_of<decltype(nm::terminated(nm::be_u16, nm::u8)), std::uint16_t> &&
        parser_of<decltype(nm::delimited(nm::u8, nm::be_u16, nm::u8)), std::uint16_t>);
API("alt / permutation", parser_of<decltype(nm::alt(nm::tag("a"), nm::tag("b"))), nm::bytes> &&
        nm::Parser<decltype(nm::permutation(nm::u8, nm::be_u16))>);
// multi
API("many* / count / separated_list* / length_*", parser_of<decltype(nm::many0(nm::u8)), std::vector<std::uint8_t>> && nm::Parser<decltype(nm::many1(nm::u8))> &&
        nm::Parser<decltype(nm::many_m_n(1, 2, nm::u8))> && nm::Parser<decltype(nm::many_till(nm::u8, nm::eof))> &&
        nm::Parser<decltype(nm::count(nm::u8, 2))> && nm::Parser<decltype(nm::separated_list0(nm::u8, nm::u8))> &&
        nm::Parser<decltype(nm::separated_list1(nm::u8, nm::u8))> &&
        parser_of<decltype(nm::length_data(nm::u8)), nm::bytes> &&
        nm::Parser<decltype(nm::length_value(nm::u8, nm::be_u16))> &&
        nm::Parser<decltype(nm::length_count(nm::u8, nm::be_u16))>);
API("fold_many0/1/m_n accept both the mutating and the functional fold", nm::Parser<decltype(nm::fold_many0(nm::u8, [] { return 0; }, [](int a, std::uint8_t v) { return a + v; }))> &&
        nm::Parser<decltype(nm::fold_many0(nm::u8, [] { return 0; }, [](int& a, std::uint8_t v) { a += v; }))> &&
        nm::Parser<decltype(nm::fold_many1(nm::u8, [] { return 0; }, [](int a, std::uint8_t v) { return a + v; }))> &&
        nm::Parser<decltype(nm::fold_many_m_n(1, 3, nm::u8, [] { return 0; }, [](int a, std::uint8_t v) { return a + v; }))>);
// combinator
API("combinators", parser_of<decltype(nm::map(nm::u8, [](std::uint8_t v) { return int(v); })), int> &&
        nm::Parser<decltype(nm::map_res(nm::u8, [](std::uint8_t v) { return std::optional<int>(v); }))> &&
        nm::Parser<decltype(nm::map_opt(nm::u8, [](std::uint8_t v) { return std::optional<int>(v); }))> &&
        nm::Parser<decltype(nm::map_parser(nm::take(std::size_t{2}), nm::be_u16))> &&
        nm::Parser<decltype(nm::flat_map(nm::u8, [](std::uint8_t n) { return nm::take(n); }))> &&
        parser_of<decltype(nm::opt(nm::u8)), std::optional<std::uint8_t>> && nm::Parser<decltype(nm::cond(true, nm::u8))> &&
        nm::Parser<decltype(nm::peek(nm::u8))> && nm::Parser<decltype(nm::not_(nm::u8))> &&
        parser_of<decltype(nm::recognize(nm::u8)), nm::bytes> && nm::Parser<decltype(nm::consumed(nm::u8))> &&
        nm::Parser<decltype(nm::value(7, nm::u8))> &&
        nm::Parser<decltype(nm::verify(nm::u8, [](std::uint8_t v) { return v > 0; }))> &&
        nm::Parser<decltype(nm::success(1))> && nm::Parser<decltype(nm::fail())> &&
        nm::Parser<decltype(nm::cut(nm::u8))> && nm::Parser<decltype(nm::complete(nm::u8))> &&
        nm::Parser<decltype(nm::all_consuming(nm::u8))> && parser_of<decltype(nm::into<int>(nm::u8)), int> &&
        nm::Parser<decltype(nm::eof)> && nm::Parser<decltype(nm::rest)> && nm::Parser<decltype(nm::rest_len)> &&
        parser_of<decltype(nm::context("label", nm::u8)), std::uint8_t>);
API("parser | adaptor pipes (context)", nm::Parser<decltype(nm::u8 | nm::context("x"))>);
// numbers
API("binary numbers", parser_of<decltype(nm::u8), std::uint8_t> && parser_of<decltype(nm::i8), std::int8_t> &&
        parser_of<decltype(nm::be_u16), std::uint16_t> && parser_of<decltype(nm::be_u24), std::uint32_t> &&
        parser_of<decltype(nm::be_u32), std::uint32_t> && parser_of<decltype(nm::be_u48), std::uint64_t> &&
        parser_of<decltype(nm::be_u64), std::uint64_t> && parser_of<decltype(nm::le_u16), std::uint16_t> &&
        parser_of<decltype(nm::le_u24), std::uint32_t> && parser_of<decltype(nm::le_u32), std::uint32_t> &&
        parser_of<decltype(nm::le_u48), std::uint64_t> && parser_of<decltype(nm::le_u64), std::uint64_t> &&
        parser_of<decltype(nm::be_i16), std::int16_t> && parser_of<decltype(nm::be_i32), std::int32_t> &&
        parser_of<decltype(nm::be_i64), std::int64_t> && parser_of<decltype(nm::le_i16), std::int16_t> &&
        parser_of<decltype(nm::le_i32), std::int32_t> && parser_of<decltype(nm::le_i64), std::int64_t> &&
        parser_of<decltype(nm::be_f32), float> && parser_of<decltype(nm::be_f64), double> &&
        parser_of<decltype(nm::le_f32), float> && parser_of<decltype(nm::le_f64), double> &&
        nm::Parser<decltype(nm::ne_u16)> && nm::Parser<decltype(nm::ne_u32)> && nm::Parser<decltype(nm::ne_u64)> &&
        parser_of<decltype(nm::uint_<std::uint32_t>(std::endian::big)), std::uint32_t>);
API("variable-length integers", parser_of<decltype(nm::uleb128()), std::uint64_t> && parser_of<decltype(nm::sleb128()), std::int64_t> &&
        nm::Parser<decltype(nm::zigzag_varint<std::int32_t>())> && parser_of<decltype(nm::varint_u64), std::uint64_t> &&
        nm::Parser<decltype(nm::varint_u32)>);
API("text numbers", parser_of<decltype(nm::dec<std::uint32_t>()), std::uint32_t> &&
        parser_of<decltype(nm::hex<std::uint32_t>()), std::uint32_t> && parser_of<decltype(nm::float_), float> &&
        parser_of<decltype(nm::double_), double>);
// bits
API("bits / bseq / take_bits / tag_bits / bool_bit / bit_order", nm::Parser<decltype(nm::bits(nm::bseq(nm::take_bits<std::uint8_t>(4), nm::take_bits<std::uint8_t>(4, nm::bit_order::lsb0))))> &&
        nm::Parser<decltype(nm::bits(nm::tag_bits(0xA, 4)))> && nm::Parser<decltype(nm::bits(nm::bool_bit()))>);
}  // namespace nom_surface

// =====================================================================================
// nanom/dyn.hpp — parsers composed at run time (docs/RUNTIME_COMPOSE.md)
// =====================================================================================
namespace dyn_surface {
using D = nm::dyn<std::uint64_t>;
API("dyn<T> is a Parser of T", parser_of<D, std::uint64_t>);
API_SAME("dyn_parser<T> alias", nm::dyn_parser<std::uint64_t>, D);
API("any parser converts to dyn", std::is_convertible_v<decltype(nm::be_u16), D> && std::is_copy_constructible_v<D>);
API("alt(range)", parser_of<decltype(nm::alt(std::declval<std::vector<D>&>())), std::uint64_t>);
API("seq(range)", parser_of<decltype(nm::seq(std::declval<std::vector<D>&>())), std::vector<std::uint64_t>>);
API("seq_fold(range, init, f)", nm::Parser<decltype(nm::seq_fold(std::declval<std::vector<D>&>(), [] { return 0ull; },
                                     [](unsigned long long a, std::uint64_t v) { return a + v; }))>);
API("length_fold(np, p, init, f)", nm::Parser<decltype(nm::length_fold(nm::u8, D{}, [] { return 0ull; },
                                        [](unsigned long long a, std::uint64_t v) { return a + v; }))>);
API("dispatch(key, arms) / dispatch<T>(key, {...})", nm::Parser<decltype(nm::dispatch(nm::u8, std::declval<std::vector<std::pair<std::uint8_t, D>>&>()))> &&
        nm::Parser<decltype(nm::dispatch<std::uint64_t>(nm::u8, {{std::uint8_t{1}, D{}}}))>);
API("recursive<T>(build)", nm::Parser<decltype(nm::recursive<std::uint64_t>([](D self) { return self; }))>);
}  // namespace dyn_surface

// =====================================================================================
// nanom/reflect.hpp — wire types, describe<T>, strct / overlay / footer / view
// =====================================================================================
namespace reflect_surface {
API("Described concept / NANOM_DESCRIBE", nm::Described<api_hdr> && !nm::Described<int>);
API("describe<T>::fields() / name()", requires { nm::describe<api_hdr>::fields(); nm::describe<api_hdr>::name(); });
API_SAME("be<T>", nm::be<std::uint16_t>, nm::endian_scalar<std::uint16_t, std::endian::big>);
API_SAME("le<T>", nm::le<std::uint16_t>, nm::endian_scalar<std::uint16_t, std::endian::little>);
API_SAME("be_uint<3> == be_u24_t", nm::be_uint<3>, nm::be_u24_t);
API_SAME("le_uint<3> == le_u24_t", nm::le_uint<3>, nm::le_u24_t);
API_SAME("be_u48_t", nm::be_uint<6>, nm::be_u48_t);
API_SAME("le_u48_t", nm::le_uint<6>, nm::le_u48_t);
API("wire types convert to host values", std::is_convertible_v<nm::be<std::uint16_t>, std::uint16_t> && std::is_convertible_v<nm::be_u24_t, std::uint32_t> &&
        std::is_convertible_v<nm::ubits<4>, std::uint8_t> && std::is_convertible_v<nm::ibits<8>, std::int8_t>);
API("ubits<N, order>::bits / ::order", nm::ubits<12>::bits == 12 && nm::ubits<3, nm::bit_order::lsb0>::order == nm::bit_order::lsb0);
// wire sizes the docs state (802.1Q tag 4, the tour header: 2 + 1 + 4 + 3 + 1 + 2)
API("wire_size_v", nm::wire_size_v<api_hdr> == 13 && nm::wire_size_v<api_outer> == 14);
API("strct<T>([order])", parser_of<decltype(nm::strct<api_hdr>()), api_hdr> && parser_of<decltype(nm::strct<api_hdr>(std::endian::big)), api_hdr>);
API("overlay<T>() -> view<T>, footer<T>()", parser_of<decltype(nm::overlay<api_hdr>()), nm::view<api_hdr>> && parser_of<decltype(nm::footer<api_hdr>()), api_hdr>);
API("view<T>::get<\"name\">()", requires(nm::view<api_hdr> v) { { v.get<"a">() } -> std::convertible_to<std::uint16_t>; });
// public reflection queries (exported for downstream libraries)
API("field_count_v", nm::field_count_v<api_hdr> == 7 && nm::field_count_v<api_outer> == 2);
API("field_index / field_index_v", nm::field_index<api_hdr, "b">() == 3 && nm::field_index_v<api_hdr, "len24"> == 4 &&
        nm::field_index_v<api_hdr, "nope"> == std::size_t(-1));
API_SAME("field_type_t<T, I>", nm::field_type_t<api_hdr, 0>, nm::be<std::uint16_t>);
API_SAME("member_t<&T::m>", nm::member_t<&api_hdr::b>, nm::le<std::uint32_t>);
API("field_bit_offsets<T>() / field_bit_offset_v<T, name>", nm::field_bit_offsets<api_hdr>()[3] == 24 && nm::field_bit_offset_v<api_hdr, "s"> == 80);
API("wire_bits_v<F>", nm::wire_bits_v<nm::ubits<5>> == 5 && nm::wire_bits_v<nm::be_u24_t> == 24 && nm::wire_bits_v<api_hdr> == 104);
API_SAME("decoded_t<F>", nm::decoded_t<nm::be<std::uint16_t>>, std::uint16_t);
API("is_std_array_v / is_byte_array_v", nm::is_std_array_v<std::array<int, 2>> && nm::is_byte_array_v<std::array<std::uint8_t, 2>> && !nm::is_std_array_v<int>);
API("field_desc<Name, MemPtr>{name, mem_ptr, value_type}", std::is_same_v<typename nm::field_desc<"a", &api_hdr::a>::value_type, nm::be<std::uint16_t>> &&
        nm::field_desc<"a", &api_hdr::a>::mem_ptr == &api_hdr::a);
consteval std::size_t visit_count() {
  std::size_t n = 0, bits = 0;
  nm::for_each_field<api_hdr>([&](auto f) { n += decltype(f)::name.sv().size() > 0; });
  nm::for_each_field_with_offset<api_hdr>([&](auto, auto off) { bits = decltype(off)::value; });
  return n * 1000 + bits;
}
API("for_each_field / for_each_field_with_offset (compile time)", visit_count() == 7 * 1000 + 88);
}  // namespace reflect_surface

// =====================================================================================
// nanom/schema.hpp + nanom/soa.hpp — schemas and columnar storage
// =====================================================================================
namespace schema_surface {
API("schema_of<T>()", requires { { nm::schema_of<api_hdr>() } -> std::same_as<const nm::schema_node&>; });
API("arrow_format(field)", requires(const nm::schema_field& f) { { nm::arrow_format(f) } -> std::same_as<std::string>; });
API("avro_schema / to_json / csv_header / csv_row", requires(const api_hdr& v) {
  { nm::avro_schema<api_hdr>() } -> std::same_as<std::string>;
  { nm::to_json(v) } -> std::same_as<std::string>;
  { nm::csv_header<api_hdr>() } -> std::same_as<std::string>;
  { nm::csv_row(v) } -> std::same_as<std::string>;
});
using T = nm::soa<api_hdr>;
API("soa<T>(chunk_rows), noexcept moves", std::is_constructible_v<T, std::size_t> && std::is_default_constructible_v<T> && std::is_nothrow_move_constructible_v<T>);
API("soa<T>::column_count (one leaf column per scalar / array)", T::column_count == 7);
API("soa<T> API (push, columns, rows, chunks, chunk_at, for_each_chunk, col / as / column / span)", requires(T t, const T& ct, const api_hdr& v, nm::view<api_hdr> vw) {
  t.push(v);
  t.push(vw);
  t.reserve(std::size_t{1});
  t.seal();
  { ct.rows() } -> std::same_as<std::size_t>;
  { ct.chunk_rows() } -> std::same_as<std::size_t>;
  { ct.chunk_count() } -> std::same_as<std::size_t>;
  ct.columns()[0].name;
  ct.columns()[0].arrow;
  ct.columns()[0].elem_bytes;
  ct.for_each_chunk([](const T::chunk&) {});
  { ct.chunk_at(0).rows } -> std::convertible_to<std::size_t>;
  ct.chunk_at(0).col(0);
  ct.chunk_at(0).cols[0].data();
  ct.chunk_at(0).cols[0].size();
  { ct.chunk_at(0).template as<std::uint16_t>(0) } -> std::same_as<std::span<const std::uint16_t>>;
  ct.chunk_at(0).template column<"a">();
  ct.chunk_at(0).template span<"a">();
});
}  // namespace schema_surface

// =====================================================================================
// nanom/sink.hpp — byte sinks shared by the encoders
// =====================================================================================
namespace sink_surface {
API("byte_sink concept", nm::byte_sink<nm::vector_sink> && nm::byte_sink<nm::span_sink> && nm::byte_sink<nm::counting_sink>);
struct my_sink {
  bool put(const std::byte*, std::size_t) { return true; }
};
API("any type with bool put(const std::byte*, std::size_t) is a sink", nm::byte_sink<my_sink>);
API("vector_sink{&vec} / span_sink{span}.used/.written() / counting_sink.count", requires(std::vector<std::byte> v, std::span<std::byte> s) {
  nm::vector_sink{&v};
  nm::span_sink{s};
  { nm::span_sink{s}.used } -> std::convertible_to<std::size_t>;
  { nm::span_sink{s}.written() } -> std::same_as<std::span<std::byte>>;
  { nm::counting_sink{}.count } -> std::convertible_to<std::size_t>;
});
API("encode_error{what, message, field}", requires(nm::encode_error e) { e.what; e.message; e.field; });
}  // namespace sink_surface

// =====================================================================================
// nanom/emit.hpp — write described structs (docs/WRITERS.md phase B)
// =====================================================================================
namespace emit_surface {
API("emit_ctx{payload}", requires(nm::emit_ctx c) { { c.payload } -> std::convertible_to<std::span<const std::byte>>; });
API("computed<T>::fields", requires { nm::computed<api_hdr>::fields; nm::computed<api_len>::fields; });
API("calc<\"f\">(fn) / checksum<\"f\">(fn)", requires { nm::calc<"x">([](const api_len&) { return 0; }); nm::checksum<"x">([](std::span<const std::byte>) { return 0; }); });
API_SAME("to_bytes(v[, ctx, order]) -> expected<array>", decltype(nm::to_bytes(std::declval<const api_hdr&>())),
         nm::expected<std::array<std::byte, 13>, nm::encode_error>);
API_SAME("to_bytes_exact(v)", decltype(nm::to_bytes_exact(std::declval<const plain&>())), std::array<std::byte, 4>);
API_SAME("emit(v, span[, ctx, order])", decltype(nm::emit(std::declval<const api_len&>(), std::declval<std::span<std::byte>>(), nm::emit_ctx{})),
         nm::expected<std::size_t, nm::encode_error>);
API_SAME("emit_to(v, sink[, ctx, order])", decltype(nm::emit_to(std::declval<const api_len&>(), std::declval<nm::vector_sink&>())),
         nm::expected<std::size_t, nm::encode_error>);
API_SAME("emit_frame(v, payload, sink)", decltype(nm::emit_frame(std::declval<const api_len&>(), std::span<const std::byte>{},
                                 std::declval<nm::counting_sink&>())),
         nm::expected<std::size_t, nm::encode_error>);
API_SAME("verify_computed<T>(wire, ctx)", decltype(nm::verify_computed<api_len>(std::span<const std::byte>{}, nm::emit_ctx{})), bool);
API_SAME("overlay_mut<T>(span) -> expected<mut_view<T>>", decltype(nm::overlay_mut<api_hdr>(std::span<std::byte>{})), nm::expected<nm::mut_view<api_hdr>, nm::encode_error>);
API("mut_view<T>: valid / raw / as_view / get / set / recompute", requires(nm::mut_view<api_len> m, nm::mut_view<api_outer> o) {
  { m.valid() } -> std::same_as<bool>;
  { m.raw() } -> std::same_as<std::span<std::byte>>;
  { m.as_view() } -> std::same_as<nm::view<api_len>>;
  { m.get<"length">() } -> std::convertible_to<std::uint16_t>;
  { o.get<"inner">() } -> std::same_as<nm::mut_view<api_hdr>>;
  { m.set<"length">(5) } -> std::same_as<nm::expected<nm::unit, nm::encode_error>>;
  { m.recompute(nm::emit_ctx{}) } -> std::same_as<nm::expected<nm::unit, nm::encode_error>>;
});
// constexpr encoding (docs: "to_bytes ... constexpr")
API("to_bytes_exact usable in constant expressions", nm::to_bytes_exact(plain{0x1234, {5, 6}})[0] == std::byte{0x12});
API("to_bytes with computed fields is constexpr", (*nm::to_bytes(api_len{}, nm::emit_ctx{}))[1] == std::byte{4});
}  // namespace emit_surface

// =====================================================================================
// nanom/craft.hpp — composable crafting combinators (nanom::craft, alias nc)
// =====================================================================================
namespace craft_surface {
using Bytes = decltype(nc::put_bytes(std::span<const std::byte>{}));
API("Crafter concept, disjoint from Parser", nc::Crafter<Bytes> && !nm::Parser<Bytes> && !nc::Crafter<decltype(nm::u8)>);
API("crafter_tag", std::derived_from<Bytes, nc::crafter_tag>);
API("put_* primitives", nc::Crafter<decltype(nc::put_u8(1))> && nc::Crafter<decltype(nc::put_be16(1))> && nc::Crafter<decltype(nc::put_be24(1))> &&
        nc::Crafter<decltype(nc::put_be32(1))> && nc::Crafter<decltype(nc::put_be48(1))> &&
        nc::Crafter<decltype(nc::put_be64(1))> && nc::Crafter<decltype(nc::put_le16(1))> &&
        nc::Crafter<decltype(nc::put_le24(1))> && nc::Crafter<decltype(nc::put_le32(1))> &&
        nc::Crafter<decltype(nc::put_le48(1))> && nc::Crafter<decltype(nc::put_le64(1))> &&
        nc::Crafter<decltype(nc::put_uleb128(1))> && nc::Crafter<decltype(nc::put_bytes(std::span<const std::uint8_t>{}))> &&
        nc::Crafter<decltype(nc::put_lit("x"))> && nc::Crafter<decltype(nc::put_pad(2))> &&
        nc::Crafter<decltype(nc::put_struct(api_len{}))>);
using Pipe = decltype(std::declval<Bytes>() | nc::framed_by(api_len{}) | nc::prefixed_with(nc::put_be16) | nc::padded_to(4));
API("| framed_by / prefixed_with / padded_to", nc::Crafter<Pipe>);
API("framed_by(hdr, ctx)", nc::Crafter<decltype(std::declval<Bytes>() | nc::framed_by(api_len{}, nm::emit_ctx{}))>);
API("+ concatenation", nc::Crafter<decltype(std::declval<Bytes>() + nc::put_u8(1))>);
API("craft_adaptor | craft_adaptor composes", nc::Crafter<decltype(std::declval<Bytes>() | (nc::padded_to(4) | nc::prefixed_with(nc::put_u8)))>);
API("cat / frame / each / when / length_prefix / align_to", nc::Crafter<decltype(nc::cat(nc::put_u8(1), nc::put_u8(2)))> && nc::Crafter<decltype(nc::frame(api_len{}, nc::put_u8(1)))> &&
        nc::Crafter<decltype(nc::each(std::declval<std::vector<int>&>(), [](int) { return nc::put_u8(1); }))> &&
        nc::Crafter<decltype(nc::when(true, nc::put_u8(1)))> &&
        nc::Crafter<decltype(nc::length_prefix(nc::put_u8, nc::put_u8(1)))> &&
        nc::Crafter<decltype(nc::align_to(4, nc::put_u8(1)))>);
inline constexpr auto identity_stage = nc::craft_adaptor{[](auto body) { return body; }};
API("craft_adaptor{fn}: a user-written stage", nc::Crafter<decltype(std::declval<Bytes>() | identity_stage)>);
API_SAME("write(crafter, sink)", decltype(nc::write(std::declval<const Bytes&>(), std::declval<nm::span_sink&>())),
         nm::expected<std::size_t, nm::encode_error>);
API_SAME("size_of(crafter)", decltype(nc::size_of(std::declval<const Bytes&>())), nm::expected<std::size_t, nm::encode_error>);
API_SAME("to_vector(crafter)", decltype(nc::to_vector(std::declval<const Bytes&>())), nm::expected<std::vector<std::byte>, nm::encode_error>);
}  // namespace craft_surface

// =====================================================================================
// nanom/checksum.hpp — Internet checksum (RFC 1071 / 1624) and the AUTOSAR CRCs
// =====================================================================================
namespace checksum_surface {
using bsp = std::span<const std::byte>;
[[maybe_unused]] constexpr std::uint16_t (*sv_checksum)(std::string_view) = &nm::inet::checksum;
[[maybe_unused]] constexpr std::uint16_t (*sg_checksum)(std::initializer_list<bsp>) = &nm::inet::checksum;
[[maybe_unused]] constexpr std::uint16_t (*range_checksum)(std::span<const bsp>) = &nm::inet::checksum;
[[maybe_unused]] constexpr bool (*verify1)(bsp) = &nm::inet::verify;
[[maybe_unused]] constexpr bool (*verify_sg)(std::initializer_list<bsp>) = &nm::inet::verify;
[[maybe_unused]] constexpr std::array<std::byte, 12> (*ph4)(const std::array<std::uint8_t, 4>&,
                                                            const std::array<std::uint8_t, 4>&, std::uint8_t,
                                                            std::uint16_t) = &nm::inet::pseudo_header_v4;
[[maybe_unused]] constexpr std::array<std::byte, 40> (*ph6)(const std::array<std::uint8_t, 16>&,
                                                            const std::array<std::uint8_t, 16>&, std::uint32_t,
                                                            std::uint8_t) = &nm::inet::pseudo_header_v6;
[[maybe_unused]] constexpr std::uint16_t (*udp_cs)(std::initializer_list<bsp>) = &nm::inet::udp_checksum;
[[maybe_unused]] constexpr std::uint16_t (*upd16)(std::uint16_t, std::uint16_t, std::uint16_t) = &nm::inet::update16;
[[maybe_unused]] constexpr std::uint16_t (*upd32)(std::uint16_t, std::uint32_t, std::uint32_t) = &nm::inet::update32;
API_SAME("inet::checksum(span)", decltype(nm::inet::checksum(bsp{})), std::uint16_t);
API("inet::sum streaming accumulator", requires(nm::inet::sum s, bsp b) {
  { s.add(b).add16(1).add32(2).add_folded(3) } -> std::same_as<nm::inet::sum&>;
  { s.folded() } -> std::same_as<std::uint16_t>;
  { s.checksum() } -> std::same_as<std::uint16_t>;
  { s.verifies() } -> std::same_as<bool>;
});
API("inet::checksum is constexpr", nm::inet::checksum(std::string_view("\x45\x00")) == 0xbaff);
template <class C, class V>
concept crc_api = std::same_as<typename C::value_type, V> && requires(C c, bsp b, V v) {
  { C::compute(b) } -> std::same_as<V>;
  { C::compute(std::string_view{}) } -> std::same_as<V>;
  { c.update(b).update(std::uint8_t{1}) } -> std::same_as<C&>;
  { c.value() } -> std::same_as<V>;
  { C::resume(v) } -> std::same_as<C>;
  C::params::check;
  C::params::poly;
};
API("AUTOSAR CRC set: compute / update / value / resume", crc_api<nm::crc8_sae_j1850, std::uint8_t> && crc_api<nm::crc8_h2f, std::uint8_t> &&
        crc_api<nm::crc16_ccitt_false, std::uint16_t> && crc_api<nm::crc16_arc, std::uint16_t> &&
        crc_api<nm::crc32, std::uint32_t> && crc_api<nm::crc32_p4, std::uint32_t> && crc_api<nm::crc64, std::uint64_t>);
API("CRC check values (constexpr)", nm::crc32_p4::compute(std::string_view("123456789")) == nm::crc32_p4::params::check);
using my_crc = nm::crc<nm::crc_params<std::uint16_t, 0x1021, 0xFFFF, false, 0x0000, 0x29B1>>;
API("crc<crc_params<T, Poly, Init, Reflected, XorOut, Check>>", my_crc::compute(std::string_view("123456789")) == 0x29B1);
}  // namespace checksum_surface

// =====================================================================================
// nanom/layout.hpp — JSON-described raw records and AUTOSAR PDUs (docs/LAYOUT_GUIDE.md)
// =====================================================================================
namespace layout_surface {
// desc.hpp
[[maybe_unused]] lay::lresult<lay::description> (*parse_desc)(std::string_view, const lay::load_options&) =
    &lay::parse_description;
[[maybe_unused]] lay::lresult<lay::description> (*load_desc)(const std::string&, lay::load_options) = &lay::load_description;
[[maybe_unused]] lay::lresult<lay::enum_catalog> (*parse_en)(std::string_view, std::string) = &lay::parse_enums;
[[maybe_unused]] lay::lresult<lay::enum_catalog> (*load_en)(const std::string&) = &lay::load_enums;
API_SAME("lresult<T> = expected<T, layout_error>", lay::lresult<int>, nm::expected<int, lay::layout_error>);
API("layout_error::str()", requires(const lay::layout_error& e) { { e.str() } -> std::same_as<std::string>; });
API("description::raw_files / of(raw_file)", requires(const lay::description& d) { d.raw_files; d.of("x"); });
API("load_options", requires(lay::load_options o) { o.strict; o.source; });
// plan.hpp
[[maybe_unused]] lay::lresult<lay::plan> (*compile)(const lay::description&, std::string_view, const lay::enum_catalog*,
                                                    const lay::compile_options&) = &lay::plan::compile;
API("compile_options{stride, stride_by_file, order, strict}", requires(lay::compile_options o) { o.stride = 8; o.stride_by_file["x"] = 8; o.order = std::endian::big; o.strict; });
API("plan queries: find / all / select / records / view / stride / signal flags", requires(const lay::plan& p, std::span<const std::byte> in) {
  { p.find("x") } -> std::same_as<std::optional<lay::field_handle>>;
  { p.all() } -> std::same_as<lay::selection>;
  { p.select({"a", "b.*"}) } -> std::same_as<lay::lresult<lay::selection>>;
  { p.records(in) } -> std::same_as<lay::record_set>;
  { p.view(in) } -> std::same_as<std::optional<lay::record>>;
  { p.stride() } -> std::same_as<std::size_t>;
  { p.raw_file() } -> std::convertible_to<std::string_view>;
  p.fields();
  p.warnings();
  { p.has_signals() } -> std::same_as<bool>;
  { p.conditional() } -> std::same_as<bool>;
  { p.scaled() } -> std::same_as<bool>;
});
[[maybe_unused]] lay::lresult<bool> (lay::plan::*set)(const lay::field_handle&, std::span<std::byte>, double) const =
    &lay::plan::set;
[[maybe_unused]] lay::lresult<bool> (lay::plan::*set_raw)(const lay::field_handle&, std::span<std::byte>, std::int64_t)
    const = &lay::plan::set_raw;
[[maybe_unused]] lay::lresult<bool> (lay::plan::*set_raw_u)(const lay::field_handle&, std::span<std::byte>, std::uint64_t)
    const = &lay::plan::set_raw_unsigned;
[[maybe_unused]] void (lay::plan::*set_bits)(const lay::field_handle&, std::span<std::byte>, std::uint64_t) const =
    &lay::plan::set_bits_unchecked;
[[maybe_unused]] lay::lresult<std::uint64_t> (lay::plan::*to_raw)(const lay::field_handle&, double) const = &lay::plan::to_raw;
[[maybe_unused]] lay::lresult<std::uint64_t> (lay::plan::*raw_bits)(const lay::field_handle&, std::int64_t) const =
    &lay::plan::raw_bits;
[[maybe_unused]] lay::lresult<bool> (lay::plan::*encode_span)(std::span<const lay::plan::signal_value>, std::span<std::byte>)
    const = &lay::plan::encode;
[[maybe_unused]] bool (lay::plan::*valid)(const lay::record&, const lay::field_handle&) const = &lay::plan::valid;
API("plan::encode({{handle, value[, raw]}, ...}, pdu)", requires(const lay::plan& p, lay::field_handle h, std::span<std::byte> pdu) {
  { p.encode({{h, 1.5}, {h, 3, /*raw=*/true}}, pdu) } -> std::same_as<lay::lresult<bool>>;
});
API("field_handle{index, factor, offset}", requires(lay::field_handle h) { h.index; h.factor; h.offset; });
API("record: get<T> / value / [] / physical / bytes / enum_name", requires(const lay::record& r, lay::field_handle h) {
  { r.get<int>(h) } -> std::same_as<int>;
  { r.value(h) } -> std::same_as<lay::scalar>;
  { r[h] } -> std::same_as<lay::scalar>;
  { r.physical(h) } -> std::same_as<double>;
  { r.bytes() } -> std::same_as<std::span<const std::byte>>;
  { r[h].enum_name() } -> std::same_as<const std::string*>;
});
API("record_set", requires(const lay::record_set& rs) {
  { rs.size() } -> std::same_as<std::size_t>;
  { rs.tail_bytes() } -> std::same_as<std::size_t>;
  rs.begin();
  rs.end();
  { rs[0] } -> std::same_as<lay::record>;
});
[[maybe_unused]] bool (*name_matches)(std::string_view, std::string_view) = &lay::name_matches;  // exact / subtree / glob
API("msb_linear (DBC sawtooth start bit)", lay::msb_linear(7) == 0);
// decode.hpp
[[maybe_unused]] lay::lresult<lay::table> (*decode_all)(const lay::plan&, std::span<const std::byte>,
                                                        const lay::decode_options&) = &lay::decode;
[[maybe_unused]] lay::lresult<lay::table> (*decode_sel)(const lay::plan&, std::span<const std::byte>, const lay::selection&,
                                                        const lay::decode_options&) = &lay::decode;
[[maybe_unused]] lay::lresult<std::size_t> (*decode_into)(const lay::decoder&, const lay::plan&, std::span<const std::byte>,
                                                          std::span<const lay::column_out>, const lay::decode_options&) =
    &lay::decode_into;
API("decoder(plan, selection)", std::is_constructible_v<lay::decoder, const lay::plan&, const lay::selection&>);
API("decode_options{first, count, allow_partial, strat, physical, validity}", requires(lay::decode_options o) { o.first; o.count; o.allow_partial; o.strat = lay::strategy::field_major; o.physical; o.validity; });
API("column_out{data, bytes}", requires(lay::column_out c) { c.data; c.bytes; });
API("table: rows / columns / find / column<T> / physical / validity / valid / null_count / cell", requires(const lay::table& t) {
  { t.rows() } -> std::same_as<std::size_t>;
  { t.columns() } -> std::same_as<std::size_t>;
  { t.find("x") } -> std::same_as<std::optional<std::size_t>>;
  { t.column<std::uint32_t>("x") } -> std::same_as<std::span<const std::uint32_t>>;
  { t.column<std::uint32_t>(std::size_t{0}) } -> std::same_as<std::span<const std::uint32_t>>;
  { t.physical(0) } -> std::same_as<std::span<const double>>;
  { t.validity(0) } -> std::same_as<std::span<const std::uint8_t>>;
  { t.valid(0, 0) } -> std::same_as<bool>;
  { t.null_count(0) } -> std::same_as<std::size_t>;
  { t.cell(0, 0) } -> std::same_as<lay::scalar>;
});
// arrow.hpp
[[maybe_unused]] void (*export_arrow)(lay::table&&, ArrowSchema*, ArrowArray*, const lay::arrow_options&) = &lay::export_arrow;
API("arrow_options{enums, signals, separator, raw_suffix}", requires(lay::arrow_options o) {
  o.enums = lay::enum_mode::dictionary;
  o.enums = lay::enum_mode::integer;
  o.enums = lay::enum_mode::both;
  o.signals = lay::signal_mode::automatic;
  o.signals = lay::signal_mode::raw;
  o.signals = lay::signal_mode::physical;
  o.signals = lay::signal_mode::both;
  o.separator = "/";
  o.raw_suffix = "#raw";
});
API("arrow_metadata(const char*)", requires(const char* md) {
  { lay::arrow_metadata(md) } -> std::same_as<std::vector<std::pair<std::string, std::string>>>;
});
API("Arrow C Data Interface structs", requires(ArrowSchema s, ArrowArray a) { s.release; s.children; s.n_children; s.format; s.name; s.dictionary; a.release; a.length; a.null_count; a.buffers; });
// export.hpp
constexpr auto str_sink = [](std::string_view) {};
API("export_jsonl / export_csv (plan, bytes, sink, selection[, decode_options, text_options])", requires(const lay::plan& p, std::span<const std::byte> in, lay::selection s) {
  { lay::export_jsonl(p, in, str_sink, s, lay::decode_options{}, lay::text_options{}) } -> std::same_as<lay::lresult<std::size_t>>;
  { lay::export_csv(p, in, str_sink, s) } -> std::same_as<lay::lresult<std::size_t>>;
});
API("text_options{physical, nulls}", requires(lay::text_options o) { o.physical; o.nulls; });
API("jsonl_writer(plan, selection, text_options)", std::is_constructible_v<lay::jsonl_writer, const lay::plan&, const lay::selection&, const lay::text_options&>);
// e2e.hpp (docs: protector / checker / statuses; profiles 1 2 4 5 6 7 11 22)
[[maybe_unused]] constexpr e2e::profile profiles[] = {e2e::profile::p01, e2e::profile::p02, e2e::profile::p04,
                                                      e2e::profile::p05, e2e::profile::p06, e2e::profile::p07,
                                                      e2e::profile::p11, e2e::profile::p22};
[[maybe_unused]] constexpr e2e::data_id_mode modes[] = {e2e::data_id_mode::both, e2e::data_id_mode::alt,
                                                        e2e::data_id_mode::low, e2e::data_id_mode::nibble};
[[maybe_unused]] constexpr e2e::status statuses[] = {
    e2e::status::ok,          e2e::status::ok_some_lost,  e2e::status::repeated,    e2e::status::wrong_sequence,
    e2e::status::no_new_data, e2e::status::wrong_crc,     e2e::status::wrong_length, e2e::status::wrong_data_id,
    e2e::status::bad_counter, e2e::status::bad_config};
API("e2e::usable(status)", e2e::usable(e2e::status::ok) && e2e::usable(e2e::status::ok_some_lost) && !e2e::usable(e2e::status::repeated));
API("counter_max / header_bytes", e2e::counter_max(e2e::profile::p05) == 0xFF && e2e::header_bytes(e2e::profile::p04) == 12);
[[maybe_unused]] const char* (*status_name)(e2e::status) = &e2e::status_name;
[[maybe_unused]] std::size_t (*required_length)(const e2e::config&) = &e2e::required_length;
[[maybe_unused]] bool (*valid_cfg)(const e2e::config&, std::size_t) = &e2e::valid;
[[maybe_unused]] std::uint64_t (*compute_crc)(const e2e::config&, std::span<const std::byte>) = &e2e::compute_crc;
[[maybe_unused]] std::uint32_t (*read_counter)(const e2e::config&, std::span<const std::byte>) = &e2e::read_counter;
[[maybe_unused]] std::uint64_t (*read_crc)(const e2e::config&, std::span<const std::byte>) = &e2e::read_crc;
[[maybe_unused]] bool (*protect)(const e2e::config&, std::span<std::byte>, std::uint32_t) = &e2e::protect;
[[maybe_unused]] e2e::status (*verify)(const e2e::config&, std::span<const std::byte>) = &e2e::verify;
// the documented brace form, `e2e::config c{.prof = ..., .data_id = ...}`
[[maybe_unused]] inline const e2e::config documented_config{.prof = e2e::profile::p05, .data_id = 0x1234};
API("e2e::config fields", requires(e2e::config c) {
  c.prof; c.data_id; c.data_id_list; c.id_mode; c.offset; c.counter_offset; c.nibble_offset;
  c.max_delta_counter; c.min_length; c.max_length;
});
API("e2e::protector / e2e::checker", requires(e2e::protector tx, e2e::checker rx, std::span<std::byte> pdu) {
  e2e::protector(e2e::config{});
  e2e::checker(e2e::config{});
  { tx.protect(pdu) } -> std::same_as<bool>;
  { tx.counter() } -> std::same_as<std::uint32_t>;
  tx.counter(std::uint32_t{3});
  { rx.check(pdu) } -> std::same_as<e2e::status>;
  { rx.check(pdu, false) } -> std::same_as<e2e::status>;
  { rx.lost() } -> std::same_as<std::uint32_t>;
  { rx.last_counter() } -> std::same_as<std::uint32_t>;
  rx.reset();
  { rx.cfg() } -> std::same_as<const e2e::config&>;
});
}  // namespace layout_surface

// =====================================================================================
// nanom_shark — pcap / pcapng decode, whole-file and streaming (docs/NANO_SHARK.md)
// =====================================================================================
namespace shark_surface {
namespace ns = nanom_shark;
using Dec = ns::default_decoder;
using Tables = ns::tables_of<Dec>;
[[maybe_unused]] bool (*run_pass)(nanom::bytes, Tables&, ns::SinkHub, const ns::DecodeOptions&, std::string&) =
    &ns::run_decode_pass<Dec>;
using Session = ns::StreamingDecodeSession<Dec>;
API("StreamingDecodeSession<Decoder>(tables, sink, opts)", std::is_constructible_v<Session, Tables&, ns::SinkHub, const ns::DecodeOptions&>);
[[maybe_unused]] void (Session::*feed_shb)(nanom::bytes) = &Session::feed_shb;
[[maybe_unused]] void (Session::*feed_idb)(nanom::bytes, bool, std::uint32_t) = &Session::feed_idb;
[[maybe_unused]] ns::FeedResult (Session::*feed_epb)(nanom::bytes, bool, ns::defrag::Token, nmpcap::Kind, std::uint64_t) =
    &Session::feed_epb;
API("streaming session queries + FeedResult{ok, pinned, released}", requires(const Session& s, ns::FeedResult r) {
  s.packets_fed();
  { s.section_little_endian() } -> std::same_as<bool>;
  { s.pinned_buffers() } -> std::same_as<std::size_t>;
  { r.ok } -> std::convertible_to<bool>;
  { r.pinned } -> std::convertible_to<bool>;
  r.released.size();
  r.released.begin();
  r.released.to_vector();
});
API_SAME("defrag::Token", ns::defrag::Token, std::uint64_t);
API("defrag::kNoToken", ns::defrag::kNoToken == 0);
API("tables_of<Decoder>: enable_only / set_enabled / set_all_enabled (projection)", requires(Tables t) {
  t.enable_only({"packets", "someip"});
  t.set_enabled("eth", false);
  t.set_all_enabled(true);
});
[[maybe_unused]] bool (*scan_blocks)(nanom::bytes, std::vector<nmpcap::BlockRef>&, std::string&) = &nmpcap::scan_blocks;
API("nmpcap::for_each_block(file, on_block, error)", requires(nanom::bytes f, std::string e) { nmpcap::for_each_block(f, [](const nmpcap::BlockRef&) {}, e); });
API("nmpcap::parse_epb / BlockRef / EpbView / Kind", requires(nanom::bytes f, nmpcap::BlockRef r, nmpcap::EpbView v) {
  { nmpcap::parse_epb(f, r, v) } -> std::same_as<bool>;
  v.caplen;
  v.payload_file_offset;
  r.kind == nmpcap::Kind::Epb;
});
API("nmproto::walk_packet(link_type, pkt, on_eth, on_vlan, on_ipv4, on_ipv6, on_tcp, on_udp)", requires(nanom::bytes pkt) {
  nmproto::walk_packet(1u, pkt, [](const nmproto::Ethernet&) {}, [](const nmproto::VlanTag&) {}, [](const nmproto::Ipv4&) {},
                       [](const nmproto::Ipv6&) {}, [](const nmproto::Tcp&) {}, [](const nmproto::Udp&) {});
});
API("nanom_shark wire structs are Described", nm::Described<nanom_shark::SomeipHeader> && nm::Described<nmproto::Ipv4>);
}  // namespace shark_surface

}  // namespace api

int main() {
  // Trivial runtime use, so the TU is also linked and run (and checked under the sanitizers).
  std::array<std::byte, 4> b{};
  const auto n = nm::emit(api_len{}, std::span<std::byte>(b), nm::emit_ctx{});
  const auto e = e2e::protect(api::layout_surface::documented_config, b, 0);
  if (!n || *n != 4 || !e || e2e::verify(api::layout_surface::documented_config, b) != e2e::status::ok) {
    std::puts("api_surface: runtime smoke failed");
    return 1;
  }
  std::puts("api_surface: ok");
  return 0;
}
