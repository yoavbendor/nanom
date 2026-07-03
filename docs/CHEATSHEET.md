# nom → nanom cheat sheet

Everything lives in `namespace nanom` (alias it: `namespace nm = nanom;`).
A parser is any callable `(nm::input) -> nm::result<T>`; `result` is
`{value, rest}` on success. Combinators take parsers by value and return
lambdas — compose freely, `constexpr` all the way.

```cpp
nm::input in = nm::from(buf, len);        // or from(span), from(string_view)
auto r = parser(in);
if (!r) std::puts(r.error().render(in).c_str());
else    use(r->value, r->rest);
```

## Renamed (C++ keywords / clarity) — everything else is the nom name

| nom | nanom | why |
|---|---|---|
| `tuple((a,b,c))` | `seq(a,b,c)` | std::tuple clash |
| `char('x')` | `chr('x')` | keyword |
| `not(p)` | `not_(p)` | keyword |
| `u8` (parser) | `u8` ✓ (also `be_u8`/`le_u8`) | |
| `float`/`double` (text) | `float_` / `double_` | keywords |
| `nom::character::complete::u32` (text int) | `dec<uint32_t>()` | clearer |
| `hex_u32` | `hex<uint32_t>()` | generalized |
| `bits::take(n)` | `take_bits<T>(n)` | value type explicit |
| `bits::tag(pat,n)` | `tag_bits(pat,n)` | |
| `bits::bytes(p)` | `bytes_(p)` | name clash with `nm::bytes` |
| `map_res` | `map_res` ✓ (f returns `std::optional`) | no Rust Result |
| streaming vs complete modules | one set; `nm::streaming(in)` opts in | see below |

## bytes

`tag("...")` `tag_no_case` `take(n)` `take_while` `take_while1`
`take_while_m_n` `take_till` `take_till1` `take_until` `is_a` `is_not`
— byte predicates get `std::uint8_t`; results are zero-copy `nm::bytes`
(`nm::as_str(b)` views as text).

## character

`chr` `satisfy` `one_of` `none_of` `anychar` `alpha0/1` `digit0/1`
`hex_digit0/1` `oct_digit0/1` `alphanumeric0/1` `space0/1` `multispace0/1`
`newline` `tab` `crlf` `line_ending` `not_line_ending`
— return `char` / `std::string_view` (zero-copy).

## sequence

`seq` `pair` `separated_pair` `preceded` `terminated` `delimited`

## branch

`alt(p...)` — same value type, backtracks on error, stops on `cut` failure;
reports the error that got **furthest** (better than nom).
`permutation(p...)` — any order, tuple in declaration order.

## multi

`many0` `many1` `many_m_n` `many_till` `count` `separated_list0`
`separated_list1` `fold_many0` `fold_many1` `fold_many_m_n`
`length_data` `length_value` `length_count`
— collect into `std::vector`; fold variants allocate nothing.

## combinator

`map` `map_res` `map_opt` `map_parser` `flat_map` `opt` `cond` `peek` `not_`
`recognize` `consumed` `value` `verify` `success` `fail` `cut` `complete`
`all_consuming` `into<T>` `eof` `rest` `rest_len` `context("label", p)`

## number

`be_u8..be_u64` (`+ be_u24, be_u48`), `le_*`, `be_i*`, `le_i*`,
`be_f32/f64`, `le_f32/f64`, `ne_*` (native), `u8`, `i8`,
`uint_<T>(std::endian)` — **runtime** byte order (ELF trick; not in nom).
Text: `dec<T>()`, `hex<T>()`, `float_`, `double_`.

## bits

`bits(bp)` enters bit mode, `bseq(...)` sequences bit parsers,
`take_bits<T>(n [, order])`, `tag_bits(pat, n)`, `bool_bit()`, `bytes_(p)`.
Orders: `bit_order::msb0` (default, network; nom's only mode) and
`bit_order::lsb0` (register layouts) — mixable per field.

## errors (nom: Err::Error / Failure / Incomplete)

- `errk::err` — recoverable, `alt`/`opt`/`many*` backtrack over it.
- `errk::fail` — from `cut(p)`: propagates through everything.
- `errk::incomplete` — only on `nm::streaming(in)` inputs; `error().needed`
  says how many bytes to fetch. Default inputs treat end-of-input as `err`
  (nom's *complete* behavior — no `::complete::` module split needed).
- `error().render(in)` ≈ nom `convert_error`: offset, context chain, hex
  caret. Errors are POD; nothing allocates until you render.

## beyond nom: structs, schemas, columns

```cpp
struct hdr { nm::be<uint16_t> a; nm::ubits<4> hi; nm::ubits<4> lo; nm::le<uint32_t> b; };
NANOM_DESCRIBE(hdr, a, hi, lo, b);           // C++23: global scope, wire order
                                             // C++26 (P2996): DELETE this line — eligible
                                             //   structs auto-describe (nanom26.hpp)

nm::strct<hdr>()          // Parser<hdr>: by value.  strct<hdr>(std::endian::big)
                          //   sets the order of *plain* int fields at runtime
nm::overlay<hdr>()        // Parser<view<hdr>>: zero-copy, decode on access
view.get<"a">()           // host-order value; typo -> compile error
nm::wire_size_v<hdr>      // bytes on the wire (layout checked at compile time)

nm::schema_of<hdr>()      // walkable schema tree
nm::arrow_format(field)   // "S", "w:6", "+s"… (nanoarrow / lance)
nm::avro_schema<hdr>()    // Avro JSON
nm::to_json(v)  nm::csv_header<hdr>()  nm::csv_row(v)

nm::soa<hdr> t(65536);    // columnar accumulator, sealed in chunks
t.push(v);
t.for_each_chunk([](auto& ch) {
  ch.col(i);              // contiguous bytes -> ArrowBufferAppend
  ch.template as<uint16_t>(0);   // typed span
});
```

Field types for described structs: plain ints/floats (endianness from
`strct<T>(order)`), `nm::be<T>` / `nm::le<T>`, `nm::ubits<N[,order]>` /
`nm::ibits<N[,order]>` (runs must end byte-aligned — compile-checked),
`std::array<T,N>`, nested described structs.
