# nanom — design

`nanom` is a single-header C++23 parser-combinator library for **binary-first**
parsing, modeled on Rust's [nom](https://github.com/rust-bakery/nom), with three
extra pillars nom does not have:

1. **Struct registration / reflection** — any C struct (plus explicit-endian and
   bit-field wrappers) can be registered and parsed zero-copy, with
   `view<T>.get<"field">()` string-literal access.
2. **Schema generation** — a registered struct yields a `schema` object that can
   be emitted as an Arrow C-Data format string (nanoarrow / Lance), an Avro JSON
   schema, or JSON/CSV for debugging.
3. **Columnar chunked storage** — `soa<T>` accumulates parse results
   column-wise in fixed-size chunks so results can be handed to nanoarrow /
   nanolance buffers without a transpose.

Target users are AI agents: the API mirrors nom's names 1:1 so prior nom
knowledge transfers without reading docs, and the docs are a cheat-sheet plus
copy-paste examples.

---

## 1. Sources studied and what was taken from each

| Library | What nanom takes | What nanom rejects |
|---|---|---|
| **rust nom** | The whole combinator vocabulary (`tag`, `alt`, `many0`, `preceded`, …), the `IResult = (rest, value)` shape, the three-way error model (*Error* / *Failure* / *Incomplete*), `cut`, `context`, streaming-vs-complete, the bits sub-parser idea | Rust-specific trait plumbing; nom's `VerboseError` heap allocation (we use a fixed inline context stack) |
| **Boost.Parser** | The idea that error messages must be *localized* (offset + caret/hex context) and human-quality; `separated_list` ergonomics | Global operator overloading (`>>`, `|` on arbitrary types) — too spooky for agents; heavy TU cost; text-first orientation |
| **acd1034/monadic-parser-combinator** | Proof that C++20 concepts + monadic bind make clean combinators; `and_then`/`or_else` naming for the monadic layer | `std::shared_ptr`-based parser storage (kills speed); string-only input |
| **hexorer/parsi** | The "always `constexpr`, always inlinable function objects" discipline; benchmark-driven zero-overhead claims | Char-only input model |
| **OneBit74/ezpz** | The "results decay into your own structs" goal — realized here as `strct<T>()` aggregate parsing | Context-object mutation style |
| **Boost.Describe** | The registration-macro approach (`NANOM_DESCRIBE`) as the C++23 stand-in for real reflection | Dependency itself — nanom re-implements the 5% it needs so the header stays standalone |

### C++26 readiness

All struct metadata flows through one customization point,
`nanom::describe<T>` (specialized by the `NANOM_DESCRIBE` macro). When P2996
reflection lands, a single `template<class T> requires(std::meta::…)` fallback
specialization makes the macro optional. Nothing else in the library changes.

---

## 2. Core model

```text
input  = { const std::byte* first, last; const std::byte* base }   // zero-copy view + error offsets
result<T> = std::expected< done<T>, error >                        // done<T> = { T value; input rest; }
Parser<T> = callable: (input) -> result<T>                         // a concept, not a base class
```

* **Zero-copy, always.** No parser allocates or copies input bytes. `take`,
  `tag`, `recognize`, `rest` return `bytes` (a `std::span<const std::byte>`
  into the original buffer); text parsers return `std::string_view` into it.
  Multi-combinators (`many0`, …) collect *values* into a container the caller
  controls (default `std::vector`, or fold variants for none).
* **Errors are POD.** `error` = kind (error/failure/incomplete) + absolute
  offset + expected-code + a fixed inline stack of up to 8 `context()` frames.
  No allocation on the failure path; `alt` backtracking is therefore free.
  `error::render(input)` produces the pretty localized message (offset,
  hex window, caret, context chain) — you pay for formatting only when you
  print.
* **Failure vs Error (`cut`).** Exactly nom's semantics: `alt` and `opt`
  backtrack on *Error* but propagate *Failure*; `cut(p)` upgrades. This is what
  makes error messages point at the real problem instead of the last
  alternative.
* **Incomplete / streaming.** Parsers that run out of input return
  `incomplete(n)` with bytes still needed — usable for packet reassembly. The
  `complete(p)` adapter converts Incomplete→Error for whole-buffer parsing
  (nom's complete/streaming split, without duplicating every module).

## 3. nom feature coverage matrix

| nom module | nom items | nanom status |
|---|---|---|
| `bytes` | tag, tag_no_case, take, take_while(_m_n/1), take_till(1), take_until, is_a, is_not | ✔ all, byte- and char-flavored |
| `character` | char/one_of/none_of/satisfy/anychar, alpha0/1, digit0/1, hex_digit, alphanumeric, space/multispace, line_ending, crlf, newline, tab, not_line_ending | ✔ (`chr` instead of reserved `char`) |
| `sequence` | tuple, pair, separated_pair, preceded, terminated, delimited | ✔ (`seq` = nom `tuple`, returns `std::tuple`) |
| `branch` | alt, permutation | ✔ |
| `multi` | many0/1, many_till, many_m_n, count, fold_many0/1/m_n, separated_list0/1, length_count, length_data, length_value | ✔ |
| `combinator` | map, map_res, map_opt, map_parser, flat_map, opt, cond, peek, not, recognize, consumed, value, verify, success, fail, cut, complete, all_consuming, rest, rest_len, eof, into | ✔ (`not_` for reserved word) |
| `number` | be/le × u8..u64,i8..i64,f32,f64 (+ u24/u48 etc.), text `float`/`double`/dec/hex | ✔ + native-endian `ne_*` |
| `bits` | bits(), bytes(), take(n bits), tag | ✔ **plus** LSB0 bit order and per-field mixing (nom is MSB0-only) |
| `error` | ParseError, context, VerboseError, convert_error | ✔ allocation-free equivalent, `error::render` ≈ `convert_error` |
| streaming | Incomplete(Needed) | ✔ |

Beyond nom: `strct<T>()`, `view<T>` overlays, `schema_of<T>()`, `soa<T>`
columnar chunking, Arrow/Avro/JSON/CSV emission.

## 4. Reflection & registration layer

```cpp
struct eth_hdr {
  mac_t          dst;       // std::array<std::uint8_t,6>
  mac_t          src;
  nm::be<std::uint16_t> eth_type;   // explicit endianness in the type
};
NANOM_DESCRIBE(eth_hdr, dst, src, eth_type);
```

Field types the registry understands:

| type | meaning |
|---|---|
| integral / floating T | native endianness (must be explicit to serialize: prefer be/le) |
| `nm::be<T>` / `nm::le<T>` | big/little-endian wire integer/float; storage is raw bytes, converts on access — safe to mix in one struct |
| `nm::ubits<N>` / `nm::ibits<N>` | N-bit field inside a `nm::bitpack<Order, ...>` group |
| `std::array<T,N>` | fixed list |
| nested described struct | struct column |

Two ways to parse a registered struct:

* `strct<T>()` — a real combinator: parses each field in declaration order
  (through bit groups, endian wrappers, nested structs), aggregate-initializes
  a `T` **by value**. Composable with everything (`many0(strct<eth_hdr>())`).
* `overlay<T>()` — zero-copy: validates length, returns `view<T>` pointing at
  the wire bytes. `view<T>::get<"eth_type">()` decodes on access (endian/bit
  extraction), `get<"dst">()` of an array field returns a span. This requires
  `T` to have a fully-defined wire layout (all multi-byte fields endian-wrapped,
  packed layout) — checked at compile time, misuse is a `static_assert`.

`view.get<"name">()` uses a `fixed_string` NTTP; unknown names fail at compile
time with the field list in the error.

## 5. Schema + columnar layer

```cpp
constexpr auto s = nm::schema_of<eth_hdr>();      // walkable schema tree
s.to_arrow_format(field);   // "w:6", "S" (u16) … per Arrow C data interface
nm::avro_schema<eth_hdr>()  // {"type":"record","name":"eth_hdr",...}
nm::to_json(v) / nm::csv_header<T>() / nm::csv_row(v)   // debug dumps

nm::soa<eth_hdr> cols(/*chunk_rows=*/65536);
cols.push(hdr);                       // field-wise append, SoA
cols.for_each_chunk([&](auto&& chunk){ /* chunk.column<"eth_type">() -> span */ });
```

`soa<T>` stores one contiguous buffer per (flattened) leaf field, sealed into
chunks of `chunk_rows` — exactly the shape nanoarrow `ArrowArray` /
Lance fragment writers want, so dumping is `memcpy`-free (hand the spans to
`ArrowBufferAppend` or wrap them as imported buffers).

## 6. Ergonomic pledges (checked by tests)

1. Every public name a nom user would type either exists or has the obvious
   C++ spelling (`chr`, `not_`, `seq`) — see docs/CHEATSHEET.md.
2. Failure path never allocates.
3. `sizeof(error) <= 160` and `result<int>` fits in two cache lines.
4. A wrong `get<"nmae">()` is a compile error listing valid fields.
5. `error::render()` output contains: absolute offset, hex window with caret,
   innermost expected-token, outermost context chain — in that order.

## 7. Test workloads

* **Ethernet**: Eth II → VLAN (bit fields: PCP/DEI/VID) → IPv4 (mixed bits +
  BE fields, options via length_data) → UDP/TCP → TLV payload
  (`length_value`, `many0`), from a synthetic pcap-like record stream.
* **ELF**: ident magic (`tag`), class/endianness switch mid-parse (the same
  header parsed BE or LE depending on `EI_DATA` — shows runtime endian
  selection), program headers via `count` + offset seeking.
* **FAT16**: boot sector overlay (packed, mixed widths), directory entries
  (fixed 32-byte records, `many0` + `verify` filters), 8.3 names.
