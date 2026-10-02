# Columnar decode kernels, value kernels and codecs

These headers are the inner loops of a columnar reader (Parquet today; Lance shares most of them).
A reader built on them keeps only its format's framing (page layout, which encoding applies where)
and its output container.

- `nanom/columnar.hpp`: encoded bits -> integers (bit unpacking, RLE / bit-packed runs, deltas).
- `nanom/values.hpp`: integers and byte ranges -> values (bitmaps, Dremel levels and structure,
  null spreading, offsets + data, dictionaries, UTF-8, widening). No file format in it.
- `nanom/codec.hpp`: dependency-free Snappy and LZ4 block decompression.
- `nanom/formats/parquet_values.hpp`: the two layouts only Parquet uses (INT96 timestamps, the
  bit-width byte in front of dictionary indices).

## One safety rule: check at the boundary, run unchecked inside

Every count and size taken from the wire is validated once, against the input span and the caller's
output span, before a loop starts. The loop itself never reads past what was proven present and
never writes past the output. A kernel that cannot finish says so (`false`, `nullopt`, a short
count or a `codec_error`); it never guesses.

| kernel | encoding | notes |
|---|---|---|
| `unpack_bits<U>(in, width, out, n)` | LSB-first bit packing | the width is a template parameter inside the loop: one runtime switch picks a loop specialized per width (0..32 for `u32`, 0..64 for `u64`) |
| `rle_bp_decoder` | RLE / bit-packed hybrid (levels, dictionary indices, RLE booleans) | streams in caller-sized batches; wire run lengths never size anything; a truncated final run yields what is present |
| `delta_binary_packed<T>(in, out, n)` | DELTA_BINARY_PACKED (int32/int64), the length stream of DELTA_(LENGTH_)BYTE_ARRAY | wrapping arithmetic (no signed overflow); returns the bytes consumed |
| `byte_stream_split(in, width, n, out)` | BYTE_STREAM_SPLIT | any fixed width; 4-byte (float) path unrolled |
| `copy_bits(in, n, out, dst_bit)` | PLAIN booleans | already Arrow's bitmap layout: a memcpy when byte-aligned |
| `codec::snappy_decompress(in, out)` | Snappy raw block (Parquet SNAPPY) | output sized from the page header; back-references outside the output are rejected |
| `codec::lz4_block_decompress(in, out)` | LZ4 block (Parquet LZ4_RAW) | same guarantees |

### Value kernels (`values.hpp`)

Kernels that can fail return `kernel_status` (`explicit operator bool`; `.error` is a static
message). Outputs are sized by the caller; the doc comment of each kernel states how much.

| kernel | what it does | used for |
|---|---|---|
| `set_bits`, `count_bits`, `get_bit` | LSB-first bitmaps, a 64-bit word at a time | validity |
| `rle_bitmap(decoder, n, out, at)` | a width-1 RLE / bit-packed stream into a bitmap, run by run (fills and bit copies) | definition levels of optional fields, RLE booleans |
| `scatter_bits(dense, validity, n, out, at)` | dense bits to the non-null slots of a bitmap | booleans with nulls |
| `decode_levels(data, max, n, out_u16)` | RLE / bit-packed levels straight to u16, range-checked | repetition / definition levels |
| `level_slots(def, n, slot_level, max_def, bm)` | which level entries are value slots, and which are non-null | leaves of nested columns |
| `struct_slots`, `list_slots` (`dremel_node`) | Dremel record assembly: struct validity, list offsets + validity, with parent / child count checks | struct / list / map columns (Parquet; Lance's rep/def structural encoding) |
| `spread_nulls(dst, n, nn, width, validity)` | nn dense fixed-width values spread over n slots in place, nulls zeroed; branchless on mixed words | every fixed-width column with nulls |
| `sign_extend_be`, `sign_extend_le` | big-endian / narrower two's complement to wider little-endian | decimals -> decimal128 |
| `length_prefixed_views` | `[u32 len][bytes]` values -> views | PLAIN BYTE_ARRAY, dictionary pages |
| `delta_length_views`, `delta_prefix_views` | DELTA_LENGTH_BYTE_ARRAY, DELTA_BYTE_ARRAY (front coding, rebuilt into a bounded arena) | string / binary columns |
| `check_indices`, `gather_fixed`, `gathered_size` | dictionary index bounds, fixed-width gather, gathered byte count | dictionary-encoded columns |
| `append_length_prefixed`, `append_gathered`, `append_views` | write values + int32 (or int64) end offsets for n slots, nulls repeating the offset; short values move as one 16-byte copy into `kValueSlack` | Arrow / Lance offsets + data output |
| `valid_utf8`, `utf8_starts_ok` | UTF-8 check of a whole buffer (ASCII-word fast path), then a boundary check per value start | string columns: one pass per page, not per value |

zstd, gzip and brotli plug in at the reader through the same shape:
`status decompress(std::span<const std::byte> in, std::span<std::byte> out)`.

## Verification

| check | what it proves |
|---|---|
| `tests/test_columnar.cpp` (default and strict profiles) | every kernel matches a reference (bit-by-bit unpacking for all widths 0..64; a reference RLE-hybrid and DELTA_BINARY_PACKED encoder over random data, decoded in random batch sizes), plus hostile run lengths, truncation and malformed headers. The value kernels are checked against naive implementations over random data: bitmaps, levels at every width (and values above the maximum), a hand-built nested list, null spreading at widths 1–16 and every density, the three byte-array encodings, dictionary gathers, UTF-8 edge cases and widening |
| `tests/codec_differential.py` | Snappy and LZ4 output matches pyarrow's compressors on ~600 buffers from 0 B to 256 KiB |
| `fuzz/fuzz_columnar.cpp` | no crash or undefined behaviour on arbitrary bytes, in ctest and as a libFuzzer target, for every wire-driven kernel (codecs with the output sized from the Snappy preamble; levels, bitmaps, Dremel assembly, byte arrays, dictionary indices with exact-size outputs); its first run found (and the suite now covers) a null `memcpy` on an empty LZ4 output |
