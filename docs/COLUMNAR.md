# Columnar decode kernels and codecs

`nanom/columnar.hpp` and `nanom/codec.hpp` are the inner loops of a columnar page reader (Parquet
today; Lance shares several encodings). They turn encoded page bytes into flat, host-order buffers.

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

zstd, gzip and brotli plug in at the reader through the same shape:
`status decompress(std::span<const std::byte> in, std::span<std::byte> out)`.

## Verification

| check | what it proves |
|---|---|
| `tests/test_columnar.cpp` (default and strict profiles) | every kernel matches a reference (bit-by-bit unpacking for all widths 0..64; a reference RLE-hybrid and DELTA_BINARY_PACKED encoder over random data, decoded in random batch sizes), plus hostile run lengths, truncation and malformed headers |
| `tests/codec_differential.py` | Snappy and LZ4 output matches pyarrow's compressors on ~600 buffers from 0 B to 256 KiB |
| `fuzz/fuzz_columnar.cpp` | no crash or undefined behaviour on arbitrary bytes, in ctest and as a libFuzzer target; its first run found (and the suite now covers) a null `memcpy` on an empty LZ4 output |
