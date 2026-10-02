// SPDX-License-Identifier: Apache-2.0
// nanom/formats/parquet_values.hpp — Parquet-only value framing on top of nanom/values.hpp.
//
// Everything generic (bitmaps, levels, byte arrays, dictionaries, UTF-8, widening) lives in
// nanom/values.hpp and nanom/columnar.hpp; this header holds the few layouts only Parquet uses.
#ifndef NANOM_FORMATS_PARQUET_VALUES_HPP_INCLUDED
#define NANOM_FORMATS_PARQUET_VALUES_HPP_INCLUDED

#include "../values.hpp"

namespace nanom_formats::parquet {

namespace col = nanom::columnar;

/// INT96 (Impala / Hive legacy timestamps): 8 bytes of nanoseconds within the day, then a 4-byte
/// Julian day, both little-endian -> nanoseconds since the Unix epoch. Wrapping arithmetic, as
/// Arrow computes it.
inline std::int64_t int96_to_unix_nanos(const std::byte* v) {
  std::uint64_t nanos;
  std::uint32_t jd;
  std::memcpy(&nanos, v, 8);
  std::memcpy(&jd, v + 8, 4);
  if constexpr (std::endian::native == std::endian::big) {
    nanos = std::byteswap(nanos);
    jd = std::byteswap(jd);
  }
  return std::int64_t(std::uint64_t(std::int64_t(jd) - 2440588) * 86400000000000ull + nanos);
}

/// The indices of a PLAIN_DICTIONARY / RLE_DICTIONARY data page: one byte of bit width, then an
/// RLE / bit-packed stream. Decodes nn indices into `out` and checks each is < dict_size.
inline col::kernel_status dictionary_indices(std::span<const std::byte> vals, std::size_t nn, std::size_t dict_size,
                                             std::span<std::uint32_t> out) {
  if (out.size() < nn) return col::kernel_fail("output smaller than the value count");
  if (nn == 0) return col::kernel_ok;
  if (vals.empty()) return col::kernel_fail("dictionary indices missing");
  const unsigned bw = std::uint8_t(vals[0]);
  if (bw > 32) return col::kernel_fail("dictionary index bit width over 32");
  col::rle_bp_decoder d(vals.subspan(1), bw);
  if (d.get(out.data(), nn) != nn || !d.ok()) return col::kernel_fail("dictionary indices shorter than the page");
  if (!col::check_indices(out.first(nn), dict_size)) return col::kernel_fail("dictionary index out of range");
  return col::kernel_ok;
}

}  // namespace nanom_formats::parquet

#endif  // NANOM_FORMATS_PARQUET_VALUES_HPP_INCLUDED
