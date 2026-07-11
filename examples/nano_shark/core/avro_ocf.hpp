// SPDX-License-Identifier: Apache-2.0
#pragma once

// nano_shark/core/avro_ocf.hpp — a real Avro Object Container File writer, dependency-free (Avro
// binary encoding is just zigzag varints + raw bytes; no external Avro/codec library needed for
// the "null" codec this writes). Reuses nm::avro_schema<T>() verbatim for the header's schema
// field; the encoding technique (walk fields, zigzag-encode) mirrors soatins' avro_glue.hpp,
// re-derived nanom-natively: once over nanom::detail::for_each_field (for a single row VALUE) and
// once over nanom::soa<T>::columns() (for a soa<T> chunk, since node_table<T> only ever stores
// rows in soa<T>'s column-major form -- there is no "read row i back" API to reconstruct a T from,
// so this reads each row's fields directly from the chunk's column buffers instead).
//
// Scope limit (documented, like avro_glue.hpp's own caveats): "null" codec only here (no
// deflate/zstd dependency); u64 values above INT64_MAX wrap when zigzag-encoded as Avro `long`
// (Avro has no unsigned type) -- the same caveat soatins' avro_glue.hpp documents, for the same
// reason.

#include "node_row.hpp"

#include <nanom/nanom.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <random>
#include <string>
#include <type_traits>
#include <vector>

namespace nano_shark {

inline void avro_put_varint(std::vector<std::byte>& out, std::uint64_t u) {
  while (u >= 0x80) {
    out.push_back(std::byte((u & 0x7F) | 0x80));
    u >>= 7;
  }
  out.push_back(std::byte(u));
}
inline void avro_put_long(std::vector<std::byte>& out, std::int64_t v) {
  const std::uint64_t z = (std::uint64_t(v) << 1) ^ std::uint64_t(v >> 63);
  avro_put_varint(out, z);
}
inline void avro_put_bytes(std::vector<std::byte>& out, const void* data, std::size_t n) {
  avro_put_long(out, std::int64_t(n));
  const auto* p = static_cast<const std::byte*>(data);
  out.insert(out.end(), p, p + n);
}
inline void avro_put_fixed(std::vector<std::byte>& out, const void* data, std::size_t n) {
  const auto* p = static_cast<const std::byte*>(data);
  out.insert(out.end(), p, p + n);
}
inline void avro_put_float(std::vector<std::byte>& out, float f) {
  std::uint32_t bits;
  std::memcpy(&bits, &f, 4);
  for (int i = 0; i < 4; ++i) out.push_back(std::byte((bits >> (8 * i)) & 0xFF));
}
inline void avro_put_double(std::vector<std::byte>& out, double d) {
  std::uint64_t bits;
  std::memcpy(&bits, &d, 8);
  for (int i = 0; i < 8; ++i) out.push_back(std::byte((bits >> (8 * i)) & 0xFF));
}

namespace detail {

template <class F>
void avro_field_value(const F& v, std::vector<std::byte>& out) {
  if constexpr (nanom::Described<F>) {
    nanom::detail::for_each_field<F>(
        [&](auto fld) { avro_field_value(v.*(decltype(fld)::mem_ptr), out); });
  } else if constexpr (nanom::detail::is_std_array_v<F>) {
    using E = typename F::value_type;
    using ED = typename nanom::detail::wire<E>::decoded;
    if constexpr (sizeof(ED) == 1 && std::is_integral_v<ED>) {
      std::array<std::byte, std::tuple_size_v<F>> raw{};
      for (std::size_t i = 0; i < raw.size(); ++i) raw[i] = std::byte(std::uint8_t(ED(v[i])));
      avro_put_fixed(out, raw.data(), raw.size());
    } else {  // not exercised by any current row, but handled correctly: Avro array encoding
      avro_put_long(out, std::int64_t(v.size()));
      for (const auto& e : v) avro_field_value(e, out);
      avro_put_long(out, 0);
    }
  } else {
    using D = typename nanom::detail::wire<F>::decoded;
    D d = D(v);
    if constexpr (std::floating_point<D>) {
      if constexpr (sizeof(D) == 4) avro_put_float(out, float(d));
      else avro_put_double(out, double(d));
    } else {
      avro_put_long(out, std::int64_t(d));  // covers integers AND bool (0/1), matching
                                            // nm::avro_schema<T>()'s own u8-shaped "int" for bool
    }
  }
}

}  // namespace detail

// Binary-encodes one row's fields in schema-declaration order (depth-first through nested
// Described members, matching how a nested Avro record's fields are concatenated on the wire).
template <nanom::Described T>
void avro_encode_row(const T& row, std::vector<std::byte>& out) {
  detail::avro_field_value(row, out);
}

// A real Avro Object Container File: "Obj\x01" magic, header (avro.schema = nm::avro_schema<T>(),
// avro.codec = "null"), a random 16-byte sync marker, then one block per write_row/write_chunk
// call (row count, encoded-bytes size, the encoded rows, the sync marker repeated).
template <nanom::Described T>
class AvroOcfWriter {
 public:
  explicit AvroOcfWriter(const std::string& path) : out_(path, std::ios::binary) {
    if (!out_) return;
    std::random_device rd;
    std::mt19937_64 gen(rd());
    for (std::byte& b : sync_) b = std::byte(std::uint8_t(gen()));
    write_header();
  }

  bool ok() const { return bool(out_); }

  // One row at a time, for a caller that has a T value directly.
  void write_row(const T& row) {
    if (!ok()) return;
    std::vector<std::byte> block;
    avro_encode_row(row, block);
    write_block(1, block);
  }

  // One nanom::soa<T> chunk at a time: reads each row's fields directly from the chunk's column
  // buffers (soa<T>'s leaf-column order already matches avro_schema<T>()'s depth-first field
  // order, since both derive from the same for_each_field traversal) -- no row object is ever
  // reconstructed, since soa<T> has no API to do that and none is needed here.
  void write_chunk(const typename nanom::soa<T>::chunk& c) {
    if (!ok() || c.rows == 0) return;
    const auto& cols = probe_.columns();
    std::vector<std::byte> block;
    for (std::size_t r = 0; r < c.rows; ++r) {
      for (std::size_t i = 0; i < cols.size(); ++i) encode_column_value(cols[i], c.col(i), r, block);
    }
    write_block(c.rows, block);
  }

  void close() { out_.close(); }

 private:
  void write_header() {
    out_.write("Obj\x01", 4);
    const std::string schema = nanom::avro_schema<T>();
    std::vector<std::byte> hdr;
    avro_put_long(hdr, 2);  // one metadata block, 2 entries
    avro_put_bytes(hdr, "avro.schema", 11);
    avro_put_bytes(hdr, schema.data(), schema.size());
    avro_put_bytes(hdr, "avro.codec", 10);
    avro_put_bytes(hdr, "null", 4);
    avro_put_long(hdr, 0);  // terminate the metadata map
    out_.write(reinterpret_cast<const char*>(hdr.data()), std::streamsize(hdr.size()));
    out_.write(reinterpret_cast<const char*>(sync_.data()), std::streamsize(sync_.size()));
  }

  static void encode_column_value(const typename nanom::soa<T>::column_info& info, nanom::bytes col,
                                  std::size_t row, std::vector<std::byte>& out) {
    const std::byte* p = col.data() + row * info.elem_bytes;
    switch (info.kind) {
      case nanom::dkind::u8: avro_put_long(out, std::int64_t(std::uint8_t(*p))); break;
      case nanom::dkind::i8: avro_put_long(out, std::int64_t(*reinterpret_cast<const std::int8_t*>(p))); break;
      case nanom::dkind::u16: { std::uint16_t v; std::memcpy(&v, p, 2); avro_put_long(out, std::int64_t(v)); break; }
      case nanom::dkind::i16: { std::int16_t v; std::memcpy(&v, p, 2); avro_put_long(out, std::int64_t(v)); break; }
      case nanom::dkind::u32: { std::uint32_t v; std::memcpy(&v, p, 4); avro_put_long(out, std::int64_t(v)); break; }
      case nanom::dkind::i32: { std::int32_t v; std::memcpy(&v, p, 4); avro_put_long(out, std::int64_t(v)); break; }
      case nanom::dkind::u64: { std::uint64_t v; std::memcpy(&v, p, 8); avro_put_long(out, std::int64_t(v)); break; }
      case nanom::dkind::i64: { std::int64_t v; std::memcpy(&v, p, 8); avro_put_long(out, v); break; }
      case nanom::dkind::f32: { float v; std::memcpy(&v, p, 4); avro_put_float(out, v); break; }
      case nanom::dkind::f64: { double v; std::memcpy(&v, p, 8); avro_put_double(out, v); break; }
      case nanom::dkind::fixed_bin:
      case nanom::dkind::list: avro_put_fixed(out, p, info.elem_bytes); break;
      case nanom::dkind::record: break;  // never a leaf column: soa<T> flattens nested records
    }
  }

  void write_block(std::size_t count, const std::vector<std::byte>& objects) {
    std::vector<std::byte> hdr;
    avro_put_long(hdr, std::int64_t(count));
    avro_put_long(hdr, std::int64_t(objects.size()));
    out_.write(reinterpret_cast<const char*>(hdr.data()), std::streamsize(hdr.size()));
    out_.write(reinterpret_cast<const char*>(objects.data()), std::streamsize(objects.size()));
    out_.write(reinterpret_cast<const char*>(sync_.data()), std::streamsize(sync_.size()));
  }

  std::ofstream           out_;
  std::array<std::byte, 16> sync_{};
  nanom::soa<T>           probe_{1};  // never pushed to; exists only for its compile-time columns()
};

}  // namespace nano_shark
