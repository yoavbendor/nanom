// SPDX-License-Identifier: Apache-2.0
// nanom/layout/e2e.hpp — AUTOSAR E2E (end-to-end) protection of PDU buffers: protect() writes the
// counter / length / data-ID fields and the CRC, check() verifies a received PDU and runs the
// per-data-ID counter state machine.
//
//   namespace e2e = nanom::layout::e2e;
//   e2e::config c{.prof = e2e::profile::p05, .data_id = 0x1234};
//   e2e::protector tx(c);   tx.protect(pdu);                 // counter 0, 1, 2, ... per call
//   e2e::checker   rx(c);   e2e::status s = rx.check(pdu);   // ok / repeated / wrong_crc / ...
//
// Header layouts and CRCs (PRS_E2EProtocol). Offsets are in BITS, as AUTOSAR configures them
// (multiples of 8 except the P01/P11 nibbles). "excl. CRC" = every PDU byte except the CRC field.
//
//   P01  CRC8 SAE-J1850 (init 0, xorout 0)  CRC byte at crc_offset, counter nibble (0..14) at
//        counter_offset, data-ID nibble at nibble_offset (mode nibble). CRC over the data-ID
//        bytes (mode both: low, high / low: low / alt: low if counter even else high /
//        nibble: low, 0x00) then the data excl. CRC.
//   P02  CRC8H2F over data[1..n) then data_id_list[counter]; CRC byte 0, counter low nibble of
//        byte 1 (0..15).
//   P04  12-byte big-endian header at offset: length u16, counter u16, data ID u32, CRC u32;
//        CRC32P4 over the data excl. CRC.
//   P05  3-byte header at offset: CRC u16 LITTLE-endian, counter u8; CRC16 (CCITT-FALSE) over the
//        data excl. CRC, then data ID low byte, high byte.
//   P06  5-byte big-endian header at offset: CRC u16, length u16, counter u8; CRC16 over the data
//        excl. CRC, then data ID high byte, low byte.
//   P07  20-byte big-endian header at offset: CRC u64, length u32, counter u32, data ID u32;
//        CRC64 over the data excl. CRC.
//   P11  as P01 (modes both / nibble only, counter 0..14); the CRC is computed the same way.
//   P22  CRC8H2F like P02 with the header at offset: CRC byte, then counter low nibble (0..15);
//        CRC over the data excl. CRC then data_id_list[counter].
//
// Verification (docs/LAYOUT.md "E2E"): P01 (all four data-ID modes), P02, P04, P05, P06, P07
// and P11 (both modes) are checked byte for byte against the independent `autosar-e2e` Python
// package (tests/layout_autosar_oracle.py, random PDUs, lengths and offsets) and by golden vectors
// in tests/test_layout_autosar.cpp. P22 has NO independent oracle: it is implemented from the
// PRS text and equals P02 at offset 0 (tested) -- treat it as unverified.
//
// check(): the counter evaluation of the R4.2+ profiles (P04 ... P22): the state starts at the
// counter maximum (so a first PDU with counter 0 is `ok`), delta = (received - last) mod range:
// 0 repeated, 1 ok, 2..max_delta_counter ok_some_lost, else wrong_sequence; the state takes the
// received counter whenever the PDU is not an error. P01/P02 use the same evaluation here, NOT the
// legacy P01/P02 state machine (INITIAL / SYNC / MaxNoNewOrRepeatedData) -- see docs.
#ifndef NANOM_LAYOUT_E2E_HPP_INCLUDED
#define NANOM_LAYOUT_E2E_HPP_INCLUDED

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "../checksum.hpp"

namespace nanom::layout::e2e {

enum class profile : std::uint8_t { p01, p02, p04, p05, p06, p07, p11, p22 };
/// P01 / P11 data-ID inclusion. P11 supports both and nibble only.
enum class data_id_mode : std::uint8_t { both, alt, low, nibble };

enum class status : std::uint8_t {
  ok,              ///< new data, counter advanced by 1
  ok_some_lost,    ///< new data, counter advanced by 2..max_delta_counter
  repeated,        ///< same counter as the last PDU
  wrong_sequence,  ///< counter jumped by more than max_delta_counter
  no_new_data,     ///< check() called without new data
  wrong_crc,
  wrong_length,    ///< PDU too short for the header, length field mismatch, or outside min/max
  wrong_data_id,   ///< P04/P07 data-ID field, P01/P11 data-ID nibble
  bad_counter,     ///< P01/P11 counter value 15 (not allowed)
  bad_config       ///< the configuration does not fit this PDU (offsets, mode for the profile)
};
inline const char* status_name(status s) {
  static constexpr const char* n[] = {"ok", "ok_some_lost", "repeated", "wrong_sequence", "no_new_data",
                                      "wrong_crc", "wrong_length", "wrong_data_id", "bad_counter", "bad_config"};
  return n[std::size_t(s)];
}
/// True for the statuses that deliver usable data (ok, ok_some_lost).
constexpr bool usable(status s) { return s == status::ok || s == status::ok_some_lost; }

struct config {
  profile prof = profile::p05;
  std::uint32_t data_id = 0;                       ///< P01/P11: 16 bits, P05/P06: 16, P04/P07: 32
  std::array<std::uint8_t, 16> data_id_list{};     ///< P02 / P22
  data_id_mode id_mode = data_id_mode::both;       ///< P01 / P11
  std::uint32_t offset = 0;                        ///< bits: header start (P01/P11: CRC offset)
  std::optional<std::uint32_t> counter_offset;     ///< P01/P11 bits (default offset + 8)
  std::optional<std::uint32_t> nibble_offset;      ///< P01/P11 bits (default offset + 12)
  std::uint32_t max_delta_counter = 1;             ///< check(): largest accepted counter step
  std::size_t min_length = 0, max_length = 0;      ///< check() bytes, P04/P06/P07 (0 = no limit)
};

/// Largest counter value of a profile (counters wrap to 0 after it).
constexpr std::uint32_t counter_max(profile p) {
  switch (p) {
    case profile::p01: case profile::p11: return 14;
    case profile::p02: case profile::p22: return 15;
    case profile::p04: return 0xFFFF;
    case profile::p05: case profile::p06: return 0xFF;
    case profile::p07: return 0xFFFFFFFFu;
  }
  return 0;
}
/// Bytes of the E2E header (from the header offset).
constexpr std::size_t header_bytes(profile p) {
  switch (p) {
    case profile::p04: return 12;
    case profile::p05: return 3;
    case profile::p06: return 5;
    case profile::p07: return 20;
    default: return 2;
  }
}

namespace detail {
inline std::uint64_t be(const std::byte* p, unsigned n) {
  std::uint64_t v = 0;
  for (unsigned i = 0; i < n; ++i) v = (v << 8) | std::uint8_t(p[i]);
  return v;
}
inline void put_be(std::byte* p, std::uint64_t v, unsigned n) {
  for (unsigned i = 0; i < n; ++i) p[i] = std::byte(v >> (8 * (n - 1 - i)));
}
inline unsigned nibble(const std::byte* d, std::uint32_t bit) { return (std::uint8_t(d[bit / 8]) >> (bit % 8)) & 0xF; }
inline void put_nibble(std::byte* d, std::uint32_t bit, unsigned v) {
  const unsigned sh = bit % 8;
  d[bit / 8] = std::byte((std::uint8_t(d[bit / 8]) & ~(0xFu << sh)) | ((v & 0xF) << sh));
}
/// A CRC over data with the bytes [skip, skip + n) left out, then `tail`.
template <class C>
inline C crc_excluding(C c, std::span<const std::byte> d, std::size_t skip, std::size_t n) {
  c.update(d.first(skip));
  c.update(d.subspan(skip + n));
  return c;
}
inline std::uint32_t counter_bit(const config& c) { return c.counter_offset.value_or(c.offset + 8); }
inline std::uint32_t nibble_bit(const config& c) { return c.nibble_offset.value_or(c.offset + 12); }
}  // namespace detail

/// Bytes a PDU needs for this configuration's header; 0 = the configuration itself is invalid
/// (misaligned offsets, overlapping P01/P11 fields, a data-ID mode the profile lacks, P02 offset).
inline std::size_t required_length(const config& c) {
  switch (c.prof) {
    case profile::p01: case profile::p11: {
      const std::uint32_t cb = detail::counter_bit(c), nb = detail::nibble_bit(c);
      if (c.offset % 8 || cb % 4 || nb % 4 || cb / 8 == c.offset / 8) return 0;
      if (c.prof == profile::p11 && c.id_mode != data_id_mode::both && c.id_mode != data_id_mode::nibble) return 0;
      std::size_t end = std::max(c.offset, cb) / 8 + 1;
      if (c.id_mode == data_id_mode::nibble) {
        if (nb / 8 == c.offset / 8 || nb == cb) return 0;
        end = std::max<std::size_t>(end, nb / 8 + 1);
      }
      return end;
    }
    case profile::p02:
      return c.offset == 0 ? 2 : 0;
    default:
      return c.offset % 8 ? 0 : c.offset / 8 + header_bytes(c.prof);
  }
}
/// The configuration fits a PDU of `length` bytes.
inline bool valid(const config& c, std::size_t length) {
  const std::size_t r = required_length(c);
  return r != 0 && length >= r;
}

/// The CRC `protect` stores, given the PDU with its other header fields (counter, length, data
/// ID, P01/P11 nibble) already in place. `data` is the whole PDU.
inline std::uint64_t compute_crc(const config& c, std::span<const std::byte> data) {
  const std::size_t at = c.offset / 8;
  switch (c.prof) {
    case profile::p01: case profile::p11: {
      const auto lo = std::uint8_t(c.data_id), hi = std::uint8_t(c.data_id >> 8);
      // AUTOSAR: Crc_CalculateCRC8(.., StartValue 0xFF, IsFirstCall FALSE) chained, then ^ 0xFF:
      // a CRC-8/SAE-J1850 register starting at 0 with no final xor.
      auto k = crc8_sae_j1850::resume(0xFF);
      switch (c.id_mode) {
        case data_id_mode::both: k.update(lo).update(hi); break;
        case data_id_mode::low: k.update(lo); break;
        case data_id_mode::nibble: k.update(lo).update(std::uint8_t(0)); break;
        case data_id_mode::alt: k.update(detail::nibble(data.data(), detail::counter_bit(c)) % 2 ? hi : lo); break;
      }
      return std::uint8_t(detail::crc_excluding(k, data, at, 1).value() ^ 0xFF);
    }
    case profile::p02: case profile::p22: {
      const unsigned ctr = std::uint8_t(data[at + 1]) & 0xF;
      auto k = detail::crc_excluding(crc8_h2f{}, data, at, 1);
      k.update(c.data_id_list[ctr]);
      return k.value();
    }
    case profile::p04:
      return detail::crc_excluding(crc32_p4{}, data, at + 8, 4).value();
    case profile::p05: {
      auto k = detail::crc_excluding(crc16_ccitt_false{}, data, at, 2);
      k.update(std::uint8_t(c.data_id)).update(std::uint8_t(c.data_id >> 8));
      return k.value();
    }
    case profile::p06: {
      auto k = detail::crc_excluding(crc16_ccitt_false{}, data, at, 2);
      k.update(std::uint8_t(c.data_id >> 8)).update(std::uint8_t(c.data_id));
      return k.value();
    }
    case profile::p07:
      return detail::crc_excluding(crc64{}, data, at, 8).value();
  }
  return 0;
}

/// The counter stored in a PDU.
inline std::uint32_t read_counter(const config& c, std::span<const std::byte> d) {
  const std::size_t at = c.offset / 8;
  switch (c.prof) {
    case profile::p01: case profile::p11: return detail::nibble(d.data(), detail::counter_bit(c));
    case profile::p02: case profile::p22: return std::uint8_t(d[at + 1]) & 0xF;
    case profile::p04: return std::uint32_t(detail::be(d.data() + at + 2, 2));
    case profile::p05: return std::uint8_t(d[at + 2]);
    case profile::p06: return std::uint8_t(d[at + 4]);
    case profile::p07: return std::uint32_t(detail::be(d.data() + at + 12, 4));
  }
  return 0;
}
/// The CRC stored in a PDU.
inline std::uint64_t read_crc(const config& c, std::span<const std::byte> d) {
  const std::size_t at = c.offset / 8;
  switch (c.prof) {
    case profile::p04: return detail::be(d.data() + at + 8, 4);
    case profile::p05: return std::uint8_t(d[at]) | unsigned(std::uint8_t(d[at + 1])) << 8;
    case profile::p06: return detail::be(d.data() + at, 2);
    case profile::p07: return detail::be(d.data() + at, 8);
    default: return std::uint8_t(d[at]);
  }
}

/// Write counter, length, data ID / nibble and CRC into `data` (the whole PDU; every other
/// byte is left as is). false (nothing written) when the config does not fit the PDU or the
/// counter is above counter_max(). Stateless; protector keeps the counter.
inline bool protect(const config& c, std::span<std::byte> data, std::uint32_t counter) {
  if (!valid(c, data.size()) || counter > counter_max(c.prof)) return false;
  std::byte* d = data.data();
  const std::size_t at = c.offset / 8, n = data.size();
  switch (c.prof) {
    case profile::p01: case profile::p11:
      detail::put_nibble(d, detail::counter_bit(c), counter);
      if (c.id_mode == data_id_mode::nibble) detail::put_nibble(d, detail::nibble_bit(c), (c.data_id >> 8) & 0xF);
      d[at] = std::byte(compute_crc(c, data));
      return true;
    case profile::p02: case profile::p22:
      d[at + 1] = std::byte((std::uint8_t(d[at + 1]) & 0xF0) | counter);
      d[at] = std::byte(compute_crc(c, data));
      return true;
    case profile::p04:
      if (n > 0xFFFF) return false;
      detail::put_be(d + at, n, 2);
      detail::put_be(d + at + 2, counter, 2);
      detail::put_be(d + at + 4, c.data_id, 4);
      detail::put_be(d + at + 8, compute_crc(c, data), 4);
      return true;
    case profile::p05: {
      d[at + 2] = std::byte(counter);
      const auto k = std::uint16_t(compute_crc(c, data));
      d[at] = std::byte(k);
      d[at + 1] = std::byte(k >> 8);
      return true;
    }
    case profile::p06:
      if (n > 0xFFFF) return false;
      detail::put_be(d + at + 2, n, 2);
      d[at + 4] = std::byte(counter);
      detail::put_be(d + at, compute_crc(c, data), 2);
      return true;
    case profile::p07:
      if (n > 0xFFFFFFFFu) return false;
      detail::put_be(d + at + 8, n, 4);
      detail::put_be(d + at + 12, counter, 4);
      detail::put_be(d + at + 16, c.data_id, 4);
      detail::put_be(d + at, compute_crc(c, data), 8);
      return true;
  }
  return false;
}

/// Verify one PDU without state: header fields and CRC. Returns ok or the first error
/// (wrong_length, wrong_data_id, bad_counter, wrong_crc, bad_config).
inline status verify(const config& c, std::span<const std::byte> data) {
  const std::size_t need = required_length(c);
  if (need == 0) return status::bad_config;
  if (data.size() < need) return status::wrong_length;
  const std::byte* d = data.data();
  const std::size_t at = c.offset / 8, n = data.size();
  const auto in_range = [&] { return (c.min_length == 0 || n >= c.min_length) && (c.max_length == 0 || n <= c.max_length); };
  switch (c.prof) {
    case profile::p01: case profile::p11:
      if (read_counter(c, data) > 14) return status::bad_counter;
      if (c.id_mode == data_id_mode::nibble && detail::nibble(d, detail::nibble_bit(c)) != ((c.data_id >> 8) & 0xF))
        return status::wrong_data_id;
      break;
    case profile::p04:
      if (!in_range() || detail::be(d + at, 2) != n) return status::wrong_length;
      if (detail::be(d + at + 4, 4) != c.data_id) return status::wrong_data_id;
      break;
    case profile::p06:
      if (!in_range() || detail::be(d + at + 2, 2) != n) return status::wrong_length;
      break;
    case profile::p07:
      if (!in_range() || detail::be(d + at + 8, 4) != n) return status::wrong_length;
      if (detail::be(d + at + 16, 4) != c.data_id) return status::wrong_data_id;
      break;
    default:
      if (!in_range()) return status::wrong_length;
      break;
  }
  return read_crc(c, data) == compute_crc(c, data) ? status::ok : status::wrong_crc;
}

/// Sender side: one per data ID. protect() writes counter 0, 1, ..., counter_max, 0, ...
class protector {
 public:
  protector() = default;
  explicit protector(const config& c) : c_(c) {}
  /// Protect `pdu` with the current counter, then advance it. false = config/PDU mismatch
  /// (the counter does not advance).
  bool protect(std::span<std::byte> pdu) {
    if (!e2e::protect(c_, pdu, counter_)) return false;
    counter_ = counter_ == counter_max(c_.prof) ? 0 : counter_ + 1;
    return true;
  }
  std::uint32_t counter() const { return counter_; }
  void counter(std::uint32_t v) { counter_ = v > counter_max(c_.prof) ? 0 : v; }
  const config& cfg() const { return c_; }

 private:
  config c_;
  std::uint32_t counter_ = 0;
};

/// Receiver side: the counter state machine of one data ID.
class checker {
 public:
  checker() = default;
  explicit checker(const config& c) : c_(c), last_(counter_max(c.prof)) {}
  /// Check a received PDU (new_data = false: nothing was received this cycle -> no_new_data).
  status check(std::span<const std::byte> pdu, bool new_data = true) {
    lost_ = 0;
    if (!new_data) return status::no_new_data;
    const status v = verify(c_, pdu);
    if (v != status::ok) return v;
    const std::uint64_t range = std::uint64_t(counter_max(c_.prof)) + 1;
    const std::uint32_t rec = read_counter(c_, pdu);
    const std::uint64_t delta = (rec + range - last_) % range;
    last_ = rec;
    if (delta == 0) return status::repeated;
    if (delta == 1) return status::ok;
    if (delta <= c_.max_delta_counter) { lost_ = std::uint32_t(delta - 1); return status::ok_some_lost; }
    return status::wrong_sequence;
  }
  /// PDUs lost before the last ok_some_lost.
  std::uint32_t lost() const { return lost_; }
  std::uint32_t last_counter() const { return last_; }
  void reset() { last_ = counter_max(c_.prof); lost_ = 0; }
  const config& cfg() const { return c_; }

 private:
  config c_;
  std::uint32_t last_ = 0, lost_ = 0;
};

}  // namespace nanom::layout::e2e

#endif
