// SPDX-License-Identifier: Apache-2.0
// Shared streaming pcapng parse loop — used by the Rust head-to-head bench, streaming
// safety tests, and libFuzzer. Parses through a bounded refill window with nm::streaming.

#pragma once

#include "nm_pcap.hpp"

#include <nanom/nanom.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

namespace streaming_pcapng {

namespace nm = nanom;
using namespace nmpcap;

inline constexpr std::size_t kDefaultCap = 65536;
inline constexpr std::uint64_t kFnvOffset = 0xcbf29ce484222325ULL;
inline constexpr std::uint64_t kFnvPrime  = 0x00000100000001b3ULL;

struct agg {
  std::uint64_t packets = 0, sum_caplen = 0, sum_origlen = 0, opts = 0, checksum = kFnvOffset;
};

inline std::uint64_t mix(std::uint64_t h, std::uint64_t v) { return (h ^ v) * kFnvPrime; }

#if NANOM_GENERATION
struct track_ctx {
  nm::wire_arena   arena{};
  const std::byte* base = nullptr;
  std::size_t      have = 0;

  void sync(const std::byte* buf_base, std::size_t buf_have) {
    if (buf_base != base || buf_have != have) {
      arena.open(buf_base, buf_have);
      base = buf_base;
      have = buf_have;
    }
  }

  nm::input make(const std::byte* p, std::size_t n, const std::byte* buf_base, std::size_t buf_have,
                 bool stream) {
    sync(buf_base, buf_have);
    nm::input in = nm::from(p, n);
    in.arena     = &arena;
    in.gen       = arena.generation;
    return stream ? nm::streaming(in) : in;
  }
};
#endif

inline nm::input bench_input(const std::byte* p, std::size_t n,
#if NANOM_GENERATION
                             track_ctx& trk, const std::byte* buf_base, std::size_t buf_have,
#endif
                             bool stream) {
#if NANOM_GENERATION
  return trk.make(p, n, buf_base, buf_have, stream);
#else
  // Sized-span entry (works in every profile incl. NANOM_STRICT, which removes
  // the raw pointer+length from()).
  const auto in = nm::from(std::span<const std::byte>(p, n));
  return stream ? nm::streaming(in) : in;
#endif
}

inline nm::input bench_body(const std::byte* p, std::size_t n
#if NANOM_GENERATION
                          ,
                          track_ctx& trk, const std::byte* buf_base, std::size_t buf_have
#endif
) {
#if NANOM_GENERATION
  return trk.make(p, n, buf_base, buf_have, false);
#else
  return nm::from(std::span<const std::byte>(p, n));
#endif
}

inline agg parse(const std::vector<std::uint8_t>& data, std::size_t cap = kDefaultCap) {
  agg a;
  if (cap == 0) return a;
  std::vector<std::uint8_t> buf(cap);
  std::size_t src = 0, pos = 0, have = 0;
  bool little = true;
#if NANOM_GENERATION
  track_ctx trk;
#endif
  const auto buf_base = reinterpret_cast<const std::byte*>(buf.data());

  auto refill = [&]() -> bool {
    if (pos > 0) {
      std::memmove(buf.data(), buf.data() + pos, have - pos);
      have -= pos;
      pos = 0;
    }
    const std::size_t n = std::min(buf.size() - have, data.size() - src);
    if (n == 0) return false;
    std::memcpy(buf.data() + have, data.data() + src, n);
    src += n;
    have += n;
    return true;
  };

  while (true) {
    const std::size_t avail = have - pos;
    nm::input in = bench_input(buf_base + pos, avail
#if NANOM_GENERATION
                               ,
                               trk, buf_base, have
#endif
                               ,
                               true);
    auto hdr = nm::strct<png_block_hdr>(order_of(little))(in);
    if (!hdr) {
      if (hdr.error().kind == nm::errk::incomplete && refill()) continue;
      break;
    }
    if (hdr->value.type == kShb) {
      nm::input bo = bench_input(buf_base + pos, avail
#if NANOM_GENERATION
                                 ,
                                 trk, buf_base, have
#endif
                                 ,
                                 true);
      auto probe = nm::preceded(nm::take(std::size_t{8}), nm::le_u32)(bo);
      if (!probe) {
        if (probe.error().kind == nm::errk::incomplete && refill()) continue;
        break;
      }
      little = (probe->value == kByteOrderMagic);
      nm::input in2 = bench_input(buf_base + pos, avail
#if NANOM_GENERATION
                                  ,
                                  trk, buf_base, have
#endif
                                  ,
                                  true);
      hdr = nm::strct<png_block_hdr>(order_of(little))(in2);
      if (!hdr) break;
    }
    const std::uint32_t total = hdr->value.total_len;
    if (total < 12 || total % 4 != 0) break;
    if (total > buf.size()) break;
    if (total > avail) {
      if (refill()) continue;
      break;
    }
    if (hdr->value.type == kEpb) {
      nm::input body = bench_body(buf_base + pos + 8, total - 8
#if NANOM_GENERATION
                                  ,
                                  trk, buf_base, have
#endif
      );
      auto e = nm::strct<png_epb_body>(order_of(little))(body);
      if (e) {
        const std::uint64_t ts_raw = (std::uint64_t(e->value.ts_high) << 32) | e->value.ts_low;
        a.packets += 1;
        a.sum_caplen += e->value.caplen;
        a.sum_origlen += e->value.origlen;
        a.checksum = mix(a.checksum, ts_raw);
        a.checksum = mix(a.checksum, e->value.caplen);
        a.checksum = mix(a.checksum, e->value.origlen);

        std::size_t opt_off = pos + 28 + pad4(e->value.caplen);
        const std::size_t opt_end = pos + total - 4;
        while (opt_off + 4 <= opt_end) {
          nm::input oh_in = bench_body(buf_base + opt_off, opt_end - opt_off
#if NANOM_GENERATION
                                       ,
                                       trk, buf_base, have
#endif
          );
          auto oh = nm::strct<png_opt_hdr>(order_of(little))(oh_in);
          if (!oh) break;
          const std::uint16_t code = oh->value.code, olen = oh->value.length;
          const std::size_t padded = pad4(olen);
          if (opt_off + 4 + padded > opt_end) break;
          a.checksum = mix(a.checksum, code);
          a.checksum = mix(a.checksum, olen);
          for (std::uint16_t k = 0; k < olen; ++k) a.checksum = mix(a.checksum, buf[opt_off + 4 + k]);
          a.opts += 1;
          opt_off += 4 + padded;
        }
      }
    }
    pos += total;
  }
  return a;
}

}  // namespace streaming_pcapng
