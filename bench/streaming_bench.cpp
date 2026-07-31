// SPDX-License-Identifier: Apache-2.0

// Benchmark for the EPB-at-a-time streaming decode (nanom_shark/streaming.hpp), quantifying the
// two things that work is supposed to buy, and the one thing it must not cost:
//
//   (A) MEMORY BOUND. run_decode_pass takes the whole capture as one nanom::bytes -- the file is
//       resident, in full, for the entire pass, because zero-copy reassembly holds spans into it.
//       StreamingDecodeSession is fed one block at a time out of a small recycled pool, so the
//       caller's packet-buffer footprint is bounded by how many buffers open reassemblies pin, not
//       by the file size. This bench measures both: bytes the caller must keep resident, and the
//       high-water number of pool slots actually in use, on a synthetic capture with many
//       interleaved fragmented datagrams. Only the CALLER-side buffer footprint is measured (the
//       decoded tables grow with the data either way, identically, in both modes).
//
//   (B) THROUGHPUT. The per-EPB work is the same PacketVisitor walk in both modes; the session adds
//       a synthetic BlockRef, a token compare, and (only when something is pinned) one hash-map
//       probe. This bench reports ns/packet for the whole-file pass and for the streaming session
//       over the same capture, on a fragment-free capture (the hot path most captures are) and on
//       the defrag-heavy one, so any regression shows up where it actually happens. The copy into
//       the pool slot is timed as part of the streaming number: a real streaming caller reads into
//       that buffer instead, but charging it here keeps the comparison honest rather than flattering.
//
// Best-of-N, no file I/O, in-memory synthetic captures. A checksum over the decoded tables keeps
// the optimizer honest and proves both modes decode identically.

#include <nanom_shark/decode_pass.hpp>
#include <nanom_shark/streaming.hpp>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

using Bytes = std::vector<std::uint8_t>;

void put8(Bytes& b, std::uint8_t v) { b.push_back(v); }
void put16be(Bytes& b, std::uint16_t v) { put8(b, std::uint8_t(v >> 8)); put8(b, std::uint8_t(v)); }
void put32be(Bytes& b, std::uint32_t v) {
  put16be(b, std::uint16_t(v >> 16));
  put16be(b, std::uint16_t(v));
}
void put16le(Bytes& b, std::uint16_t v) { put8(b, std::uint8_t(v)); put8(b, std::uint8_t(v >> 8)); }
void put32le(Bytes& b, std::uint32_t v) {
  put16le(b, std::uint16_t(v));
  put16le(b, std::uint16_t(v >> 16));
}

struct Capture {
  Bytes file;
  struct Rec { std::size_t off, len; };
  std::vector<Rec> records;
  std::size_t max_record = 0;
};

Capture new_capture() {
  Capture c;
  put32le(c.file, 0xA1B2C3D4U);
  put16le(c.file, 2);
  put16le(c.file, 4);
  put32le(c.file, 0);
  put32le(c.file, 0);
  put32le(c.file, 65535);
  put32le(c.file, 1);  // Ethernet
  return c;
}

void add_record(Capture& c, const Bytes& pkt, std::uint32_t ts) {
  const std::size_t off = c.file.size();
  put32le(c.file, ts);
  put32le(c.file, 0);
  put32le(c.file, std::uint32_t(pkt.size()));
  put32le(c.file, std::uint32_t(pkt.size()));
  c.file.insert(c.file.end(), pkt.begin(), pkt.end());
  c.records.push_back(Capture::Rec{off, 16 + pkt.size()});
  if (16 + pkt.size() > c.max_record) c.max_record = 16 + pkt.size();
}

Bytes eth_ipv4(std::uint16_t ident, std::uint16_t frag_off_units, bool mf, std::uint8_t dst_last,
               const Bytes& payload) {
  Bytes p;
  for (int i = 0; i < 6; ++i) put8(p, 0x02);
  for (int i = 0; i < 6; ++i) put8(p, 0x06);
  put16be(p, 0x0800);
  put8(p, 0x45);
  put8(p, 0x00);
  put16be(p, std::uint16_t(20 + payload.size()));
  put16be(p, ident);
  put16be(p, std::uint16_t((mf ? 0x2000u : 0u) | (frag_off_units & 0x1FFFu)));
  put8(p, 64);
  put8(p, 17);
  put16be(p, 0);
  put8(p, 10); put8(p, 0); put8(p, 0); put8(p, 1);
  put8(p, 10); put8(p, 0); put8(p, 0); put8(p, dst_last);
  p.insert(p.end(), payload.begin(), payload.end());
  return p;
}

// A SOME/IP-SD datagram, so a completed reassembly does real work (header + SD entry + option) over
// the segment list rather than just reading a UDP header.
Bytes someip_sd_datagram(std::uint16_t seed) {
  Bytes d;
  put16be(d, 30490);
  put16be(d, 30490);
  put16be(d, 8 + 56);
  put16be(d, 0);
  put16be(d, 0xFFFF);
  put16be(d, 0x8100);
  put32be(d, 8 + 40);
  put16be(d, seed);
  put16be(d, std::uint16_t(seed + 1));
  put8(d, 1); put8(d, 1); put8(d, 0x02); put8(d, 0);
  put8(d, 0xC0); put8(d, 0); put8(d, 0); put8(d, 0);
  put32be(d, 16);
  put8(d, 0x01); put8(d, 0); put8(d, 0); put8(d, 0x10);
  put16be(d, std::uint16_t(0x1000 + seed));
  put16be(d, std::uint16_t(0x2000 + seed));
  put8(d, 1); put8(d, 0); put8(d, 0); put8(d, 60);
  put32be(d, seed);
  put32be(d, 12);
  put16be(d, 9);
  put8(d, 0x04); put8(d, 0);
  put8(d, 192); put8(d, 168); put8(d, 0); put8(d, std::uint8_t(seed));
  put8(d, 0); put8(d, 17);
  put16be(d, std::uint16_t(40000 + (seed & 0xFF)));
  return d;
}

Bytes plain_udp_packet(std::uint16_t seed) {
  Bytes d;
  put16be(d, std::uint16_t(1000 + (seed & 0xFF)));
  put16be(d, 2000);
  put16be(d, 8 + 32);
  put16be(d, 0);
  for (int i = 0; i < 32; ++i) put8(d, std::uint8_t(seed + std::uint16_t(i)));
  return eth_ipv4(std::uint16_t(0x7000 + (seed & 0xFFF)), 0, false, std::uint8_t(seed), d);
}

// `n_datagrams` fragmented SOME/IP-SD datagrams, each split into 3 fragments, INTERLEAVED across a
// window so several reassemblies are open at once -- the shape that actually stresses the buffer
// pool. `filler_per` plain packets are mixed in between.
Capture build_defrag_capture(std::size_t n_datagrams, std::size_t interleave,
                             std::size_t filler_per) {
  Capture c = new_capture();
  const std::size_t seams[3] = {16, 24, 24};

  std::vector<std::vector<Bytes>> pending;  // fragments not yet emitted, per open datagram
  std::uint32_t ts = 0;
  std::size_t next = 0;

  auto make = [&](std::uint16_t seed) {
    const Bytes dg = someip_sd_datagram(seed);
    std::vector<Bytes> frags;
    std::size_t off = 0;
    for (std::size_t i = 0; i < 3; ++i) {
      Bytes part(dg.begin() + std::ptrdiff_t(off), dg.begin() + std::ptrdiff_t(off + seams[i]));
      frags.push_back(eth_ipv4(std::uint16_t(0x1000 + seed), std::uint16_t(off / 8), i + 1 < 3,
                               std::uint8_t(seed), part));
      off += seams[i];
    }
    return frags;
  };

  while (next < n_datagrams || !pending.empty()) {
    while (pending.size() < interleave && next < n_datagrams)
      pending.push_back(make(std::uint16_t(next++)));
    // emit one fragment from each open datagram, round robin
    for (std::size_t i = 0; i < pending.size();) {
      add_record(c, pending[i].front(), ++ts);
      pending[i].erase(pending[i].begin());
      if (pending[i].empty()) pending.erase(pending.begin() + std::ptrdiff_t(i));
      else ++i;
    }
    for (std::size_t f = 0; f < filler_per; ++f) {
      const Bytes filler = plain_udp_packet(std::uint16_t(ts));
      add_record(c, filler, ++ts);
    }
  }
  return c;
}

Capture build_plain_capture(std::size_t n_packets) {
  Capture c = new_capture();
  for (std::size_t i = 0; i < n_packets; ++i)
    add_record(c, plain_udp_packet(std::uint16_t(i)), std::uint32_t(i + 1));
  return c;
}

// ---- checksum over the decoded tables, so both modes are proven to agree ------------------------

std::uint64_t table_checksum(nanom_shark::AllTables& t) {
  std::uint64_t h = 1469598103934665603ull;
  auto mix = [&](std::uint64_t v) { h = (h ^ v) * 1099511628211ull; };
  std::size_t rows = 0;
  t.get<"datagram">().soa().for_each_chunk([&](const auto& chunk) {
    rows += chunk.rows;
    auto status = chunk.template as<std::uint8_t>(6);
    auto total = chunk.template as<std::uint32_t>(2);
    for (std::size_t i = 0; i < chunk.rows; ++i) mix(std::uint64_t(status[i]) << 32 | total[i]);
  });
  mix(rows);
  std::size_t sd = 0;
  t.get<"someip_sd_entry">().soa().for_each_chunk([&](const auto& chunk) { sd += chunk.rows; });
  mix(sd);
  std::size_t pkts = 0;
  t.get<"packets">().soa().for_each_chunk([&](const auto& chunk) { pkts += chunk.rows; });
  mix(pkts);
  return h;
}

nanom::bytes as_bytes(const Bytes& v) {
  return nanom::bytes(reinterpret_cast<const std::byte*>(v.data()), v.size());
}

nanom_shark::DecodeOptions make_opts() {
  nanom_shark::DecodeOptions opts{};
  opts.ipv4_defrag.timeout_ticks = 64;
  return opts;
}

// ---- the two modes ------------------------------------------------------------------------------

std::uint64_t whole_file_pass(const Capture& c, std::size_t& resident_bytes) {
  nanom_shark::AllTables tables;
  nanom_shark::SinkHub sink{};
  const auto opts = make_opts();
  std::string error;
  nanom_shark::run_decode_pass(as_bytes(c.file), tables, sink, opts, error);
  resident_bytes = c.file.size();  // the whole capture, by construction
  return table_checksum(tables);
}

// A fixed pool of recycled slots. Returns -1 from acquire() when every slot is pinned; the caller
// grows the pool and reports it, since that is the memory bound we are measuring.
class Pool {
 public:
  Pool(std::size_t slots, std::size_t slot_bytes) : slots_(slots), busy_(slots, false) {
    for (auto& s : slots_) s.resize(slot_bytes);
    slot_bytes_ = slot_bytes;
  }
  int acquire() {
    for (std::size_t i = 0; i < slots_.size(); ++i) {
      if (!busy_[i]) {
        busy_[i] = true;
        std::size_t n = 0;
        for (bool b : busy_) n += b ? 1 : 0;
        if (n > high_) high_ = n;
        return int(i);
      }
    }
    return -1;
  }
  void release(int slot) { busy_[std::size_t(slot)] = false; }
  nanom::bytes fill(int slot, const std::uint8_t* p, std::size_t n) {
    auto& v = slots_[std::size_t(slot)];
    std::memcpy(v.data(), p, n);
    return nanom::bytes(v.data(), n);
  }
  std::size_t high_water() const { return high_; }
  std::size_t bytes() const { return slots_.size() * slot_bytes_; }

 private:
  std::vector<std::vector<std::byte>> slots_;
  std::vector<bool> busy_;
  std::size_t slot_bytes_ = 0;
  std::size_t high_ = 0;
};

// `copy_into_pool` false feeds the blocks straight out of the capture instead of copying them into
// a pool slot: same session, same per-block work, without the memcpy a real streaming caller would
// pay anyway (it reads into that buffer rather than copying from a file). Reported separately so
// the session's own overhead is not confused with the cost of moving bytes.
std::uint64_t streaming_pass(const Capture& c, std::size_t pool_slots, std::size_t& resident_bytes,
                             std::size_t& slots_high_water, std::size_t& max_pinned,
                             bool copy_into_pool = true) {
  nanom_shark::AllTables tables;
  nanom_shark::SinkHub sink{};
  const auto opts = make_opts();
  nanom_shark::StreamingDecodeSession<nanom_shark::default_decoder> session(tables, sink, opts);

  std::vector<std::byte> idb(reinterpret_cast<const std::byte*>(c.file.data()),
                             reinterpret_cast<const std::byte*>(c.file.data()) + 28);
  session.feed_idb(nanom::bytes(idb.data(), idb.size()), true, 24);

  Pool pool(pool_slots, c.max_record);
  std::vector<int> token_slot(pool_slots + 1, -1);
  max_pinned = 0;

  for (const auto& rec : c.records) {
    const int slot = pool.acquire();
    if (slot < 0) {
      std::fprintf(stderr, "pool of %zu slots exhausted -- the memory bound claim failed\n",
                   pool_slots);
      std::exit(1);
    }
    const nanom::bytes view =
        copy_into_pool ? pool.fill(slot, c.file.data() + rec.off, rec.len)
                       : nanom::bytes(reinterpret_cast<const std::byte*>(c.file.data() + rec.off),
                                      rec.len);
    const auto token = nanom_shark::defrag::Token(slot + 1);
    token_slot[std::size_t(token)] = slot;
    const auto fr = session.feed_epb(view, true, token, nmpcap::Kind::PcapRecord, rec.off);
    for (const auto t : fr.released) {
      pool.release(token_slot[std::size_t(t)]);
      token_slot[std::size_t(t)] = -1;
    }
    if (session.pinned_buffers() > max_pinned) max_pinned = session.pinned_buffers();
  }
  resident_bytes = pool.bytes();
  slots_high_water = pool.high_water();
  return table_checksum(tables);
}

// ---- timing --------------------------------------------------------------------------------------

template <class F>
double best_ns(int iters, F&& f) {
  double best = 1e300;
  for (int i = 0; i < iters; ++i) {
    const auto t0 = std::chrono::steady_clock::now();
    f();
    const auto t1 = std::chrono::steady_clock::now();
    const double ns = std::chrono::duration<double, std::nano>(t1 - t0).count();
    if (ns < best) best = ns;
  }
  return best;
}

void report(const char* label, const Capture& c, std::size_t pool_slots, int iters) {
  std::size_t whole_resident = 0, stream_resident = 0, high = 0, pinned = 0;
  const std::uint64_t sum_whole = whole_file_pass(c, whole_resident);
  const std::uint64_t sum_stream = streaming_pass(c, pool_slots, stream_resident, high, pinned);

  const double whole_ns = best_ns(iters, [&] {
    std::size_t r = 0;
    volatile std::uint64_t s = whole_file_pass(c, r);
    (void)s;
  });
  const double stream_ns = best_ns(iters, [&] {
    std::size_t r = 0, h = 0, p = 0;
    volatile std::uint64_t s = streaming_pass(c, pool_slots, r, h, p, /*copy_into_pool=*/true);
    (void)s;
  });
  const double stream_nocopy_ns = best_ns(iters, [&] {
    std::size_t r = 0, h = 0, p = 0;
    volatile std::uint64_t s = streaming_pass(c, pool_slots, r, h, p, /*copy_into_pool=*/false);
    (void)s;
  });

  const double n = double(c.records.size());
  std::printf("%-22s packets=%-6zu file=%-9zu\n", label, c.records.size(), c.file.size());
  std::printf("    whole-file   %7.1f ns/pkt   caller-resident %8zu bytes (the whole file)\n",
              whole_ns / n, whole_resident);
  std::printf("    streaming    %7.1f ns/pkt   caller-resident %8zu bytes (%zu slots x %zu, peak "
              "%zu in use, peak %zu pinned)\n",
              stream_ns / n, stream_resident, pool_slots, c.max_record, high, pinned);
  std::printf("    streaming*   %7.1f ns/pkt   (* same session, blocks not copied into the pool: "
              "session overhead alone)\n",
              stream_nocopy_ns / n);
  std::printf("    delta        %+6.1f%% (%+.1f%% excl. the pool copy)   memory bound %.1fx smaller"
              "   checksums %s\n",
              100.0 * (stream_ns - whole_ns) / whole_ns,
              100.0 * (stream_nocopy_ns - whole_ns) / whole_ns,
              double(whole_resident) / double(stream_resident ? stream_resident : 1),
              sum_whole == sum_stream ? "MATCH" : "*** DIFFER ***");
  if (sum_whole != sum_stream) std::exit(1);
}

}  // namespace

int main(int argc, char** argv) {
  const int iters = argc > 1 ? std::atoi(argv[1]) : 20;
  const std::size_t scale = argc > 2 ? std::size_t(std::atoi(argv[2])) : 1;

  // (B) the hot path most captures are: no fragmentation at all, so nothing is ever pinned and a
  // ONE-slot pool suffices.
  const Capture plain = build_plain_capture(20000 * scale);
  report("no fragmentation", plain, /*pool_slots=*/4, iters);

  // (A) the defrag-heavy workload: 8 datagrams' fragments interleaved at any moment, so several
  // buffers are pinned continuously while the file grows without bound.
  const Capture frag = build_defrag_capture(4000 * scale, /*interleave=*/8, /*filler_per=*/4);
  report("interleaved defrag", frag, /*pool_slots=*/32, iters);

  // Same workload at 4x the size: the file grows, the caller's buffer pool does not.
  const Capture frag_big = build_defrag_capture(16000 * scale, /*interleave=*/8, /*filler_per=*/4);
  report("interleaved defrag 4x", frag_big, /*pool_slots=*/32, iters);
  return 0;
}
