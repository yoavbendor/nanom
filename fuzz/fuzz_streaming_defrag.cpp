// SPDX-License-Identifier: Apache-2.0

// Differential fuzz harness for StreamingDecodeSession's buffer-release contract
// (nanom_shark/streaming.hpp), the continuous counterpart to the deterministic
// tests/nanom_shark_test_streaming.cpp.
//
// The fuzzer input is turned into a sequence of IPv4 fragments (arbitrary identifications, offsets,
// More-Fragments flags, lengths -- so out-of-order, overlapping, conflicting, gapped, oversized and
// never-completing datagrams all occur), packed into a well-formed classic pcap. That ONE capture
// is then decoded two ways:
//
//   A. run_decode_pass over the contiguous file -- every byte stays resident and untouched;
//   B. StreamingDecodeSession fed one record at a time out of separately heap-allocated buffers,
//      each POISONED (memset 0xA5) and FREED the moment FeedResult reports its token released.
//
// The two decodes must produce byte-identical output. If the release contract is ever wrong, either
// ASan reports a heap-use-after-free on the stale fragment span, or -- if the freed memory happens
// to survive -- the output diverges from A and this harness traps. Both nets, every input.
//
// libFuzzer build (Clang): -DNANOM_BUILD_FUZZERS, then
//   ./fuzz_streaming_defrag -max_total_time=60 corpus/
// Standalone build (no libFuzzer runtime needed; this is what ctest runs):
//   -DNANOM_FUZZ_STANDALONE, then ./nm_streaming_defrag_fuzz [iterations] [seed]

#include <nanom_shark/decode_pass.hpp>
#include <nanom_shark/streaming.hpp>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

[[noreturn]] void die(const char* what) {
  std::fprintf(stderr, "fuzz_streaming_defrag divergence: %s\n", what);
  __builtin_trap();
}

using Bytes = std::vector<std::uint8_t>;

void put8(Bytes& b, std::uint8_t v) { b.push_back(v); }
void put16be(Bytes& b, std::uint16_t v) { put8(b, std::uint8_t(v >> 8)); put8(b, std::uint8_t(v)); }
void put16le(Bytes& b, std::uint16_t v) { put8(b, std::uint8_t(v)); put8(b, std::uint8_t(v >> 8)); }
void put32le(Bytes& b, std::uint32_t v) {
  put16le(b, std::uint16_t(v));
  put16le(b, std::uint16_t(v >> 16));
}

struct Capture {
  Bytes file;
  struct Rec { std::size_t off, len; };
  std::vector<Rec> records;
};

// Ethernet + IPv4 (UDP protocol) around `payload`.
Bytes eth_ipv4(std::uint16_t ident, std::uint16_t frag_off_units, bool mf, std::uint8_t dst_last,
               const std::uint8_t* payload, std::size_t n) {
  Bytes p;
  for (int i = 0; i < 6; ++i) put8(p, 0x02);
  for (int i = 0; i < 6; ++i) put8(p, 0x06);
  put16be(p, 0x0800);
  put8(p, 0x45);
  put8(p, 0x00);
  put16be(p, std::uint16_t(20 + n));
  put16be(p, ident);
  put16be(p, std::uint16_t((mf ? 0x2000u : 0u) | (frag_off_units & 0x1FFFu)));
  put8(p, 64);
  put8(p, 17);  // UDP, so a completed datagram re-enters L4 dispatch (and SOME/IP on port 30490)
  put16be(p, 0);
  put8(p, 10); put8(p, 0); put8(p, 0); put8(p, 1);
  put8(p, 10); put8(p, 0); put8(p, 0); put8(p, dst_last);
  p.insert(p.end(), payload, payload + n);
  return p;
}

void add_record(Capture& c, const Bytes& pkt, std::uint32_t ts) {
  const std::size_t off = c.file.size();
  put32le(c.file, ts);
  put32le(c.file, 0);
  put32le(c.file, std::uint32_t(pkt.size()));
  put32le(c.file, std::uint32_t(pkt.size()));
  c.file.insert(c.file.end(), pkt.begin(), pkt.end());
  c.records.push_back(Capture::Rec{off, 16 + pkt.size()});
}

struct Cursor {
  const std::uint8_t* p;
  const std::uint8_t* end;
  std::uint8_t u8() { return p < end ? *p++ : 0; }
};

// Input layout, one fragment record per iteration: [ctrl][offset_units][len], then `len` payload
// bytes. `ctrl` picks one of 4 identifications (so datagrams collide and interleave), the MF flag,
// and occasionally a plain non-fragment packet.
Capture build_capture(const std::uint8_t* data, std::size_t size) {
  Capture c;
  put32le(c.file, 0xA1B2C3D4U);
  put16le(c.file, 2);
  put16le(c.file, 4);
  put32le(c.file, 0);
  put32le(c.file, 0);
  put32le(c.file, 65535);
  put32le(c.file, 1);  // Ethernet

  static constexpr std::uint16_t kIdents[4] = {0x1111, 0x2222, 0x3333, 0x4444};
  Cursor cur{data, data + size};
  std::uint32_t ts = 0;
  while (cur.p + 3 <= cur.end && c.records.size() < 96) {
    const std::uint8_t ctrl = cur.u8();
    const std::uint8_t off_units = cur.u8();
    const std::size_t want = cur.u8() % 96u;
    const std::size_t avail = std::size_t(cur.end - cur.p);
    const std::size_t take = want < avail ? want : avail;

    Bytes pkt;
    if ((ctrl & 0x30) == 0x30) {
      // a plain, non-fragment packet: its buffer must come straight back
      pkt = eth_ipv4(std::uint16_t(0x7000 + ctrl), 0, false, ctrl, cur.p, take);
    } else {
      pkt = eth_ipv4(kIdents[ctrl & 0x3], std::uint16_t(off_units & 0x3F), (ctrl & 0x40) != 0,
                     std::uint8_t(ctrl & 0x3), cur.p, take);
    }
    cur.p += take;
    add_record(c, pkt, ++ts);
  }
  return c;
}

std::string join_json(const std::vector<nanom_shark::PacketJson>& packets) {
  std::string s;
  for (const auto& p : packets) {
    s += p.to_json();
    s += '\n';
  }
  return s;
}

// Each fed record gets its own heap buffer, freed (after poisoning) the instant its token is
// reported released. Unlike the fixed pool in tests/nanom_shark_test_streaming.cpp this grows on
// demand: a fuzzer-chosen input can leave arbitrarily many datagrams in flight, and the property
// under test here is the release contract's SOUNDNESS, not its boundedness.
class Buffers {
 public:
  nanom::bytes hold(std::uint64_t token, const std::uint8_t* p, std::size_t n) {
    auto& v = live_[token];
    v.assign(reinterpret_cast<const std::byte*>(p), reinterpret_cast<const std::byte*>(p) + n);
    return nanom::bytes(v.data(), v.size());
  }
  void release(std::uint64_t token) {
    auto it = live_.find(token);
    if (it == live_.end()) die("token released twice (or never handed out)");
    if (!it->second.empty()) std::memset(it->second.data(), 0xA5, it->second.size());
    live_.erase(it);  // actually free it, so a stale span is a use-after-free
  }
  bool holds(std::uint64_t token) const { return live_.find(token) != live_.end(); }
  std::size_t live() const { return live_.size(); }

 private:
  std::unordered_map<std::uint64_t, std::vector<std::byte>> live_;
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size < 8) return 0;
  const Capture cap = build_capture(data, size);
  if (cap.records.empty()) return 0;

  nanom_shark::DecodeOptions opts{};
  // Small caps so the capacity / oversize / timeout release paths are hit often rather than rarely.
  opts.ipv4_defrag.max_concurrent = 6;
  opts.ipv4_defrag.max_datagram_bytes = 2048;
  opts.ipv4_defrag.timeout_ticks = 5;

  const nanom::bytes file(reinterpret_cast<const std::byte*>(cap.file.data()), cap.file.size());

  // ---- A: whole-file path, nothing ever freed or overwritten ----
  nanom_shark::AllTables tables_a;
  std::vector<nanom_shark::PacketJson> json_a;
  nanom_shark::SinkHub sink_a{&json_a};
  std::string error;
  if (!nanom_shark::run_decode_pass(file, tables_a, sink_a, opts, error)) return 0;

  // ---- B: streaming, every buffer poisoned + freed the moment it is reported released ----
  nanom_shark::AllTables tables_b;
  std::vector<nanom_shark::PacketJson> json_b;
  nanom_shark::SinkHub sink_b{&json_b};
  nanom_shark::StreamingDecodeSession<nanom_shark::default_decoder> session(tables_b, sink_b, opts);

  {
    std::vector<std::byte> idb(reinterpret_cast<const std::byte*>(cap.file.data()),
                               reinterpret_cast<const std::byte*>(cap.file.data()) + 28);
    session.feed_idb(nanom::bytes(idb.data(), idb.size()), /*little_endian=*/true,
                     /*declared_length=*/24);
  }

  Buffers bufs;
  std::uint64_t next_token = 1;
  for (const auto& rec : cap.records) {
    const std::uint64_t token = next_token++;
    const nanom::bytes view = bufs.hold(token, cap.file.data() + rec.off, rec.len);
    const auto fr = session.feed_epb(view, /*little_endian=*/true, token,
                                     nmpcap::Kind::PcapRecord, rec.off);
    if (!fr.ok) die("streaming rejected a block the whole-file scan accepted");
    for (const auto t : fr.released) bufs.release(t);
    // The contract, checked both ways round on every single call.
    if (fr.pinned != bufs.holds(token)) die("pinned flag disagrees with what is still held");
    if (session.pinned_buffers() > bufs.live()) die("session pins more buffers than exist");
  }

  if (join_json(json_a) != join_json(json_b)) die("streaming output differs from whole-file output");
  if (json_a.size() != json_b.size()) die("packet count differs");
  return 0;
}

#ifdef NANOM_FUZZ_STANDALONE
// No libFuzzer runtime needed: a deterministic PRNG driver so this harness runs as an ordinary
// ctest alongside self_fuzz, and can be pointed at more iterations by hand.
namespace {
struct Rng {
  std::uint64_t s;
  std::uint64_t next() {
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return s;
  }
};
}  // namespace

int main(int argc, char** argv) {
  const int iters = argc > 1 ? std::atoi(argv[1]) : 3000;
  Rng rng{argc > 2 ? std::strtoull(argv[2], nullptr, 10) : 0x9E3779B97F4A7C15ull};
  std::vector<std::uint8_t> buf;
  for (int i = 0; i < iters; ++i) {
    const std::size_t n = 8 + std::size_t(rng.next() % 1024);
    buf.resize(n);
    for (std::size_t j = 0; j < n; ++j) buf[j] = std::uint8_t(rng.next() >> 24);
    LLVMFuzzerTestOneInput(buf.data(), buf.size());
  }
  std::printf("nm_streaming_defrag_fuzz: %d iterations OK\n", iters);
  return 0;
}
#endif
