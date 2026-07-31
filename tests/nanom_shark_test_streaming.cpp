// SPDX-License-Identifier: Apache-2.0
//
// The buffer-reuse proof for StreamingDecodeSession (streaming.hpp).
//
// Reassembly is zero-copy: defrag.hpp's tables hold spans into whatever buffer each fragment's
// packet came from. A streaming caller that recycles a small pool of buffers is therefore exactly
// one bookkeeping mistake away from parsing freed memory, and "we call retire() at the right time"
// is a claim that has to be executed, not documented. So:
//
//   * an ORACLE run decodes the whole capture through run_decode_pass, with the entire file
//     resident and nothing ever overwritten -- the known-good output;
//   * a STREAMING run feeds the same blocks one at a time out of an 8-slot pool, and the instant
//     FeedResult reports a token released it POISONS that slot (memset 0xA5) and then FREES it,
//     so the next block's copy lands in recycled memory.
//
// Any premature release then shows up two ways: ASan reports a heap-use-after-free on the stale
// span -- configure a second build dir with -DNANOM_SANITIZER=address,undefined and run this test
// there), and -- even without a sanitizer -- the decoded output diverges from the oracle, because
// the bytes a stale span reads are now poison or somebody else's packet. The capture is built to
// make that divergence loud: SOME/IP-SD datagrams whose header and SD entries deliberately
// STRADDLE fragment seams, so a completed reassembly reads deep into three different buffers.
//
// The capture mixes, on purpose: plain non-fragment packets (token free the moment the walk
// returns), a datagram that completes immediately, one that stays in flight across many packets
// before completing, one delivered out of order, and one that never completes at all and is only
// released when evict_stale() ages it out.

#include <nanom_shark/decode_pass.hpp>
#include <nanom_shark/streaming.hpp>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

int failures = 0;
#define CHECK(cond)                                               \
  do {                                                            \
    if (!(cond)) {                                                \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
      ++failures;                                                 \
    }                                                             \
  } while (0)

using Bytes = std::vector<std::uint8_t>;

void put8(Bytes& b, std::uint8_t v) { b.push_back(v); }
void put16be(Bytes& b, std::uint16_t v) { put8(b, std::uint8_t(v >> 8)); put8(b, std::uint8_t(v)); }
void put32be(Bytes& b, std::uint32_t v) { put16be(b, std::uint16_t(v >> 16)); put16be(b, std::uint16_t(v)); }
void put16le(Bytes& b, std::uint16_t v) { put8(b, std::uint8_t(v)); put8(b, std::uint8_t(v >> 8)); }
void put32le(Bytes& b, std::uint32_t v) { put16le(b, std::uint16_t(v)); put16le(b, std::uint16_t(v >> 16)); }

// ---- capture construction: a classic little-endian pcap, link type 1 (Ethernet) ---------------

struct Capture {
  Bytes file;
  struct Rec { std::size_t off, len; };
  std::vector<Rec> records;  // one per pcap record: 16-byte record header + caplen bytes
};

Capture new_capture() {
  Capture c;
  put32le(c.file, 0xA1B2C3D4U);  // magic (us, little-endian)
  put16le(c.file, 2);
  put16le(c.file, 4);
  put32le(c.file, 0);       // thiszone
  put32le(c.file, 0);       // sigfigs
  put32le(c.file, 65535);   // snaplen
  put32le(c.file, 1);       // link_type = Ethernet
  return c;
}

std::uint32_t g_ts = 0;
void add_record(Capture& c, const Bytes& pkt) {
  const std::size_t off = c.file.size();
  put32le(c.file, ++g_ts);
  put32le(c.file, 0);
  put32le(c.file, std::uint32_t(pkt.size()));
  put32le(c.file, std::uint32_t(pkt.size()));
  c.file.insert(c.file.end(), pkt.begin(), pkt.end());
  c.records.push_back(Capture::Rec{off, 16 + pkt.size()});
}

// Ethernet + IPv4 header around `payload`. `frag_off_units` is the wire fragment offset in 8-byte
// units; `mf` sets the More Fragments flag. Checksums are zeroed (nothing verifies them).
Bytes eth_ipv4(std::uint16_t ident, std::uint16_t frag_off_units, bool mf, std::uint8_t last_octet,
               const Bytes& payload) {
  Bytes p;
  for (int i = 0; i < 6; ++i) put8(p, 0x02);  // dst mac
  for (int i = 0; i < 6; ++i) put8(p, 0x06);  // src mac
  put16be(p, 0x0800);                          // ethertype IPv4

  put8(p, 0x45);  // version 4, ihl 5
  put8(p, 0x00);  // dscp/ecn
  put16be(p, std::uint16_t(20 + payload.size()));
  put16be(p, ident);
  put16be(p, std::uint16_t((mf ? 0x2000u : 0u) | (frag_off_units & 0x1FFFu)));
  put8(p, 64);    // ttl
  put8(p, 17);    // protocol = UDP
  put16be(p, 0);  // checksum
  put8(p, 10); put8(p, 0); put8(p, 0); put8(p, 1);            // src
  put8(p, 10); put8(p, 0); put8(p, 0); put8(p, last_octet);   // dst
  p.insert(p.end(), payload.begin(), payload.end());
  return p;
}

// A 64-byte SOME/IP-SD datagram: UDP(8) + SOME/IP header(16) + SD payload(40). `seed` varies the
// decoded field values so different datagrams produce visibly different output.
Bytes someip_sd_datagram(std::uint8_t seed) {
  Bytes d;
  put16be(d, 30490);  // udp src
  put16be(d, 30490);  // udp dst -- the configured SOME/IP port
  put16be(d, 8 + 56); // udp length
  put16be(d, 0);      // udp checksum

  put16be(d, 0xFFFF);  // someip service_id  = SD
  put16be(d, 0x8100);  // someip method_id   = SD
  put32be(d, 8 + 40);  // someip length
  put16be(d, std::uint16_t(0x0100 + seed));  // client_id
  put16be(d, std::uint16_t(0x0200 + seed));  // session_id
  put8(d, 1);          // protocol_version
  put8(d, 1);          // interface_version
  put8(d, 0x02);       // message_type = notification
  put8(d, 0);          // return_code

  put8(d, 0xC0); put8(d, 0); put8(d, 0); put8(d, 0);  // SD flags + reserved
  put32be(d, 16);                                      // entries_length: exactly one entry
  put8(d, 0x01);                                       // entry type = OfferService
  put8(d, 0); put8(d, 0);                              // option index 1st/2nd
  put8(d, 0x10);                                       // num_opt_1 = 1, num_opt_2 = 0
  put16be(d, std::uint16_t(0x1000 + seed));            // service_id
  put16be(d, std::uint16_t(0x2000 + seed));            // instance_id
  put8(d, 1);                                          // major_version
  put8(d, 0); put8(d, 0); put8(d, 60);                 // ttl (24 bits)
  put32be(d, std::uint32_t(seed));                     // minor_version
  put32be(d, 12);                                      // options_length
  put16be(d, 9);                                       // option length
  put8(d, 0x04);                                       // option type = IPv4 endpoint
  put8(d, 0);                                          // reserved
  put8(d, 192); put8(d, 168); put8(d, 0); put8(d, seed);  // ipv4 address
  put8(d, 0);                                          // reserved
  put8(d, 17);                                         // l4 proto = UDP
  put16be(d, std::uint16_t(40000 + seed));             // port
  return d;
}

// A plain, non-fragment UDP packet: its buffer is free the instant the per-packet walk returns.
Bytes plain_udp_packet(std::uint8_t seed) {
  Bytes d;
  put16be(d, std::uint16_t(1000 + seed));
  put16be(d, 2000);
  put16be(d, 8 + 8);
  put16be(d, 0);
  for (int i = 0; i < 8; ++i) put8(d, std::uint8_t(seed + i));
  return eth_ipv4(/*ident=*/std::uint16_t(0x7000 + seed), 0, false, seed, d);
}

// Slice `datagram` into IPv4 fragments at 8-byte boundaries and hand each back as a full packet.
// The seams are chosen (16 / 24 / 24 over a 64-byte datagram) so the SOME/IP header (datagram
// bytes 8..24) and the first SD entry (32..48) both STRADDLE a fragment boundary: reading them
// after completion touches two different caller buffers, which is exactly what a premature
// release would corrupt.
std::vector<Bytes> fragment_packets(std::uint16_t ident, std::uint8_t last_octet,
                                    const Bytes& datagram, const std::vector<std::size_t>& sizes) {
  std::vector<Bytes> out;
  std::size_t off = 0;
  for (std::size_t i = 0; i < sizes.size(); ++i) {
    const std::size_t n = sizes[i];
    const bool mf = (i + 1 < sizes.size());
    Bytes part(datagram.begin() + std::ptrdiff_t(off), datagram.begin() + std::ptrdiff_t(off + n));
    out.push_back(eth_ipv4(ident, std::uint16_t(off / 8), mf, last_octet, part));
    off += n;
  }
  return out;
}

// The capture the whole test runs on, plus the packet-id positions the interesting things happen
// at, so the assertions below can be specific rather than "something completed somewhere".
Capture build_capture() {
  Capture c = new_capture();
  const std::vector<std::size_t> seams{16, 24, 24};

  // pid 0-1: plain traffic
  add_record(c, plain_udp_packet(1));
  add_record(c, plain_udp_packet(2));

  // pid 2-4: flow A -- three fragments back to back, completes right away
  for (const auto& p : fragment_packets(0x1111, 11, someip_sd_datagram(0x11), seams))
    add_record(c, p);

  // pid 5: flow B fragment 1 -- stays in flight for a long time (buffer pinned throughout)
  const auto flow_b = fragment_packets(0x2222, 22, someip_sd_datagram(0x22), seams);
  add_record(c, flow_b[0]);

  // pid 6-8: flow C delivered OUT OF ORDER (3rd, 1st, 2nd): completes on the last one
  const auto flow_c = fragment_packets(0x3333, 33, someip_sd_datagram(0x33), seams);
  add_record(c, flow_c[2]);
  add_record(c, flow_c[1]);
  add_record(c, flow_c[0]);

  // pid 9-13: filler, with flow B still open across all of it
  for (std::uint8_t i = 0; i < 5; ++i) add_record(c, plain_udp_packet(std::uint8_t(20 + i)));

  // pid 14-15: flow B finishes, 9 packets after it started
  add_record(c, flow_b[1]);
  add_record(c, flow_b[2]);

  // pid 16: flow D's first fragment -- the rest never arrives, so this buffer stays pinned until
  // evict_stale() ages the datagram out
  const auto flow_d = fragment_packets(0x4444, 44, someip_sd_datagram(0x44), seams);
  add_record(c, flow_d[0]);

  // pid 17-40: enough filler for flow D to time out mid-stream (not just at the end)
  for (std::uint8_t i = 0; i < 24; ++i) add_record(c, plain_udp_packet(std::uint8_t(60 + i)));

  return c;
}

std::vector<std::byte> to_byte_vector(const std::uint8_t* p, std::size_t n) {
  return std::vector<std::byte>(reinterpret_cast<const std::byte*>(p),
                                reinterpret_cast<const std::byte*>(p) + n);
}

nanom::bytes as_bytes(const Bytes& v) {
  return nanom::bytes(reinterpret_cast<const std::byte*>(v.data()), v.size());
}

std::string join_json(const std::vector<nanom_shark::PacketJson>& packets) {
  std::string s;
  for (const auto& p : packets) {
    s += p.to_json();
    s += '\n';
  }
  return s;
}

// ---- the recycling buffer pool -----------------------------------------------------------------

// Fixed number of slots, each an independently heap-allocated buffer. Releasing a slot poisons it
// and then FREES it, so a stale span gets both nets: ASan sees a use-after-free, and any read that
// slips through sees 0xA5 or an unrelated later packet instead of the bytes it expected.
class Pool {
 public:
  explicit Pool(std::size_t slots) : slots_(slots), busy_(slots, false) {}

  // -1 when every slot is pinned: that is a real failure of the bounded-memory claim, not a test
  // detail, so callers report it rather than growing the pool.
  int acquire() {
    for (std::size_t i = 0; i < slots_.size(); ++i) {
      if (!busy_[i]) {
        busy_[i] = true;
        live_ = std::max(live_, count_busy());
        return int(i);
      }
    }
    return -1;
  }

  void fill(int slot, const std::uint8_t* p, std::size_t n) {
    slots_[std::size_t(slot)].assign(reinterpret_cast<const std::byte*>(p),
                                     reinterpret_cast<const std::byte*>(p) + n);
  }

  nanom::bytes view(int slot) const {
    const auto& v = slots_[std::size_t(slot)];
    return nanom::bytes(v.data(), v.size());
  }

  void release(int slot) {
    auto& v = slots_[std::size_t(slot)];
    if (!v.empty()) std::memset(v.data(), 0xA5, v.size());  // poison before freeing
    v.clear();
    v.shrink_to_fit();  // actually give the memory back, so ASan can catch a stale read
    busy_[std::size_t(slot)] = false;
  }

  std::size_t high_water() const { return live_; }

 private:
  std::size_t count_busy() const {
    std::size_t n = 0;
    for (bool b : busy_) n += b ? 1 : 0;
    return n;
  }
  std::vector<std::vector<std::byte>> slots_;
  std::vector<bool> busy_;
  std::size_t live_ = 0;
};

// ---- the test ----------------------------------------------------------------------------------

nanom_shark::DecodeOptions make_opts() {
  nanom_shark::DecodeOptions opts{};
  // Long enough that flow B (9 packets in flight) completes, short enough that flow D ages out
  // mid-capture rather than only being drained at the end.
  opts.ipv4_defrag.timeout_ticks = 12;
  return opts;
}

void test_streaming_matches_whole_file_with_buffer_reuse() {
  const Capture cap = build_capture();
  const auto opts = make_opts();

  // ---- oracle: whole file resident, nothing ever overwritten ----
  nanom_shark::AllTables oracle_tables;
  std::vector<nanom_shark::PacketJson> oracle_json;
  nanom_shark::SinkHub oracle_sink{&oracle_json};
  std::string error;
  CHECK(nanom_shark::run_decode_pass(as_bytes(cap.file), oracle_tables, oracle_sink, opts, error));

  // ---- streaming: 8 recycled buffers, poisoned + freed the moment they are reported released ----
  nanom_shark::AllTables stream_tables;
  std::vector<nanom_shark::PacketJson> stream_json;
  nanom_shark::SinkHub stream_sink{&stream_json};
  nanom_shark::StreamingDecodeSession<nanom_shark::default_decoder> session(stream_tables,
                                                                           stream_sink, opts);

  // The interface's link type comes from the classic-pcap global header, which scan_blocks exposes
  // as a synthetic 24-byte IDB. Fed from its own copy; it holds no spans, only a link_type integer.
  {
    std::vector<std::byte> idb = to_byte_vector(cap.file.data(), 28);
    session.feed_idb(nanom::bytes(idb.data(), idb.size()), /*little_endian=*/true,
                     /*declared_length=*/24);
  }

  Pool pool(8);
  std::vector<int> token_slot(9, -1);  // token == slot + 1; index 0 unused (kNoToken)
  std::size_t max_pinned = 0;
  bool pool_exhausted = false;

  for (const auto& rec : cap.records) {
    const int slot = pool.acquire();
    if (slot < 0) {
      pool_exhausted = true;
      break;
    }
    pool.fill(slot, cap.file.data() + rec.off, rec.len);
    const nanom_shark::defrag::Token token = nanom_shark::defrag::Token(slot + 1);
    token_slot[std::size_t(token)] = slot;

    const auto fr = session.feed_epb(pool.view(slot), /*little_endian=*/true, token,
                                     nmpcap::Kind::PcapRecord, rec.off);
    CHECK(fr.ok);

    for (const auto t : fr.released) {
      CHECK(t != nanom_shark::defrag::kNoToken);
      const int s = token_slot[std::size_t(t)];
      CHECK(s >= 0);
      if (s >= 0) {
        pool.release(s);          // poison + free, RIGHT NOW -- the whole point of this test
        token_slot[std::size_t(t)] = -1;
      }
    }
    // The contract's other half: if it was not released, it must have been reported pinned.
    if (token_slot[std::size_t(token)] >= 0) CHECK(fr.pinned);
    else CHECK(!fr.pinned);

    max_pinned = std::max(max_pinned, session.pinned_buffers());
  }

  CHECK(!pool_exhausted);

  // ---- the actual assertion: recycling buffers changed nothing ----
  const std::string oracle_out = join_json(oracle_json);
  const std::string stream_out = join_json(stream_json);
  CHECK(oracle_json.size() == stream_json.size());
  CHECK(oracle_out == stream_out);
  if (oracle_out != stream_out) {
    // Point at the first divergence -- a stale read is usually a single mangled field.
    std::size_t i = 0;
    while (i < oracle_out.size() && i < stream_out.size() && oracle_out[i] == stream_out[i]) ++i;
    std::printf("  first divergence at byte %zu:\n    oracle: %.120s\n    stream: %.120s\n", i,
                oracle_out.c_str() + (i > 60 ? i - 60 : 0),
                stream_out.c_str() + (i > 60 ? i - 60 : 0));
  }

  // Sanity that the capture exercised what it claims to: SOME/IP-SD rows only exist if reassembled
  // datagrams were parsed across fragment seams, and they must match the oracle exactly.
  std::size_t oracle_entries = 0, stream_entries = 0;
  oracle_tables.get<"someip_sd_entry">().soa().for_each_chunk(
      [&](const auto& chunk) { oracle_entries += chunk.rows; });
  stream_tables.get<"someip_sd_entry">().soa().for_each_chunk(
      [&](const auto& chunk) { stream_entries += chunk.rows; });
  CHECK(oracle_entries == 3);  // flows A, B, C complete; flow D never does
  CHECK(oracle_entries == stream_entries);

  // And that buffers really were pinned across packets (otherwise the test proves nothing) while
  // staying bounded far below the capture's block count.
  CHECK(max_pinned >= 2);
  CHECK(pool.high_water() <= 8);
  std::printf(
      "streaming buffer-reuse: %zu blocks through an 8-slot pool; peak %zu slots in use, peak %zu "
      "pinned by open reassemblies; output byte-identical to the whole-file pass\n",
      cap.records.size(), pool.high_water(), max_pinned);
}

// A capture with no fragmentation at all must never pin anything: every token comes straight back
// on the same call. This is the cheap majority path (and the one the hot-path cost depends on).
void test_non_fragment_tokens_release_immediately() {
  Capture c = new_capture();
  for (std::uint8_t i = 0; i < 16; ++i) add_record(c, plain_udp_packet(i));

  nanom_shark::AllTables tables;
  nanom_shark::SinkHub sink{};
  const nanom_shark::DecodeOptions opts{};
  nanom_shark::StreamingDecodeSession<nanom_shark::default_decoder> session(tables, sink, opts);
  {
    std::vector<std::byte> idb = to_byte_vector(c.file.data(), 28);
    session.feed_idb(nanom::bytes(idb.data(), idb.size()), true, 24);
  }

  Pool pool(1);  // ONE slot: this only works if every token is released synchronously
  for (const auto& rec : c.records) {
    const int slot = pool.acquire();
    CHECK(slot == 0);
    if (slot < 0) return;
    pool.fill(slot, c.file.data() + rec.off, rec.len);
    const auto fr = session.feed_epb(pool.view(slot), true, /*token=*/1, nmpcap::Kind::PcapRecord,
                                     rec.off);
    CHECK(fr.ok);
    CHECK(!fr.pinned);
    CHECK(fr.released.size() == 1);
    if (fr.released.size() == 1) CHECK(fr.released[0] == 1);
    CHECK(session.pinned_buffers() == 0);
    pool.release(slot);
  }
  CHECK(session.packets_fed() == 16);
}

// A malformed block must not decode anything, must not advance the packet id, and must hand the
// caller's buffer straight back.
void test_malformed_block_releases_its_buffer() {
  nanom_shark::AllTables tables;
  nanom_shark::SinkHub sink{};
  const nanom_shark::DecodeOptions opts{};
  nanom_shark::StreamingDecodeSession<nanom_shark::default_decoder> session(tables, sink, opts);

  std::vector<std::byte> junk(4, std::byte{0xFF});  // too short to hold a record header
  const auto fr = session.feed_epb(nanom::bytes(junk.data(), junk.size()), true, /*token=*/7,
                                   nmpcap::Kind::PcapRecord);
  CHECK(!fr.ok);
  CHECK(!fr.pinned);
  CHECK(fr.released.size() == 1);
  if (fr.released.size() == 1) CHECK(fr.released[0] == 7);
  CHECK(session.packets_fed() == 0);
}

}  // namespace

int main() {
  test_streaming_matches_whole_file_with_buffer_reuse();
  test_non_fragment_tokens_release_immediately();
  test_malformed_block_releases_its_buffer();
  if (failures) {
    std::printf("%d failure(s)\n", failures);
    return 1;
  }
  std::printf("nanom_shark_streaming_tests: OK\n");
  return 0;
}
