// Tests for nanom/emit.hpp: writing fixed-layout described structs (the inverse of strct<T>()).
//
//   * byte round trip: for random wire bytes b, emit(strct<T>(b)) == b — every bit of every
//     layout below (be / le, plain scalars in both byte orders, msb0 and lsb0 bit fields, signed
//     bit fields, byte arrays, arrays of be<>, nested structs, floats) is written back exactly;
//   * the real-world layouts of nanom's examples (Ethernet, 802.1Q, IPv4, UDP, ELF64, FAT16);
//   * range errors (a value wider than its bit field, a computed length that does not fit),
//     reported with the field's name, and exact-size buffers (ASan);
//   * computed fields: IPv4 total_len + header checksum and UDP length against the textbook packet;
//   * constant evaluation: to_bytes() in a static_assert.
#include <nanom/emit.hpp>

#include <cstdio>
#include <random>
#include <vector>

namespace nm = nanom;
using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

static int failures = 0;
#define CHECK(cond)                                                        \
  do {                                                                     \
    if (!(cond)) {                                                         \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);          \
      ++failures;                                                          \
    }                                                                      \
  } while (0)

// ------------------------------------------------------------------ the examples' layouts
struct eth_hdr {
  std::array<u8, 6> dst, src;
  nm::be<u16>       eth_type;
};
NANOM_DESCRIBE(eth_hdr, dst, src, eth_type);
struct vlan_hdr {
  nm::ubits<3>  pcp;
  nm::ubits<1>  dei;
  nm::ubits<12> vid;
  nm::be<u16>   eth_type;
};
NANOM_DESCRIBE(vlan_hdr, pcp, dei, vid, eth_type);
struct ipv4_hdr {
  nm::ubits<4>      version;
  nm::ubits<4>      ihl;
  nm::ubits<6>      dscp;
  nm::ubits<2>      ecn;
  nm::be<u16>       total_len;
  nm::be<u16>       ident;
  nm::ubits<3>      flags;
  nm::ubits<13>     frag_off;
  u8                ttl;
  u8                proto;
  nm::be<u16>       checksum;
  std::array<u8, 4> src, dst;
};
NANOM_DESCRIBE(ipv4_hdr, version, ihl, dscp, ecn, total_len, ident, flags, frag_off, ttl, proto, checksum,
               src, dst);
struct udp_hdr {
  nm::be<u16> src_port, dst_port, length, checksum;
};
NANOM_DESCRIBE(udp_hdr, src_port, dst_port, length, checksum);
struct elf64_hdr {
  u16 type; u16 machine; u32 version;
  u64 entry; u64 phoff; u64 shoff;
  u32 flags;
  u16 ehsize; u16 phentsize; u16 phnum;
  u16 shentsize; u16 shnum; u16 shstrndx;
};
NANOM_DESCRIBE(elf64_hdr, type, machine, version, entry, phoff, shoff, flags, ehsize, phentsize, phnum,
               shentsize, shnum, shstrndx);
struct elf64_phdr {
  u32 type; u32 flags;
  u64 offset; u64 vaddr; u64 paddr;
  u64 filesz; u64 memsz; u64 align;
};
NANOM_DESCRIBE(elf64_phdr, type, flags, offset, vaddr, paddr, filesz, memsz, align);
struct fat16_bpb {
  std::array<u8, 3> jmp;
  std::array<u8, 8> oem;
  nm::le<u16> bytes_per_sector;
  u8          sectors_per_cluster;
  nm::le<u16> reserved_sectors;
  u8          num_fats;
  nm::le<u16> root_entries;
  nm::le<u16> total_sectors16;
  u8          media;
  nm::le<u16> fat_size16;
  nm::le<u16> sectors_per_track;
  nm::le<u16> num_heads;
  nm::le<u32> hidden_sectors;
  nm::le<u32> total_sectors32;
};
NANOM_DESCRIBE(fat16_bpb, jmp, oem, bytes_per_sector, sectors_per_cluster, reserved_sectors, num_fats,
               root_entries, total_sectors16, media, fat_size16, sectors_per_track, num_heads, hidden_sectors,
               total_sectors32);
struct fat_dirent {
  std::array<u8, 8> name;
  std::array<u8, 3> ext;
  nm::ubits<1, nm::bit_order::lsb0> read_only, hidden, system, volume_id, directory, archive;
  nm::ubits<2, nm::bit_order::lsb0> attr_rsvd;
  u8 nt_rsvd, ctime_tenths;
  nm::le<u16> ctime, cdate, adate, cluster_hi, mtime, mdate, cluster_lo;
  nm::le<u32> size;
};
NANOM_DESCRIBE(fat_dirent, name, ext, read_only, hidden, system, volume_id, directory, archive, attr_rsvd,
               nt_rsvd, ctime_tenths, ctime, cdate, adate, cluster_hi, mtime, mdate, cluster_lo, size);

// ------------------------------------------------------------------ every remaining field kind
struct mixed_bits {            // msb0 and lsb0 runs, signed fields, 64-bit fields, odd widths
  nm::ubits<5>                       a;   // msb0 run: 16 bits
  nm::ibits<7>                       b;
  nm::ubits<4>                       pad;
  nm::ubits<4, nm::bit_order::lsb0>  c;   // lsb0 run: 24 bits
  nm::ibits<3, nm::bit_order::lsb0>  d;
  nm::ubits<13, nm::bit_order::lsb0> e;
  nm::ubits<4, nm::bit_order::lsb0>  pad2;
  nm::ubits<64>                      f;
  nm::ibits<64, nm::bit_order::lsb0> g;
};
NANOM_DESCRIBE(mixed_bits, a, b, pad, c, d, e, pad2, f, g);

// msb0 and lsb0 fields sharing a byte have no single meaning: such layouts do not compile
struct shared_byte { nm::ubits<4> a; nm::ubits<4, nm::bit_order::lsb0> b; };
NANOM_DESCRIBE(shared_byte, a, b);
static_assert(!nm::detail::layout_ok<shared_byte>());
static_assert(nm::detail::layout_ok<mixed_bits>());
struct inner_t {
  nm::le<u32>   x;
  nm::be<float> y;
};
NANOM_DESCRIBE(inner_t, x, y);
struct scalars_t {             // plain scalars follow `dflt`; floats; arrays of wire ints; nesting
  std::int8_t                  i8;
  std::int16_t                 i16;
  u32                          u32v;
  std::int64_t                 i64;
  float                        f;
  double                       d;
  std::array<nm::be<u16>, 3>   be_arr;
  std::array<nm::le<u64>, 2>   le_arr;
  inner_t                      in;
  std::array<inner_t, 2>       ins;
  nm::be<double>               bd;
};
NANOM_DESCRIBE(scalars_t, i8, i16, u32v, i64, f, d, be_arr, le_arr, in, ins, bd);

// ------------------------------------------------------------------ computed fields
inline u16 ones_complement(std::span<const std::byte> b) {
  u32 sum = 0;
  for (std::size_t i = 0; i + 1 < b.size(); i += 2) sum += u32(u8(b[i])) << 8 | u8(b[i + 1]);
  if (b.size() % 2) sum += u32(u8(b.back())) << 8;
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return u16(~sum);
}
template <>
struct nm::computed<ipv4_hdr> {
  static constexpr auto fields = std::tuple{
      nm::calc<"ihl">([](const ipv4_hdr&, const nm::emit_ctx&) { return 5; }),  // no options
      nm::calc<"total_len">([](const ipv4_hdr&, const nm::emit_ctx& c) { return 20 + c.payload.size(); }),
      nm::checksum<"checksum">([](std::span<const std::byte> h, const nm::emit_ctx&) { return ones_complement(h); }),
  };
};
template <>
struct nm::computed<udp_hdr> {
  static constexpr auto fields = std::tuple{
      nm::calc<"length">([](const udp_hdr&, const nm::emit_ctx& c) { return 8 + c.payload.size(); }),
  };
};

// ------------------------------------------------------------------ properties
/// emit(strct(b)) == b for random b (in both default byte orders). `computed` types are excluded
/// (their computed fields legitimately differ from random bytes).
template <class T>
void byte_roundtrip(const char* name, std::mt19937_64& rng, int rounds) {
  int bad = 0;
  for (int t = 0; t < rounds; ++t) {
    for (auto order : {std::endian::little, std::endian::big}) {
      std::array<std::byte, nm::wire_size_v<T>> wire;
      for (auto& b : wire) b = std::byte(rng());
      auto v = nm::strct<T>(order)(nm::from(std::span<const std::byte>(wire)));
      if (!v) { ++bad; continue; }
      std::vector<std::byte> out(nm::wire_size_v<T>);  // exact size: ASan sees any overrun
      auto n = nm::emit(v->value, out, {}, order);
      if (!n || *n != wire.size() || !std::equal(out.begin(), out.end(), wire.begin())) ++bad;
      // and through a sink: identical bytes
      std::vector<std::byte> via;
      nm::vector_sink s{&via};
      if (!nm::emit_to(v->value, s, {}, order) || via != out) ++bad;
    }
  }
  if (bad) std::printf("%s: %d failed round trips\n", name, bad);
  CHECK(bad == 0);
}

static std::vector<std::byte> hex(const char* h) {
  std::vector<std::byte> out;
  for (const char* p = h; p[0] && p[1]; p += 2) {
    while (*p == ' ') ++p;
    const auto nib = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
    out.push_back(std::byte(nib(p[0]) << 4 | nib(p[1])));
  }
  return out;
}

static void test_computed() {
  // the classic example header: 4500 0073 0000 4000 4011 b861 c0a8 0001 c0a8 00c7
  const auto want = hex("450000730000400040110000c0a80001c0a800c7");
  ipv4_hdr h{};
  h.version.v = 4;
  h.flags.v = 2;  // don't fragment
  h.ttl = 64;
  h.proto = 17;
  h.src = {192, 168, 0, 1};
  h.dst = {192, 168, 0, 199};
  h.checksum = 0x1234;     // overwritten
  h.total_len = 9;         // overwritten
  std::vector<std::byte> payload(115 - 20, std::byte{0xab});
  auto b = nm::to_bytes(h, nm::emit_ctx{payload});
  CHECK(b.has_value());
  if (b) {
    auto expect = want;
    expect[10] = std::byte{0xb8};
    expect[11] = std::byte{0x61};
    CHECK(std::equal(b->begin(), b->end(), expect.begin()));
    CHECK(nm::verify_computed<ipv4_hdr>(*b, nm::emit_ctx{payload}));
    auto tampered = *b;
    tampered[8] = std::byte{63};  // TTL changed, checksum not updated
    CHECK(!nm::verify_computed<ipv4_hdr>(tampered, nm::emit_ctx{payload}));
    CHECK(!nm::verify_computed<ipv4_hdr>(*b, nm::emit_ctx{std::span(payload).first(10)}));  // wrong length
  }
  // a payload too long for be<u16> total_len: an error naming the field, nothing truncated
  std::vector<std::byte> huge(70000);
  auto e = nm::to_bytes(h, nm::emit_ctx{huge});
  CHECK(!e);
  if (!e) CHECK(e.error().message == "ipv4_hdr" && e.error().field == "total_len");

  // a UDP frame through a sink: header (length computed) + payload, payload passed through
  udp_hdr u{};
  u.src_port = 53;
  u.dst_port = 40000;
  const auto body = hex("deadbeef00");
  std::vector<std::byte> frame;
  nm::vector_sink s{&frame};
  auto n = nm::emit_frame(u, body, s);
  CHECK(n && *n == 13 && frame.size() == 13);
  CHECK(frame[4] == std::byte{0} && frame[5] == std::byte{13});
  CHECK(std::equal(body.begin(), body.end(), frame.begin() + 8));
  // a fixed sink too small for the frame
  std::array<std::byte, 10> small;
  nm::span_sink ss{small};
  CHECK(!nm::emit_frame(u, body, ss) && ss.used <= small.size());
}

static void test_errors() {
  vlan_hdr v{};
  v.vid.v = 5000;  // 13 bits into a 12-bit field
  auto r = nm::to_bytes(v);
  CHECK(!r);
  if (!r) CHECK(r.error().field == "vid");
  mixed_bits m{};
  m.b.v = 64;  // 7-bit signed: -64 .. 63
  CHECK(!nm::to_bytes(m));
  m.b.v = -64;
  CHECK(nm::to_bytes(m).has_value());
  m.d.v = -5;  // 3-bit signed: -4 .. 3
  auto r2 = nm::to_bytes(m);
  CHECK(!r2 && r2.error().field == "d");
  // an output buffer smaller than the struct
  udp_hdr u{};
  std::array<std::byte, 7> seven;
  CHECK(!nm::emit(u, seven));
}

// ------------------------------------------------------------------ compile time
constexpr bool compile_time_emit() {
  vlan_hdr v{};
  v.pcp.v = 5;
  v.dei.v = 1;
  v.vid.v = 0x123;
  v.eth_type = 0x0800;
  auto b = nm::to_bytes(v);
  // pcp(3) dei(1) vid(12) = 101 1 0001 0010 0011 = 0xb1 0x23, then 08 00
  return b && (*b)[0] == std::byte{0xb1} && (*b)[1] == std::byte{0x23} && (*b)[2] == std::byte{0x08} &&
         (*b)[3] == std::byte{0x00};
}
static_assert(compile_time_emit(), "to_bytes() is usable in constant expressions");

int main() {
  std::mt19937_64 rng(2026);
  byte_roundtrip<eth_hdr>("eth_hdr", rng, 500);
  byte_roundtrip<vlan_hdr>("vlan_hdr", rng, 500);
  byte_roundtrip<elf64_hdr>("elf64_hdr", rng, 500);
  byte_roundtrip<elf64_phdr>("elf64_phdr", rng, 500);
  byte_roundtrip<fat16_bpb>("fat16_bpb", rng, 500);
  byte_roundtrip<fat_dirent>("fat_dirent", rng, 500);
  byte_roundtrip<mixed_bits>("mixed_bits", rng, 2000);
  byte_roundtrip<scalars_t>("scalars_t", rng, 2000);
  test_computed();
  test_errors();
  if (failures) {
    std::printf("%d failure(s)\n", failures);
    return 1;
  }
  std::puts("emit tests: all passed");
  return 0;
}
