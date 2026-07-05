// Generation-tracking tests — NANOM_GENERATION=1 only (see CMakeLists.txt).
#include <nanom/nanom.hpp>

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

namespace nm = nanom;

static int failures = 0;
#define CHECK(cond)                                                        \
  do {                                                                     \
    if (!(cond)) {                                                         \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);          \
      ++failures;                                                          \
    }                                                                      \
  } while (0)

#define EXPECT_STALE(expr)                                                 \
  do {                                                                     \
    bool _threw = false;                                                   \
    try {                                                                  \
      (void)(expr);                                                        \
    } catch (const nm::generation_exception& _e) {                       \
      _threw = true;                                                       \
      CHECK(_e.fault().kind == nm::gen_fault_kind::stale_generation);    \
    }                                                                      \
    CHECK(_threw);                                                         \
  } while (0)

#define EXPECT_NO_THROW(expr)                                              \
  do {                                                                     \
    bool _ok = true;                                                       \
    try {                                                                  \
      (void)(expr);                                                        \
    } catch (...) {                                                        \
      _ok = false;                                                         \
    }                                                                      \
    CHECK(_ok);                                                            \
  } while (0)

struct vlan_tag {
  nm::ubits<3>     pcp;
  nm::ubits<1>     dei;
  nm::ubits<12>    vid;
  nm::be<uint16_t> ether;
};
NANOM_DESCRIBE(vlan_tag, pcp, dei, vid, ether);

struct mac_hdr {
  std::array<uint8_t, 6> dst;
  std::array<uint8_t, 6> src;
  nm::be<uint16_t>       ethertype;
};
NANOM_DESCRIBE(mac_hdr, dst, src, ethertype);

static void test_tracked_parse_ok() {
  const std::uint8_t raw[] = {0x60, 0x2a, 0x08, 0x00};
  nm::wire_arena arena;
  auto r = nm::overlay<vlan_tag>()(nm::from(raw, sizeof raw, arena));
  CHECK(r);
  CHECK(r->value.get<"vid">() == 42);
  CHECK(r->value.get<"ether">() == 0x0800);
}

static void test_stale_after_invalidate() {
  std::array<std::byte, 4> wire = {std::byte{0x60}, std::byte{0x2a}, std::byte{0x08},
                                   std::byte{0x00}};
  nm::wire_arena arena;
  nm::view<vlan_tag> v{};
  {
    auto r = nm::overlay<vlan_tag>()(nm::from(wire.data(), wire.size(), arena));
    CHECK(r);
    v = r->value;
    CHECK(v.get<"vid">() == 42);
  }
  arena.invalidate();
  EXPECT_STALE(v.get<"vid">());
}

static void test_use_after_free_owner() {
  nm::wire_arena arena;
  nm::view<vlan_tag> v{};
  {
    auto buf = std::make_unique<std::array<std::byte, 4>>();
    (*buf)[0] = std::byte{0x60};
    (*buf)[1] = std::byte{0x2a};
    (*buf)[2] = std::byte{0x08};
    (*buf)[3] = std::byte{0x00};
    auto r = nm::overlay<vlan_tag>()(nm::from(buf->data(), buf->size(), arena));
    CHECK(r);
    v = r->value;
    arena.invalidate();
  }
  EXPECT_STALE(v.get<"vid">());
}

static void test_nested_view_after_invalidate() {
  std::vector<std::byte> wire(14);
  for (std::size_t i = 0; i < wire.size(); ++i) wire[i] = std::byte(i);

  nm::wire_arena arena;
  nm::view<mac_hdr> v{};
  {
    auto r = nm::overlay<mac_hdr>()(nm::from(wire.data(), wire.size(), arena));
    CHECK(r);
    v = r->value;
    (void)v.get<"dst">()[0];
  }
  wire.clear();
  arena.invalidate();

  EXPECT_STALE(v.get<"ethertype">());
}

static void test_untracked_parse_unchanged() {
  const std::uint8_t raw[] = {0x60, 0x2a, 0x08, 0x00};
  auto r = nm::overlay<vlan_tag>()(nm::from(raw, sizeof raw));
  CHECK(r && r->value.get<"vid">() == 42);
}

static nm::gen_action ignore_stale(const nm::generation_fault& f) {
  (void)f;
  return nm::gen_action::ignore;
}

static void test_handler_ignore() {
  std::array<std::byte, 4> wire = {std::byte{0x60}, std::byte{0x2a}, std::byte{0x08},
                                   std::byte{0x00}};
  nm::wire_arena arena;
  auto r = nm::overlay<vlan_tag>()(nm::from(wire.data(), wire.size(), arena));
  CHECK(r);
  auto v = r->value;
  arena.invalidate();

  nm::generation_handler = ignore_stale;
  EXPECT_NO_THROW(v.get<"vid">());
  nm::generation_handler = nullptr;
}

// --- attested_bytes: parser outputs -------------------------------------------------

static void test_take_bytes_stale() {
  const std::uint8_t raw[] = {0xde, 0xad, 0xbe, 0xef};
  nm::wire_arena arena;
  nm::bytes payload{};
  {
    std::vector<std::byte> wire(sizeof raw);
    for (std::size_t i = 0; i < sizeof raw; ++i)
      wire[i] = std::byte(raw[i]);
    auto r = nm::take(4)(nm::from(wire.data(), wire.size(), arena));
    CHECK(r);
    payload = r->value;
    CHECK(payload[0] == 0xde);
    wire.clear();
    arena.invalidate();
  }
  EXPECT_STALE(payload[0]);
}

static void test_tag_bytes_stale() {
  const char pat[] = "GET";
  nm::wire_arena arena;
  nm::bytes matched{};
  {
    std::vector<std::byte> wire = {std::byte{'G'}, std::byte{'E'}, std::byte{'T'},
                                   std::byte{' '}};
    auto r = nm::tag(pat)(nm::from(wire.data(), wire.size(), arena));
    CHECK(r);
    matched = r->value;
    CHECK(matched[0] == std::uint8_t{'G'});
    wire.clear();
    arena.invalidate();
  }
  EXPECT_STALE(matched[1]);
}

static void test_recognize_bytes_stale() {
  nm::wire_arena arena;
  nm::bytes consumed{};
  {
    std::vector<std::byte> wire = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
    auto r = nm::recognize(nm::take(2))(nm::from(wire.data(), wire.size(), arena));
    CHECK(r);
    consumed = r->value;
    CHECK(consumed.size() == 2);
    wire.clear();
    arena.invalidate();
  }
  EXPECT_STALE(consumed[0]);
}

static void test_consumed_pair_bytes_stale() {
  nm::wire_arena arena;
  nm::bytes raw{};
  {
    std::vector<std::byte> wire = {std::byte{0xaa}, std::byte{0xbb}};
    auto r = nm::consumed(nm::be_u16)(nm::from(wire.data(), wire.size(), arena));
    CHECK(r);
    raw = r->value.first;
    CHECK(r->value.second == 0xaabb);
    wire.clear();
    arena.invalidate();
  }
  EXPECT_STALE(raw[0]);
}

static void test_rest_bytes_stale() {
  nm::wire_arena arena;
  nm::bytes tail{};
  {
    std::vector<std::byte> wire = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
    auto r = nm::rest(nm::from(wire.data(), wire.size(), arena));
    CHECK(r);
    tail = r->value;
    CHECK(tail.size() == 3);
    wire.clear();
    arena.invalidate();
  }
  EXPECT_STALE(tail[2]);
}

static void test_length_data_payload_stale() {
  nm::wire_arena arena;
  nm::bytes payload{};
  {
    std::vector<std::byte> wire = {std::byte{0x00}, std::byte{0x03}, std::byte{0xca},
                                   std::byte{0xfe}, std::byte{0xba}};
    auto r = nm::length_data(nm::be_u16)(nm::from(wire.data(), wire.size(), arena));
    CHECK(r);
    payload = r->value;
    CHECK(payload.size() == 3);
    CHECK(payload[0] == 0xca);
    wire.clear();
    arena.invalidate();
  }
  EXPECT_STALE(payload[1]);
}

static void test_view_raw_stale() {
  std::array<std::byte, 4> wire = {std::byte{0x60}, std::byte{0x2a}, std::byte{0x08},
                                   std::byte{0x00}};
  nm::wire_arena arena;
  nm::bytes raw{};
  {
    auto r = nm::overlay<vlan_tag>()(nm::from(wire.data(), wire.size(), arena));
    CHECK(r);
    raw = r->value.raw();
    CHECK(raw.size() == 4);
    arena.invalidate();
  }
  EXPECT_STALE(raw[0]);
}

static void test_byte_array_field_stale() {
  std::vector<std::byte> wire(14);
  for (std::size_t i = 0; i < wire.size(); ++i) wire[i] = std::byte(i);

  nm::wire_arena arena;
  nm::bytes dst{};
  {
    auto r = nm::overlay<mac_hdr>()(nm::from(wire.data(), wire.size(), arena));
    CHECK(r);
    dst = r->value.get<"dst">();
    CHECK(dst.size() == 6);
    CHECK(dst[0] == 0);
    wire.clear();
    arena.invalidate();
  }
  EXPECT_STALE(dst[0]);
}

static void test_untracked_bytes_no_throw() {
  const std::uint8_t raw[] = {0x01, 0x02, 0x03};
  auto r = nm::take(3)(nm::from(raw, sizeof raw));
  CHECK(r);
  auto b = r->value;
  EXPECT_NO_THROW(b[0]);
  EXPECT_NO_THROW(b.at(2));
}

static void test_attested_at_oob() {
  const std::uint8_t raw[] = {0x01, 0x02};
  nm::wire_arena arena;
  auto r = nm::take(2)(nm::from(raw, sizeof raw, arena));
  CHECK(r);
  auto b = r->value;
  bool threw = false;
  try {
    (void)b.at(2);
  } catch (const nm::generation_exception& e) {
    threw = true;
    CHECK(e.fault().kind == nm::gen_fault_kind::out_of_arena);
  }
  CHECK(threw);
}

static void test_many0_bytes_each_stale() {
  nm::wire_arena arena;
  std::vector<nm::bytes> chunks;
  {
    std::vector<std::byte> wire = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
    auto r = nm::many0(nm::take(1))(nm::from(wire.data(), wire.size(), arena));
    CHECK(r);
    CHECK(r->value.size() == 3);
    chunks = std::move(r->value);
    wire.clear();
    arena.invalidate();
  }
  EXPECT_STALE(chunks[1][0]);
}

int main() {
  std::printf("nanom generation tests (NANOM_GENERATION=1)\n");
  test_tracked_parse_ok();
  test_untracked_parse_unchanged();
  test_stale_after_invalidate();
  test_use_after_free_owner();
  test_nested_view_after_invalidate();
  test_handler_ignore();
  test_take_bytes_stale();
  test_tag_bytes_stale();
  test_recognize_bytes_stale();
  test_consumed_pair_bytes_stale();
  test_rest_bytes_stale();
  test_length_data_payload_stale();
  test_view_raw_stale();
  test_byte_array_field_stale();
  test_untracked_bytes_no_throw();
  test_attested_at_oob();
  test_many0_bytes_each_stale();
  if (failures) {
    std::printf("%d FAILURE(S)\n", failures);
    return 1;
  }
  std::printf("all generation tests passed\n");
  return 0;
}
