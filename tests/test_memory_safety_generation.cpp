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
    } catch (const nm::generation_exception& _e) {                         \
      _threw = true;                                                       \
      CHECK(_e.fault().kind == nm::gen_fault_kind::stale_generation);      \
    }                                                                      \
    CHECK(_threw);                                                         \
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
  bool threw = false;
  try {
    (void)v.get<"vid">();
  } catch (const nm::generation_exception& e) {
    threw = true;
    CHECK(e.fault().kind == nm::gen_fault_kind::stale_generation);
    const std::string msg = e.what();
    CHECK(msg.find("stale_generation") != std::string::npos);
    CHECK(msg.find("gen expected") != std::string::npos);
  }
  CHECK(threw);
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
    arena.invalidate();  // simulates owner release before view use
  }
  bool threw = false;
  try {
    (void)v.get<"vid">();
  } catch (const nm::generation_exception& e) {
    threw = true;
    CHECK(e.fault().kind == nm::gen_fault_kind::stale_generation);
  }
  CHECK(threw);
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

  bool threw = false;
  try {
    (void)v.get<"ethertype">();
  } catch (const nm::generation_exception& e) {
    threw = true;
    CHECK(e.fault().kind == nm::gen_fault_kind::stale_generation);
  }
  CHECK(threw);
}

static void test_take_bytes_stale() {
  nm::wire_arena arena;
  nm::bytes      payload{};
  {
    std::vector<std::byte> wire = {std::byte{0xde}, std::byte{0xad}, std::byte{0xbe}, std::byte{0xef}};
    auto r = nm::take(4)(nm::from(wire.data(), wire.size(), arena));
    CHECK(r);
    payload = r->value;
    CHECK(payload[0] == 0xde);
    arena.invalidate();
  }
  EXPECT_STALE(payload[1]);
}

static void test_recognize_consumed_rest_stale() {
  nm::wire_arena arena;
  nm::bytes      rec{};
  nm::bytes      con{};
  nm::bytes      tail{};
  {
    std::vector<std::byte> wire = {std::byte{'a'}, std::byte{'b'}, std::byte{'c'}, std::byte{'!'}};
    auto rr = nm::recognize(nm::tag("abc"))(nm::from(wire.data(), wire.size(), arena));
    CHECK(rr);
    rec = rr->value;
    auto rc = nm::consumed(nm::tag("abc"))(nm::from(wire.data(), wire.size(), arena));
    CHECK(rc);
    con = rc->value.first;
    auto rt = nm::rest(rr->rest);
    CHECK(rt);
    tail = rt->value;
    arena.invalidate();
  }
  EXPECT_STALE(rec[0]);
  EXPECT_STALE(con[1]);
  EXPECT_STALE(tail[0]);
}

static void test_length_data_stale() {
  nm::wire_arena arena;
  nm::bytes      payload{};
  {
    std::vector<std::byte> wire = {std::byte{0x00}, std::byte{0x03}, std::byte{0xca},
                                   std::byte{0xfe}, std::byte{0xba}};
    auto r = nm::length_data(nm::be_u16)(nm::from(wire.data(), wire.size(), arena));
    CHECK(r);
    payload = r->value;
    CHECK(payload.size() == 3);
    arena.invalidate();
  }
  EXPECT_STALE(payload[2]);
}

static void test_view_raw_and_byte_array_field_stale() {
  nm::wire_arena arena;
  nm::bytes      raw{};
  nm::bytes      dst{};
  {
    std::vector<std::byte> wire(14);
    for (std::size_t i = 0; i < wire.size(); ++i) wire[i] = std::byte(i);
    auto r = nm::overlay<mac_hdr>()(nm::from(wire.data(), wire.size(), arena));
    CHECK(r);
    raw = r->value.raw();
    dst = r->value.get<"dst">();
    CHECK(raw.size() == 14);
    CHECK(dst.size() == 6);
    arena.invalidate();
  }
  EXPECT_STALE(raw[0]);
  EXPECT_STALE(dst[0]);
}

static void test_subspan_stale() {
  nm::wire_arena arena;
  nm::bytes      slice{};
  {
    std::vector<std::byte> wire = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
    auto in = nm::from(wire.data(), wire.size(), arena);
    slice = in.span().subspan(1, 2);
    CHECK(slice.size() == 2);
    CHECK(slice[0] == 0x02);
    arena.invalidate();
  }
  EXPECT_STALE(slice[1]);
}

static void test_untracked_bytes_unchanged() {
  const std::uint8_t raw[] = {0x01, 0x02, 0x03};
  auto r = nm::take(3)(nm::from(raw, sizeof raw));
  CHECK(r);
  CHECK(r->value[0] == 1);
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
  bool ok = false;
  try {
    (void)v.get<"vid">();
    ok = true;
  } catch (...) {
    ok = false;
  }
  CHECK(ok);
  nm::generation_handler = nullptr;
}

int main() {
  std::printf("nanom generation tests (NANOM_GENERATION=1)\n");
  test_tracked_parse_ok();
  test_untracked_parse_unchanged();
  test_stale_after_invalidate();
  test_use_after_free_owner();
  test_nested_view_after_invalidate();
  test_take_bytes_stale();
  test_recognize_consumed_rest_stale();
  test_length_data_stale();
  test_view_raw_and_byte_array_field_stale();
  test_subspan_stale();
  test_untracked_bytes_unchanged();
  test_handler_ignore();
  if (failures) {
    std::printf("%d FAILURE(S)\n", failures);
    return 1;
  }
  std::printf("all generation tests passed\n");
  return 0;
}
