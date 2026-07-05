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
  test_handler_ignore();
  if (failures) {
    std::printf("%d FAILURE(S)\n", failures);
    return 1;
  }
  std::printf("all generation tests passed\n");
  return 0;
}
