// SPDX-License-Identifier: Apache-2.0
//
// Strict safety-profile test (NANOM_STRICT=1). Proves the compile-time
// restrictions that let the strict profile run without the runtime safety
// machinery, and proves the safe routes still parse correctly.
//
// Built by CMake with -DNANOM_STRICT=1. The detection idioms below are
// static_asserts, so the *compile-time* contract is checked at build time; the
// runtime section then confirms the lean profile still parses.

#include <nanom/nanom.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <vector>

namespace nm = nanom;

static int failures = 0;
#define CHECK(cond)                                                 \
  do {                                                              \
    if (!(cond)) {                                                  \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
      ++failures;                                                   \
    }                                                               \
  } while (0)

// ---------------------------------------------------------------------------
// Compile-time contract: strict flips the runtime nets OFF (speed) …
// ---------------------------------------------------------------------------
static_assert(NANOM_STRICT == 1, "this TU must be built with -DNANOM_STRICT=1");
static_assert(NANOM_GENERATION == 0,
              "strict profile turns runtime generation tracking OFF (compile-time guards replace it)");
static_assert(NANOM_GUARD_VIEWS == 0,
              "strict profile turns runtime view guards OFF");

// ---------------------------------------------------------------------------
// … and the compile-time restrictions that pay for it.
// ---------------------------------------------------------------------------

// Raw (pointer, length) entry is removed: provenance must be a sized view.
template <class... A>
concept can_from = requires(A... a) { nm::from(a...); };

static_assert(!can_from<const void*, std::size_t>,
              "strict removes from(const void*, size_t): use a sized span/array/string_view");

// A temporary std::string (converts to string_view) would dangle — deleted.
template <class T>
concept can_from_temporary = requires { nm::from(T{}); };
static_assert(!can_from_temporary<std::string>,
              "strict deletes from(std::string&&): parsing an owning temporary dangles");

// Safe routes remain available.
static_assert(can_from<std::array<std::uint8_t, 4>&>, "from(array) must stay available");
static_assert(can_from<std::span<const std::byte>>, "from(span) must stay available");
static_assert(can_from<std::string&>, "from(named string) must stay available");

// bytes is the plain span in the strict/lean profile (no attestation wrapper).
static_assert(std::is_same_v<nm::bytes, std::span<const std::byte>>,
              "strict/lean profile: bytes is std::span (no attested_bytes overhead)");

// ---------------------------------------------------------------------------
// Runtime: the lean profile still parses correctly through the safe routes.
// ---------------------------------------------------------------------------
struct eth_hdr {
  std::array<std::uint8_t, 6> dst, src;
  nm::be<std::uint16_t>       ethertype;
};
NANOM_DESCRIBE(eth_hdr, dst, src, ethertype);

static void test_strct_and_overlay() {
  const std::array<std::uint8_t, 14> frame = {
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x08, 0x00};

  nm::input in = nm::from(frame);
  auto r = nm::strct<eth_hdr>()(in);
  CHECK(r);
  CHECK(std::uint16_t(r->value.ethertype) == 0x0800);
  CHECK(r->value.dst[0] == 0x01 && r->value.src[0] == 0x0a);

  auto v = nm::overlay<eth_hdr>()(in);
  CHECK(v);
  CHECK(v->value.get<"ethertype">() == 0x0800);
  CHECK(v->value.get<"dst">()[5] == 0x06);
}

static void test_span_and_take() {
  std::vector<std::byte> buf(8);
  for (std::size_t i = 0; i < buf.size(); ++i) buf[i] = std::byte(i + 1);
  auto sp = std::span<const std::byte>(buf.data(), buf.size());

  auto r = nm::take(4)(nm::from(sp));
  CHECK(r);
  CHECK(r->value.size() == 4);
  CHECK(std::uint8_t(r->value[0]) == 1);
  CHECK(r->rest.size() == 4);
}

static void test_streaming_incomplete() {
  const std::uint8_t wire[] = {0xaa, 0xbb};
  auto sp = std::span<const std::byte>(reinterpret_cast<const std::byte*>(wire), sizeof wire);
  auto r = nm::take(8)(nm::streaming(nm::from(sp)));
  CHECK(!r);
  CHECK(r.error().kind == nm::errk::incomplete);
}

static void test_named_string_ok() {
  std::string s = "GET /x HTTP/1.1";
  auto r = nm::tag("GET")(nm::from(s));
  CHECK(r);
}

int main() {
  std::printf("nanom strict-profile tests (STRICT=%d GENERATION=%d GUARD_VIEWS=%d)\n",
              NANOM_STRICT, NANOM_GENERATION, NANOM_GUARD_VIEWS);
  test_strct_and_overlay();
  test_span_and_take();
  test_streaming_incomplete();
  test_named_string_ok();
  if (failures) {
    std::printf("FAILED: %d strict-profile checks\n", failures);
    return 1;
  }
  std::puts("all strict-profile checks passed");
  return 0;
}
