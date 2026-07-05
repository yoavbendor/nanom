// nanom memory-safety regression suite — intentionally FAILING tests.
//
// Each test documents a memory/lifetime hazard in the zero-copy parse path and
// asserts the *desired* defensive behavior nanom does not yet provide. These
// tests are written to avoid executing undefined behavior themselves (no
// deliberate OOB reads or use-after-free in the test process); they fail via
// CHECK so you can review gaps safely before adding fencing or guards.
//
// Optional red-team demos that *do* exercise UB live in test_memory_safety_ub.cpp
// and only build when NANOM_MEMORY_SAFETY_UB_DEMOS=ON (run under ASan).
//
//   cmake -B build && cmake --build build -j --target nanom_memory_safety_tests
//   ./build/nanom_memory_safety_tests
//
// Registered in ctest with WILL_FAIL until the library grows the expected guards.

#include <nanom/nanom.hpp>
#include <nanom/bulk.hpp>  // pkt_ref (opt-in header)

#include <cstdio>
#include <cstdlib>
#include <cstring>
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

// ---------------------------------------------------------------- structs
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

// =============================================================================
// 1. NULL POINTER INPUT — from(nullptr, n>0) builds a non-empty cursor over a
//    null base; combinators that pass the size check would dereference null.
// =============================================================================
namespace null_pointer_input {

void run() {
  nm::input in = nm::from(nullptr, 8);
  CHECK(in.empty());
  CHECK(in.first == nullptr);

  nm::input empty{};
  CHECK(empty.first == nullptr && empty.size() == 0);
  CHECK(!empty.safe_at(0).has_value());
}

}  // namespace null_pointer_input

// =============================================================================
// 2. UNCHECKED CURSOR ARITHMETIC — advance()/take_span() rely on preconditions
//    (n <= size()) but expose no checked variants; misuse wraps size() or OOBs.
// =============================================================================
namespace cursor_overrun {

void run() {
  const char wire[] = "ab";
  nm::input in = nm::from(wire, 2);

  CHECK(!in.checked_advance(99).has_value());
  CHECK(in.checked_advance(1).has_value());
  CHECK(in.checked_advance(1)->size() == 1);

  nm::input past = in.advance(99);
  CHECK(past.first != in.first);  // unchecked advance still exists
}

}  // namespace cursor_overrun

// =============================================================================
// 3. UNCHECKED INDEXING — input::operator[] has no bounds check on the hot path.
// =============================================================================
namespace unchecked_index {

void run() {
  const char wire[] = "abc";
  nm::input in = nm::from(wire, 3);

  CHECK(in.safe_at(0).has_value());
  CHECK(in.safe_at(0).value() == 'a');
  CHECK(!in.safe_at(99).has_value());
}

}  // namespace unchecked_index

// =============================================================================
// 4. DANGLING TAG PATTERN — tag() stores std::string_view; ephemeral patterns
//    can dangle before the parser runs.
// =============================================================================
namespace dangling_tag_pattern {

static auto make_ephemeral_tag_parser() {
  std::string pattern = "MAGIC";
  return nm::tag(pattern);
}

void run() {
  const char wire[] = "MAGICtail";
  auto parser = make_ephemeral_tag_parser();
  auto r = parser(nm::from(wire, 9));
  CHECK(r && nm::as_str(r->value) == "MAGIC");
}

}  // namespace dangling_tag_pattern

// =============================================================================
// 5. BYTES SPAN OUTLIVES OWNER — take()/tag() return spans into caller memory.
// =============================================================================
namespace dangling_bytes_span {

void run() {
  std::string buf = "hello world";
  auto r = nm::take(5)(nm::from(buf));
  CHECK(r);

  buf += " extra bytes force reallocation";
  // Do not dereference r->value after reallocation — that is the hazard we document.
  const bool span_carries_generation_token = false;
  CHECK(span_carries_generation_token);
}

}  // namespace dangling_bytes_span

// =============================================================================
// 6. VIEW USE-AFTER-FREE — overlay() yields view<T>{const std::byte* p} with no
//    owner generation; freeing the buffer leaves a silent dangling view.
// =============================================================================
namespace view_use_after_free {

void run() {
  auto buf = std::make_unique<std::array<std::byte, 4>>();
  (*buf)[0] = std::byte{0x60};
  (*buf)[1] = std::byte{0x2a};
  (*buf)[2] = std::byte{0x08};
  (*buf)[3] = std::byte{0x00};

  nm::view<vlan_tag> v{};
  {
    auto r = nm::overlay<vlan_tag>()(nm::from(buf->data(), buf->size()));
    CHECK(r);
    v = r->value;
  }
  buf.reset();

  const bool view_tracks_owner_lifetime = false;
  CHECK(view_tracks_owner_lifetime);
  (void)v;
}

}  // namespace view_use_after_free

// =============================================================================
// 7. SINGLE VIEW ALIASING — mutating wire bytes behind a lazy view is invisible.
// =============================================================================
namespace single_view_aliasing {

void run() {
  std::array<std::byte, 4> wire = {std::byte{0x60}, std::byte{0x2a},
                                   std::byte{0x08}, std::byte{0x00}};
  auto r = nm::overlay<vlan_tag>()(nm::from(wire.data(), wire.size()));
  CHECK(r);
  nm::view<vlan_tag> v = r->value;

  CHECK(v.get<"vid">() == 42);
  wire[1] = std::byte{0xff};

  const bool view_is_const_wire_snapshot = false;
  CHECK(view_is_const_wire_snapshot);
  CHECK(v.get<"vid">() == 42);  // stale read: mutation not surfaced
}

}  // namespace single_view_aliasing

// =============================================================================
// 8. NESTED VIEW BYTE ARRAY SPAN — get<"dst">() returns span into wire memory.
// =============================================================================
namespace nested_view_span_lifetime {

void run() {
  std::vector<std::byte> wire(14);
  for (std::size_t i = 0; i < wire.size(); ++i) wire[i] = std::byte(i);

  std::span<const std::byte> mac_span{};
  {
    auto r = nm::overlay<mac_hdr>()(nm::from(wire.data(), wire.size()));
    CHECK(r);
    auto dst = r->value.get<"dst">();
    mac_span = std::span<const std::byte>(
        reinterpret_cast<const std::byte*>(dst.data()), dst.size());
  }

  wire.clear();
  wire.shrink_to_fit();

  // mac_span may dangle after wire is cleared; do not dereference it here.
  const bool field_spans_are_generation_checked = false;
  CHECK(field_spans_are_generation_checked);
  (void)mac_span;
}

}  // namespace nested_view_span_lifetime

// =============================================================================
// 9. DEFAULT-CONSTRUCTED VIEW — view<T>{} leaves p == nullptr; get() would read.
// =============================================================================
namespace null_view_decode {

void run() {
  nm::view<vlan_tag> v{};
  CHECK(v.p == nullptr);
  CHECK(!v.valid());
#if NANOM_GUARD_VIEWS
  CHECK(NANOM_GUARD_VIEWS);
#endif
}

}  // namespace null_view_decode

// =============================================================================
// 10. LENGTH_PREFIX + SPAN PROVENANCE — length_data bounds-checks take(), but
//     returned bytes are plain spans with no tie to the originating input.
// =============================================================================
namespace length_prefix_overrun {

void run() {
  const std::uint8_t wire[] = {0x00, 0x00, 0x00, 0x02, 0xaa};
  auto r = nm::length_data(nm::be_u32)(nm::from(wire, sizeof wire));
  CHECK(!r);

  const std::uint8_t ok[] = {0x00, 0x00, 0x00, 0x02, 0xaa, 0xbb};
  auto ok_r = nm::length_data(nm::be_u32)(nm::from(ok, sizeof ok));
  CHECK(ok_r);

  const bool payload_is_attested_subspan = false;
  CHECK(payload_is_attested_subspan);
}

}  // namespace length_prefix_overrun

// =============================================================================
// 11. ERROR RENDER WINDOW — error::render indexes whole.base[offset] without
//     validating offset against (last - base).
// =============================================================================
namespace error_render_overrun {

void run() {
  const char wire[] = "abc";
  nm::input whole = nm::from(wire, 3);
  nm::error e{};
  e.kind = nm::errk::err;
  e.offset = 1'000'000;
  e.expected = "tag";

  std::string msg = e.render(whole);
  CHECK(msg.find("offset beyond input") != std::string::npos);
  CHECK(msg.find("end of input") != std::string::npos);  // clamped to total == 3
}

}  // namespace error_render_overrun

// =============================================================================
// 12. MANY0 ZERO-CONSUMPTION — many0 errors, but no global iteration budget for
//     custom loops that forget the guard (hang class of bugs).
// =============================================================================
namespace zero_consumption_hang_guard {

void run() {
  const bool has_checked_many = false;
  CHECK(has_checked_many);

  const bool documents_zero_consume_hazard = false;
  CHECK(documents_zero_consume_hazard);
}

}  // namespace zero_consumption_hang_guard

// =============================================================================
// 13. STREAMING INCOMPLETE + HUGE NEEDED — incomplete.needed can be enormous;
//     callers allocating from it without saturation risk OOM.
// =============================================================================
namespace incomplete_needed_saturation {

void run() {
  const std::uint8_t wire[] = {0xff, 0xff, 0xff, 0xff};
  auto r = nm::take(1'000'000)(nm::streaming(nm::from(wire, sizeof wire)));
  CHECK(!r && r.error().kind == nm::errk::incomplete);
  CHECK(r.error().needed <= nm::max_incomplete_needed);
}

}  // namespace incomplete_needed_saturation

// =============================================================================
// 14. BULK pkt_ref — null data + nonzero len is representable; bulk_decode would
//     memcpy from nullptr without validation.
// =============================================================================
namespace bulk_null_pkt_ref {

void run() {
  nm::pkt_ref bad{};
  bad.data = nullptr;
  bad.len = 64;
  bad.link = 1;
  CHECK(!nm::pkt_ref_valid(bad));

  nm::pkt_ref empty{};
  CHECK(nm::pkt_ref_valid(empty));

  const std::uint8_t b = 0xaa;
  nm::pkt_ref ok{};
  ok.data = reinterpret_cast<const std::byte*>(&b);
  ok.len = 1;
  CHECK(nm::pkt_ref_valid(ok));
}

}  // namespace bulk_null_pkt_ref

// ------------------------------------------------------------------ driver
int main() {
  std::printf("nanom memory-safety tests (expected to FAIL until guards land)\n");
  std::printf("============================================================\n");

  null_pointer_input::run();
  cursor_overrun::run();
  unchecked_index::run();
  dangling_tag_pattern::run();
  dangling_bytes_span::run();
  view_use_after_free::run();
  single_view_aliasing::run();
  nested_view_span_lifetime::run();
  null_view_decode::run();
  length_prefix_overrun::run();
  error_render_overrun::run();
  zero_consumption_hang_guard::run();
  incomplete_needed_saturation::run();
  bulk_null_pkt_ref::run();

  if (failures) {
    std::printf("============================================================\n");
    std::printf("%d FAILURE(S) — these document missing memory-safety guards\n", failures);
    return 1;
  }
  std::printf("all memory-safety tests passed (unexpected — guards may already exist)\n");
  return 0;
}
