// Generation-tracked memory-safety GAP suite — intentionally FAILING (WILL_FAIL).
//
// Documents attested_bytes / wire_arena hazards that remain after Stage 2 attestation.
// Built with NANOM_GENERATION=1 and NANOM_GENERATION_THROW=1.
//
//   cmake -B build && cmake --build build -j --target nanom_memory_safety_gap_generation_tests

#include <nanom/nanom.hpp>

#include <cstdio>
#include <cstdlib>
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

#define EXPECT_FAULT(expr)                                                 \
  do {                                                                     \
    bool _threw = false;                                                   \
    try {                                                                  \
      (void)(expr);                                                        \
    } catch (const nm::generation_exception&) {                            \
      _threw = true;                                                       \
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

// GAP: in-place mutation with unchanged generation — stale content, valid gen.
static void gap_mutation_same_generation() {
  std::vector<std::byte> wire = {std::byte{0x60}, std::byte{0x2a}, std::byte{0x08}, std::byte{0x00}};
  nm::wire_arena arena;
  auto r = nm::overlay<vlan_tag>()(nm::from(wire.data(), wire.size(), arena));
  CHECK(r);
  auto v = r->value;
  CHECK(v.get<"vid">() == 42);
  wire[1] = std::byte{0xff};

  bool faulted = false;
  try {
    (void)v.get<"vid">();
  } catch (const nm::generation_exception&) {
    faulted = true;
  }
  CHECK(faulted);
  CHECK(nm::in_place_wire_mutation_bumps_generation);
}

// GAP: attested_bytes::operator[] lacks explicit OOB fault (at() catches it).
static void gap_attested_bytes_subscript_oob() {
  std::vector<std::byte> wire = {std::byte{0xaa}, std::byte{0xbb}};
  nm::wire_arena arena;
  auto in = nm::from(wire.data(), wire.size(), arena);
  nm::bytes b = in.span();
  EXPECT_FAULT(b.at(99));  // control: at() faults
  CHECK(nm::attested_bytes_subscript_is_bounds_checked);
}

// GAP: unchecked_span() drops attestation; stale access via plain input is silent.
static void gap_unchecked_span_bypass() {
  std::vector<std::byte> wire = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}};
  nm::wire_arena arena;
  auto r = nm::take(4)(nm::from(wire.data(), wire.size(), arena));
  CHECK(r);
  nm::bytes b = r->value;
  arena.invalidate();
  nm::input plain = nm::from(b.unchecked_span());

  bool faulted = false;
  try {
    (void)plain[0];
  } catch (const nm::generation_exception&) {
    faulted = true;
  }
  CHECK(faulted);
  CHECK(!nm::unchecked_span_bypasses_generation);
}

// GAP: bytes::data() does not validate generation (only subscript/at do).
static void gap_bytes_data_skips_generation() {
  std::vector<std::byte> wire = {std::byte{0xca}, std::byte{0xfe}};
  nm::wire_arena arena;
  auto r = nm::take(2)(nm::from(wire.data(), wire.size(), arena));
  CHECK(r);
  nm::bytes b = r->value;
  arena.invalidate();

  bool faulted = false;
  try {
    (void)b.data();
  } catch (const nm::generation_exception&) {
    faulted = true;
  }
  CHECK(faulted);
  CHECK(!nm::bytes_data_skips_generation_check);
}

// GAP: as_str(bytes) forms string_view without generation check.
static void gap_as_str_skips_generation() {
  std::vector<std::byte> wire = {std::byte{'h'}, std::byte{'i'}};
  nm::wire_arena arena;
  auto r = nm::take(2)(nm::from(wire.data(), wire.size(), arena));
  CHECK(r);
  nm::bytes b = r->value;
  arena.invalidate();

  bool faulted = false;
  try {
    (void)nm::as_str(b);
  } catch (const nm::generation_exception&) {
    faulted = true;
  }
  CHECK(faulted);
}

int main() {
  std::printf("nanom generation GAP tests (NANOM_GENERATION=1, expected WILL_FAIL)\n");
  gap_mutation_same_generation();
  gap_attested_bytes_subscript_oob();
  gap_unchecked_span_bypass();
  gap_bytes_data_skips_generation();
  gap_as_str_skips_generation();
  if (failures) {
    std::printf("%d GAP FAILURE(S) — documented attested_bytes hazards\n", failures);
    return 1;
  }
  std::printf("all generation gap tests passed (hardening complete)\n");
  return 0;
}
