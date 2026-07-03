// SPDX-License-Identifier: Apache-2.0
// nanom26 equivalence suite: proves the P2996 reflection provider synthesizes EXACTLY the
// describe<T> the NANOM_DESCRIBE macro would have — same tuple arity, same field names, same
// member pointers, same (qualified) type name — plus the eligibility fences and the
// explicit-specialization override semantics. Almost everything here is a static_assert: if this
// TU compiles, the equivalence holds; main() only spot-checks the runtime data path.
//
// Compiled only in reflection mode (CMake: NANOM_CXX26_REFLECTION); a C++23 build never sees it.

#include <nanom/nanom.hpp>

#if !NANOM_HAS_REFLECTION
#error "test_reflect26.cpp must be compiled with a P2996 reflection compiler (see NANOM_CXX26_REFLECTION)"
#endif

#include "../examples/nanotins_parity/nm_protocols.hpp"  // real wire structs incl. namespaced types

#include <cstdio>
#include <string_view>

namespace nm = nanom;
using std::string_view;

// ---- ground-truth field checks: reflection tuple vs the members as declared -------------------

// The same shapes test_nanom.cpp registers with the macro — here NOTHING registers them.
struct vlan_tag {
  nm::ubits<3> pcp;
  nm::ubits<1> dei;
  nm::ubits<12> vid;
  nm::be<std::uint16_t> tpid;
};
struct inner_pt {
  nm::be<std::uint16_t> x, y;
};
struct outer_msg {
  std::uint8_t tag;
  inner_pt pt;
  std::array<std::uint8_t, 4> raw;
  nm::le<std::uint32_t> crc;
};

template <class T, std::size_t I>
using fld_at = std::tuple_element_t<I, decltype(nm::describe<T>::fields())>;

template <class T, std::size_t I, nm::fixed_string Name, auto MemPtr>
constexpr bool field_is = fld_at<T, I>::name.sv() == Name.sv() && fld_at<T, I>::mem_ptr == MemPtr;

static_assert(std::tuple_size_v<decltype(nm::describe<vlan_tag>::fields())> == 4);
static_assert(field_is<vlan_tag, 0, "pcp", &vlan_tag::pcp>);
static_assert(field_is<vlan_tag, 1, "dei", &vlan_tag::dei>);
static_assert(field_is<vlan_tag, 2, "vid", &vlan_tag::vid>);
static_assert(field_is<vlan_tag, 3, "tpid", &vlan_tag::tpid>);

static_assert(std::tuple_size_v<decltype(nm::describe<outer_msg>::fields())> == 4);
static_assert(field_is<outer_msg, 0, "tag", &outer_msg::tag>);
static_assert(field_is<outer_msg, 1, "pt", &outer_msg::pt>);    // nested described struct
static_assert(field_is<outer_msg, 2, "raw", &outer_msg::raw>);  // fixed array member
static_assert(field_is<outer_msg, 3, "crc", &outer_msg::crc>);
static_assert(field_is<inner_pt, 0, "x", &inner_pt::x> && field_is<inner_pt, 1, "y", &inner_pt::y>);

// A real namespaced wire struct from the parity port (its NANOM_DESCRIBE line, under reflection,
// already static_asserts coverage; these assert the CONTENT matches the declaration).
static_assert(std::tuple_size_v<decltype(nm::describe<nmproto::Ipv4>::fields())> == 13);
static_assert(field_is<nmproto::Ipv4, 0, "version", &nmproto::Ipv4::version>);
static_assert(field_is<nmproto::Ipv4, 9, "protocol", &nmproto::Ipv4::protocol>);
static_assert(field_is<nmproto::Ipv4, 11, "src", &nmproto::Ipv4::src>);
static_assert(field_is<nmproto::Ipv4, 12, "dst", &nmproto::Ipv4::dst>);

// wire layout must be what the macro registration produced: same widths, same offsets.
static_assert(nm::wire_size_v<vlan_tag> == 4 && nm::wire_size_v<outer_msg> == 13);
static_assert(nm::wire_size_v<nmproto::Ipv4> == 20 && nm::wire_size_v<nmproto::Tcp> == 20);

// ---- describe<T>::name(): the macro stringizes the qualified spelling -------------------------
static_assert(string_view{nm::describe<vlan_tag>::name()} == "vlan_tag");
static_assert(string_view{nm::describe<nmproto::Ethernet>::name()} == "nmproto::Ethernet");
static_assert(string_view{nm::describe<nmproto::Ipv6Srh>::name()} == "nmproto::Ipv6Srh");

// ---- eligibility fences: library internals must NOT become Described --------------------------
static_assert(!nm::Described<std::array<std::uint8_t, 4>>);  // stays on the array column branch
static_assert(!nm::Described<nm::be<std::uint16_t>>);        // stays a wire scalar
static_assert(!nm::Described<nm::ubits<3>>);                 // stays a bit field
static_assert(!nm::Described<int> && !nm::Described<std::string_view>);
struct with_base : inner_pt { std::uint8_t z; };
static_assert(!nm::Described<with_base>);  // base classes are out (macro couldn't flatten them either)
struct empty_agg {};
static_assert(!nm::Described<empty_agg>);  // zero-field structs are not wire records

// ---- override semantics: an explicit specialization (what NANOM_DESCRIBE_FORCE_MACRO emits)
//      always beats the reflection partial specialization ---------------------------------------
struct subset_reg {
  std::uint8_t skip_me;
  nm::be<std::uint16_t> keep_me;
};
template <>
struct nanom::describe<subset_reg> {  // register only the second member, as the macro could
  static constexpr const char* name() { return "subset_reg"; }
  static constexpr auto fields() { return std::make_tuple(nm::detail::fld<"keep_me", &subset_reg::keep_me>{}); }
};
static_assert(std::tuple_size_v<decltype(nm::describe<subset_reg>::fields())> == 1);
static_assert(fld_at<subset_reg, 0>::name.sv() == "keep_me");

// ---- runtime spot-checks through the whole stack (parse -> view -> soa -> json) ---------------
int main() {
  int fails = 0;
  const auto check = [&](bool ok, const char* what) {
    if (!ok) {
      std::printf("FAIL: %s\n", what);
      ++fails;
    }
  };

  // strct<> parse of an auto-described struct (0x2A greeny bits: pcp=1, dei=0, vid=42; tpid=0x8100)
  const std::uint8_t wire[] = {0x20, 0x2A, 0x81, 0x00};
  auto r = nm::strct<vlan_tag>()(nm::from(wire, sizeof wire));
  check(bool(r), "strct<vlan_tag> parses");
  if (r) {
    check(r->value.pcp == 1 && r->value.vid == 42, "bit fields decode");
    check(std::uint16_t(r->value.tpid) == 0x8100, "be<> decodes");
  }

  // zero-copy overlay + compile-time name lookup on an auto-described struct
  auto v = nm::overlay<vlan_tag>()(nm::from(wire, sizeof wire));
  check(bool(v), "overlay<vlan_tag>");
  if (v) check(v->value.get<"vid">() == 42, "view::get<\"vid\">");

  // soa columns carry the reflected names
  nm::soa<vlan_tag> cols;
  if (r) cols.push(r->value);
  check(cols.columns().size() == 4 && cols.columns()[2].name == "vid", "soa column names");

  // json field names come from reflection too
  if (r) {
    const std::string j = nm::to_json(r->value);
    check(j.find("\"vid\":42") != std::string::npos, "to_json field name");
  }

  if (fails == 0) std::puts("test_reflect26: all static_asserts held; runtime spot-checks ok");
  return fails;
}
