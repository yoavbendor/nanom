// SPDX-License-Identifier: Apache-2.0
// nanom26 — C++26 P2996 static-reflection provider for nanom's describe<T> seam.
//
// This is the macro-free nanom. The core library (nanom.hpp) consumes struct metadata through one
// seam: `describe<T>::fields()` -> std::tuple<detail::fld<Name, MemPtr>...> and
// `describe<T>::name()`. Under C++23 that tuple is synthesized by the NANOM_DESCRIBE preprocessor
// macro (describe_macro.hpp); here the SAME tuple is synthesized from the type itself with P2996
// reflection, so any eligible struct is usable with strct<>, overlay<>, soa<>, schema_of<>,
// to_json, csv, bulk_decode — with no registration line at all:
//
//   struct eth_hdr { std::array<std::uint8_t,6> dst, src; nanom::be<std::uint16_t> eth_type; };
//   // ...that's it. No NANOM_DESCRIBE. It is already Described.
//
// Eligibility (nanom::Reflectable): a named, non-union class type with no base classes and at
// least one non-static data member, where every member is public, named, and not a C++ bit-field
// (nanom's ubits<>/ibits<> wrappers are ordinary members and are fine) — and whose namespace
// chain does not root in `std` or `nanom`. The last rule keeps library internals (std::array,
// nanom::be<>, nanom::ubits<>) out of the Described concept so the core's if-constexpr dispatch
// (array columns, wire scalars) keeps its C++23 meaning.
//
// Escape hatches: an explicit NANOM_DESCRIBE_FORCE_MACRO specialization always beats this partial
// specialization (use it to register a member subset); -DNANOM_HAS_REFLECTION=0 disables this
// provider entirely.
//
// Fork-facing surface (kept deliberately tiny; the P2996 API still moves between fork snapshots):
// nonstatic_data_members_of, access_context::unchecked, identifier_of, has_identifier, parent_of,
// bases_of, is_class_type/is_union_type/is_namespace/is_bit_field/is_public, and the ^^ / [: :]
// operators. Everything else is plain C++.

#ifndef NANOM26_HPP_INCLUDED
#define NANOM26_HPP_INCLUDED

#include "reflect.hpp"  // the describe<T> seam (fixed_string, detail::fld, describe, Described).
                       // reflect.hpp includes THIS file at its end once the seam is defined, so the
                       // re-entry here is a guarded no-op — and we avoid dragging schema/soa back in.

#if defined(NANOM_HAS_REFLECTION) && NANOM_HAS_REFLECTION

#if __has_include(<meta>)
#include <meta>
#elif __has_include(<experimental/meta>)
#include <experimental/meta>
#else
#error "nanom26: reflection feature macro is set but no <meta> header found"
#endif

#include <string_view>
#include <tuple>
#include <utility>

namespace nanom {
namespace refl26 {

consteval std::meta::access_context ctx() { return std::meta::access_context::unchecked(); }

template <class T>
consteval std::size_t field_count() {
  return std::meta::nonstatic_data_members_of(^^T, ctx()).size();
}

/// The I-th non-static data member of T, as a per-index constexpr variable: the std::vector that
/// nonstatic_data_members_of returns is created, indexed, and discarded inside ONE constant
/// expression, so no non-transient constexpr allocation ever escapes.
template <class T, std::size_t I>
inline constexpr std::meta::info field_r = std::meta::nonstatic_data_members_of(^^T, ctx())[I];

/// True when the entity's namespace chain roots in `std` or `nanom` (climb to the declaration
/// directly under the global namespace; if it is one of those namespaces, exclude).
consteval bool rooted_in_library_namespace(std::meta::info r) {
  std::meta::info cur = r;
  std::meta::info up = std::meta::parent_of(cur);
  while (up != ^^::) {
    cur = up;
    up = std::meta::parent_of(cur);
  }
  if (!std::meta::is_namespace(cur) || !std::meta::has_identifier(cur)) return false;
  const std::string_view id = std::meta::identifier_of(cur);
  return id == "std" || id == "nanom";
}

/// The eligibility predicate behind nanom::Reflectable — see the header comment for the rules.
template <class T>
consteval bool reflectable() {
  const std::meta::info t = ^^T;
  if (!std::meta::is_class_type(t) || std::meta::is_union_type(t)) return false;
  if (!std::meta::has_identifier(t)) return false;  // lambdas, anonymous structs, specializations
  if (rooted_in_library_namespace(t)) return false;
  if (!std::meta::bases_of(t, ctx()).empty()) return false;
  const auto members = std::meta::nonstatic_data_members_of(t, ctx());
  if (members.empty()) return false;
  for (const std::meta::info m : members) {
    if (!std::meta::has_identifier(m)) return false;
    if (std::meta::is_bit_field(m)) return false;  // no member pointer exists for these
    if (!std::meta::is_public(m)) return false;
  }
  return true;
}

/// Build a fixed_string (the NTTP the fld<> descriptor and view<T>::get<"name">() use) from a
/// compile-time string_view — the reflection-side equivalent of the macro's #m stringization.
template <std::size_t N>
consteval fixed_string<N + 1> make_fixed(std::string_view s) {
  fixed_string<N + 1> out{};
  for (std::size_t i = 0; i < N; ++i) out.data[i] = s[i];
  return out;
}

template <class T, std::size_t I>
consteval auto field_name() {
  constexpr std::string_view sv = std::meta::identifier_of(field_r<T, I>);
  return make_fixed<sv.size()>(sv);
}

/// describe<T>::name() parity: NANOM_DESCRIBE stringizes the type as written at global scope —
/// i.e. WITH namespace qualification ("nmproto::Ethernet") — while identifier_of gives only
/// "Ethernet". Rebuild the qualified spelling by climbing parent_of and joining the named scopes
/// with "::" (unnamed namespaces are skipped, matching how such a type would be written). Stored
/// in a static so name() hands out a pointer with static storage duration, as the constexpr
/// schema_node initializer requires.
template <class T>
struct name_holder {
 private:
  static consteval std::size_t qualified_len() {
    std::size_t n = std::meta::identifier_of(^^T).size();
    for (auto p = std::meta::parent_of(^^T); p != ^^::; p = std::meta::parent_of(p)) {
      if (std::meta::has_identifier(p)) n += std::meta::identifier_of(p).size() + 2;
    }
    return n;
  }
  template <std::size_t N>
  static consteval fixed_string<N + 1> qualified_name() {
    fixed_string<N + 1> out{};
    std::size_t pos = N;  // fill right-to-left: we walk inner -> outer
    const auto put = [&](std::string_view s) {
      pos -= s.size();
      for (std::size_t i = 0; i < s.size(); ++i) out.data[pos + i] = s[i];
    };
    put(std::meta::identifier_of(^^T));
    for (auto p = std::meta::parent_of(^^T); p != ^^::; p = std::meta::parent_of(p)) {
      if (std::meta::has_identifier(p)) {
        put("::");
        put(std::meta::identifier_of(p));
      }
    }
    return out;
  }

 public:
  static constexpr auto value = qualified_name<qualified_len()>();
};

}  // namespace refl26

/// A type nanom's C++26 reflection provider auto-describes (no NANOM_DESCRIBE needed).
template <class T>
concept Reflectable = refl26::reflectable<std::remove_cv_t<T>>();

/// The whole point of nanom26: describe<T> for every Reflectable type, synthesizing the exact
/// tuple shape the macro produces — the ~19 field-iteration sites in the core are untouched and
/// cannot tell which provider ran. An explicit specialization (NANOM_DESCRIBE_FORCE_MACRO) still
/// wins over this partial specialization, giving per-type override semantics for free.
template <Reflectable T>
struct describe<T> {
  static constexpr const char* name() { return refl26::name_holder<T>::value.data; }
  static constexpr auto fields() {
    return []<std::size_t... I>(std::index_sequence<I...>) {
      return std::make_tuple(
          detail::fld<refl26::field_name<T, I>(), &[:refl26::field_r<T, I>:]>{}...);
    }(std::make_index_sequence<refl26::field_count<T>()>{});
  }
};

}  // namespace nanom

#endif  // NANOM_HAS_REFLECTION
#endif  // NANOM26_HPP_INCLUDED
