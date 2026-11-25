// SPDX-License-Identifier: Apache-2.0
// nanom — NANOM_DESCRIBE: the C++23 struct-registration macro (preprocessor provider).
//
// This is one of nanom's two `describe<T>` providers. The seam is nanom.hpp's
// `describe<T>::fields()` -> std::tuple<detail::fld<Name, MemPtr>...>; this file synthesizes that
// tuple with the preprocessor, nanom26.hpp synthesizes the identical tuple with C++26 P2996
// reflection. The core library consumes only the seam and cannot tell the providers apart.
//
// Under C++26 reflection (NANOM_HAS_REFLECTION, see nanom.hpp), NANOM_DESCRIBE degrades to a
// static_assert that reflection covers the type — every legacy registration line becomes a proof,
// not a no-op. Define NANOM_DESCRIBE_FORCE_MACRO to restore the explicit specialization even under
// reflection (an explicit specialization always beats nanom26's constrained partial
// specialization, so this is also the per-type override for fields that reflection must not pick
// up, e.g. registering a subset of members).
//
// This header is self-contained by design: it defines only macros, so it can be included before
// nanom.hpp (the expansions reference ::nanom:: symbols at the USE site, where nanom.hpp must have
// been included).

#ifndef NANOM_DESCRIBE_MACRO_HPP_INCLUDED
#define NANOM_DESCRIBE_MACRO_HPP_INCLUDED

#if defined(NANOM_HAS_REFLECTION) && NANOM_HAS_REFLECTION && !defined(NANOM_DESCRIBE_FORCE_MACRO)

/// Reflection provides describe<T>; the registration line remains as a compile-time proof that
/// the type is covered (catches a type that reflection rejects, e.g. one with a base class).
#define NANOM_DESCRIBE(T, ...)                                                       \
  static_assert(::nanom::Described<T>,                                               \
                "NANOM_DESCRIBE(" #T ", ...): C++26 reflection does not cover this " \
                "type (see nanom::Reflectable); define NANOM_DESCRIBE_FORCE_MACRO "  \
                "to register it explicitly")

#else

// --- preprocessor map machinery (bounded, 64 fields max) -------------------
// MSVC's traditional preprocessor passes a __VA_ARGS__ forwarded to another macro as one argument;
// forcing a rescan through NANOM_PP_EXPAND makes each forwarding expansion see the separate arguments.
#define NANOM_PP_EXPAND(x) x
#define NANOM_PP_NARG(...) NANOM_PP_EXPAND(NANOM_PP_NARG_(__VA_ARGS__, NANOM_PP_RSEQ()))
#define NANOM_PP_NARG_(...) NANOM_PP_EXPAND(NANOM_PP_ARG_N(__VA_ARGS__))
#define NANOM_PP_ARG_N(_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12,_13,_14,_15,_16,_17,_18,_19,_20,_21,_22,_23,_24,_25,_26,_27,_28,_29,_30,_31,_32,_33,_34,_35,_36,_37,_38,_39,_40,_41,_42,_43,_44,_45,_46,_47,_48,_49,_50,_51,_52,_53,_54,_55,_56,_57,_58,_59,_60,_61,_62,_63,_64,N,...) N
#define NANOM_PP_RSEQ() 64,63,62,61,60,59,58,57,56,55,54,53,52,51,50,49,48,47,46,45,44,43,42,41,40,39,38,37,36,35,34,33,32,31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1
#define NANOM_PP_CAT(a, b) NANOM_PP_CAT_(a, b)
#define NANOM_PP_CAT_(a, b) a##b
#define NANOM_FLD(T, m) ::nanom::detail::fld<#m, &T::m>{}
#define NANOM_PP_M1(M,T,a) M(T,a)
#define NANOM_PP_M2(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M1(M,T,__VA_ARGS__))
#define NANOM_PP_M3(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M2(M,T,__VA_ARGS__))
#define NANOM_PP_M4(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M3(M,T,__VA_ARGS__))
#define NANOM_PP_M5(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M4(M,T,__VA_ARGS__))
#define NANOM_PP_M6(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M5(M,T,__VA_ARGS__))
#define NANOM_PP_M7(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M6(M,T,__VA_ARGS__))
#define NANOM_PP_M8(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M7(M,T,__VA_ARGS__))
#define NANOM_PP_M9(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M8(M,T,__VA_ARGS__))
#define NANOM_PP_M10(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M9(M,T,__VA_ARGS__))
#define NANOM_PP_M11(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M10(M,T,__VA_ARGS__))
#define NANOM_PP_M12(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M11(M,T,__VA_ARGS__))
#define NANOM_PP_M13(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M12(M,T,__VA_ARGS__))
#define NANOM_PP_M14(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M13(M,T,__VA_ARGS__))
#define NANOM_PP_M15(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M14(M,T,__VA_ARGS__))
#define NANOM_PP_M16(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M15(M,T,__VA_ARGS__))
#define NANOM_PP_M17(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M16(M,T,__VA_ARGS__))
#define NANOM_PP_M18(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M17(M,T,__VA_ARGS__))
#define NANOM_PP_M19(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M18(M,T,__VA_ARGS__))
#define NANOM_PP_M20(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M19(M,T,__VA_ARGS__))
#define NANOM_PP_M21(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M20(M,T,__VA_ARGS__))
#define NANOM_PP_M22(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M21(M,T,__VA_ARGS__))
#define NANOM_PP_M23(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M22(M,T,__VA_ARGS__))
#define NANOM_PP_M24(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M23(M,T,__VA_ARGS__))
#define NANOM_PP_M25(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M24(M,T,__VA_ARGS__))
#define NANOM_PP_M26(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M25(M,T,__VA_ARGS__))
#define NANOM_PP_M27(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M26(M,T,__VA_ARGS__))
#define NANOM_PP_M28(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M27(M,T,__VA_ARGS__))
#define NANOM_PP_M29(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M28(M,T,__VA_ARGS__))
#define NANOM_PP_M30(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M29(M,T,__VA_ARGS__))
#define NANOM_PP_M31(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M30(M,T,__VA_ARGS__))
#define NANOM_PP_M32(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M31(M,T,__VA_ARGS__))
#define NANOM_PP_M33(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M32(M,T,__VA_ARGS__))
#define NANOM_PP_M34(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M33(M,T,__VA_ARGS__))
#define NANOM_PP_M35(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M34(M,T,__VA_ARGS__))
#define NANOM_PP_M36(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M35(M,T,__VA_ARGS__))
#define NANOM_PP_M37(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M36(M,T,__VA_ARGS__))
#define NANOM_PP_M38(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M37(M,T,__VA_ARGS__))
#define NANOM_PP_M39(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M38(M,T,__VA_ARGS__))
#define NANOM_PP_M40(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M39(M,T,__VA_ARGS__))
#define NANOM_PP_M41(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M40(M,T,__VA_ARGS__))
#define NANOM_PP_M42(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M41(M,T,__VA_ARGS__))
#define NANOM_PP_M43(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M42(M,T,__VA_ARGS__))
#define NANOM_PP_M44(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M43(M,T,__VA_ARGS__))
#define NANOM_PP_M45(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M44(M,T,__VA_ARGS__))
#define NANOM_PP_M46(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M45(M,T,__VA_ARGS__))
#define NANOM_PP_M47(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M46(M,T,__VA_ARGS__))
#define NANOM_PP_M48(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M47(M,T,__VA_ARGS__))
#define NANOM_PP_M49(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M48(M,T,__VA_ARGS__))
#define NANOM_PP_M50(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M49(M,T,__VA_ARGS__))
#define NANOM_PP_M51(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M50(M,T,__VA_ARGS__))
#define NANOM_PP_M52(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M51(M,T,__VA_ARGS__))
#define NANOM_PP_M53(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M52(M,T,__VA_ARGS__))
#define NANOM_PP_M54(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M53(M,T,__VA_ARGS__))
#define NANOM_PP_M55(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M54(M,T,__VA_ARGS__))
#define NANOM_PP_M56(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M55(M,T,__VA_ARGS__))
#define NANOM_PP_M57(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M56(M,T,__VA_ARGS__))
#define NANOM_PP_M58(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M57(M,T,__VA_ARGS__))
#define NANOM_PP_M59(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M58(M,T,__VA_ARGS__))
#define NANOM_PP_M60(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M59(M,T,__VA_ARGS__))
#define NANOM_PP_M61(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M60(M,T,__VA_ARGS__))
#define NANOM_PP_M62(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M61(M,T,__VA_ARGS__))
#define NANOM_PP_M63(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M62(M,T,__VA_ARGS__))
#define NANOM_PP_M64(M,T,a,...) M(T,a), NANOM_PP_EXPAND(NANOM_PP_M63(M,T,__VA_ARGS__))
#define NANOM_PP_MAP(M, T, ...) \
  NANOM_PP_EXPAND(NANOM_PP_CAT(NANOM_PP_M, NANOM_PP_NARG(__VA_ARGS__))(M, T, __VA_ARGS__))

/// NANOM_DESCRIBE(type, field1, field2, …) — register a struct with nanom.
/// Must appear at GLOBAL scope (it specializes nanom::describe). List fields
/// in wire order.
#define NANOM_DESCRIBE(T, ...)                                              \
  template <>                                                               \
  struct nanom::describe<T> {                                               \
    static constexpr const char* name() { return #T; }                      \
    static constexpr auto fields() {                                        \
      return std::make_tuple(NANOM_PP_MAP(NANOM_FLD, T, __VA_ARGS__));      \
    }                                                                       \
  }

#endif  // reflection / macro provider

#endif  // NANOM_DESCRIBE_MACRO_HPP_INCLUDED
