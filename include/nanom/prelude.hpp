// SPDX-License-Identifier: Apache-2.0
// nanom/prelude.hpp — shared configuration for the layered nanom headers: the standard-library
// includes, the NANOM_HD (CUDA host/device) qualifier, and the NANOM_HAS_STD_EXPECTED /
// NANOM_HAS_REFLECTION feature probes. No nanom code lives here; every other nanom header includes
// this first. (nanom.hpp is the umbrella that pulls in the whole library — see that file.)
#ifndef NANOM_PRELUDE_HPP_INCLUDED
#define NANOM_PRELUDE_HPP_INCLUDED

#include <algorithm>
#include <array>
#include <cassert>
#include <bit>
#include <charconv>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <version>
#if defined(__cpp_lib_expected) && __cpp_lib_expected >= 202202L
#include <expected>
#define NANOM_HAS_STD_EXPECTED 1
#else
#define NANOM_HAS_STD_EXPECTED 0
#endif

// C++26 P2996 static reflection probe (drives the macro-free describe provider, nanom26.hpp).
// The Bloomberg clang-p2996 fork defines NO __cpp feature-test macro yet, so the reliable signal
// is __has_feature(reflection) (set by -freflection / -freflection-latest); a conforming C++26
// compiler will define __cpp_impl_reflection instead. Either way <meta> must exist (today that
// means -stdlib=libc++ on the fork). Override with -DNANOM_HAS_REFLECTION=0/1.
#ifndef NANOM_HAS_REFLECTION
#if defined(__cpp_impl_reflection) && __has_include(<meta>)
#define NANOM_HAS_REFLECTION 1
#elif defined(__has_feature)
#if __has_feature(reflection) && __has_include(<meta>)
#define NANOM_HAS_REFLECTION 1
#endif
#endif
#endif
#ifndef NANOM_HAS_REFLECTION
#define NANOM_HAS_REFLECTION 0
#endif
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

// Safety defaults (override with -D...=0/1):
// - NANOM_GUARD_VIEWS: assert on null view access (debug/runtime contract checks)
//
// The project defaults to the strongest practical currently-implemented runtime
// protections while keeping straightforward opt-out for users with stricter
// performance constraints.
#ifndef NANOM_GUARD_VIEWS
#define NANOM_GUARD_VIEWS 1
#endif

// NANOM_HD marks the functions on the zero-copy decode path as callable from a
// GPU kernel. On a normal host build it expands to nothing (zero cost, zero API
// change); under a CUDA/HIP compiler it becomes __host__ __device__ so the exact
// same overlay/decode code runs on the device. The failure/formatting paths
// (error::render, soa storage, the combinators that allocate) are deliberately
// NOT annotated — they stay host-only. See docs/GPU.md and include/nanom/bulk.hpp.
#ifndef NANOM_HD
#  if defined(__CUDACC__) || defined(__HIPCC__) || defined(__CUDA__)
#    define NANOM_HD __host__ __device__
#  else
#    define NANOM_HD
#  endif
#endif

#endif  // NANOM_PRELUDE_HPP_INCLUDED
