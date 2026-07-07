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

// ---------------------------------------------------------------------------
// Safety profile
// ---------------------------------------------------------------------------
// NANOM_STRICT is the "safe routes only" profile for safety- AND speed-obsessed
// users. The idea is a *sweetened pill*: you accept compile-time restrictions,
// and in return nanom compiles OUT the runtime safety machinery those
// restrictions make unnecessary — so strict runs at the speed of the unchecked
// `minimal` profile while the compiler (not a runtime branch) enforces the
// lifetime contract.
//
// When NANOM_STRICT=1:
//   * runtime generation tracking and view guards are turned OFF by default
//     (lean input/bytes, no per-access generation branch) — see below.
//   * `[[clang::lifetimebound]]` is enforced on the zero-copy entry points, so
//     binding a view/span to a temporary buffer is a COMPILE error (the exact
//     dangling-view bug that generation tracking otherwise catches at runtime).
//   * the raw pointer+length `from()` escape hatch is removed (callers pass a
//     sized span/array/string_view instead — no unbounded provenance).
//   * the GPU/bulk data-parallel path (raw device-pointer scatter, outside the
//     bounds-checked combinator model) is unavailable: including <nanom/bulk.hpp>
//     under NANOM_STRICT is a hard error.
//   * combinator bounds checks are KEPT (defense against hostile input is not a
//     caller-discipline question) and the library stays continuously fuzzed.
//
// Everything is still individually overridable, e.g. -DNANOM_STRICT=1 with an
// explicit -DNANOM_GENERATION=1 to keep runtime tracking on top of the strict
// compile-time restrictions (paranoid belt-and-suspenders build).
#ifndef NANOM_STRICT
# define NANOM_STRICT 0
#endif

// Safety defaults (override with -D...=0/1).
// Strong defaults are chosen for reviewer-facing and production hardening;
// users can opt out per target when needed. Under NANOM_STRICT the runtime
// nets default OFF because the compile-time restrictions replace them.
#ifndef NANOM_GUARD_VIEWS
# if NANOM_STRICT
#  define NANOM_GUARD_VIEWS 0
# else
#  define NANOM_GUARD_VIEWS 1
# endif
#endif
#ifndef NANOM_GENERATION
# if NANOM_STRICT
#  define NANOM_GENERATION 0
# else
#  define NANOM_GENERATION 1
# endif
#endif
#ifndef NANOM_GENERATION_THROW
# define NANOM_GENERATION_THROW 0
#endif

// NANOM_LIFETIMEBOUND — Clang's compile-time dangling-view diagnostic. Applied
// to the zero-copy entry points (from(), as_str()) so a view/span bound to a
// temporary buffer is diagnosed at compile time. Zero runtime cost; expands to
// nothing on compilers without the attribute (e.g. GCC), which still build fine.
// Under NANOM_STRICT the diagnostic is present whenever the toolchain supports
// it; outside strict it is available but unobtrusive.
#if defined(__has_cpp_attribute)
# if __has_cpp_attribute(clang::lifetimebound)
#  define NANOM_LIFETIMEBOUND [[clang::lifetimebound]]
# elif __has_cpp_attribute(msvc::lifetimebound)
#  define NANOM_LIFETIMEBOUND [[msvc::lifetimebound]]
# endif
#endif
#ifndef NANOM_LIFETIMEBOUND
# define NANOM_LIFETIMEBOUND
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
