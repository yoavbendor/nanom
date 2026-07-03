// ============================================================================
// nanom — a nom-inspired header-only C++23 binary parser combinator library
// with struct registration, schema generation and columnar (SoA) storage.
//
//   https://github.com/yoavbendor/nanom
//
// This is the UMBRELLA header: it includes the whole library. The code lives in
// layered headers you can also include individually (see README "Library layout"):
//
//   prelude.hpp   std includes, NANOM_HD, feature probes (shared config)
//   nom.hpp       the pure rust-nom parallel: input/result, combinators,
//                 binary + text numbers, bits            (parser-only subset)
//   reflect.hpp   fixed_string, wire types, describe<T> seam, strct<>/overlay<>
//   schema.hpp    schemas + Arrow/Avro/JSON/CSV emission  (extra)
//   soa.hpp       columnar Struct-of-Arrays storage       (extra)
//   bulk.hpp      data-parallel (GPU-ready) scatter        (separate, opt-in)
//
// Quick start (see README.md for more copy-paste examples):
//
//   #include <nanom/nanom.hpp>
//   namespace nm = nanom;
//
//   struct eth_hdr {
//     std::array<std::uint8_t,6> dst, src;
//     nm::be<std::uint16_t>      eth_type;
//   };
//   NANOM_DESCRIBE(eth_hdr, dst, src, eth_type);   // (optional under C++26 reflection)
//
//   nm::input in = nm::from(buffer);
//   auto r = nm::strct<eth_hdr>()(in);              // parse by value
//   if (!r) { std::puts(r.error().render(in).c_str()); return; }
//   std::uint16_t t = r->value.eth_type;            // decoded, host order
//   nm::input rest = r->rest;                       // zero-copy remainder
//
// Everything a rust-nom user knows exists under the same name (see
// docs/CHEATSHEET.md): tag, take, take_while1, alt, opt, many0, preceded,
// delimited, separated_list0, length_data, map, verify, cut, context, be_u16…
//
// SPDX-License-Identifier: Apache-2.0
// ============================================================================
#ifndef NANOM_HPP_INCLUDED
#define NANOM_HPP_INCLUDED

#include "prelude.hpp"  // shared config (includes, NANOM_HD, feature probes)
#include "nom.hpp"      // the nom-parallel parser (core + combinators + numbers + bits)
#include "reflect.hpp"  // struct reflection + strct<>/overlay<> (pulls in the describe<T> providers)
#include "schema.hpp"   // schema / Arrow / Avro / JSON / CSV
#include "soa.hpp"      // columnar (SoA) storage

#endif  // NANOM_HPP_INCLUDED
