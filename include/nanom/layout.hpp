// SPDX-License-Identifier: Apache-2.0
// nanom/layout.hpp — decode raw binary records from a JSON description of their layout.
//
//   namespace lay = nanom::layout;
//   auto desc  = lay::load_description("desc.jsonl").value();         // JSON Lines, one scalar each
//   auto enums = lay::load_enums("enums.json").value();                // optional
//   auto plan  = lay::plan::compile(desc, "/dev/vdiZ/pacemaker/gfi.raw", &enums).value();
//   auto t     = lay::decode(plan, bytes).value();                     // one column per scalar
//   auto grab  = t.column<std::uint32_t>("GFI[0].grab_index");         // std::span<const uint32_t>
//   auto brain = plan.find("GFI.brain_type").value();                  // precomputed handle
//   for (auto rec : plan.records(bytes)) use(rec.get<int>(brain));     // random access, no strings
//   lay::export_jsonl(plan, bytes, sink, plan.all());                  // nested JSON Lines
//
// Pieces: layout/json.hpp (JSON via nanom combinators), layout/desc.hpp (description + enum file),
// layout/plan.hpp (compile: stride, loads, name tree), layout/decode.hpp (column kernels),
// layout/export.hpp (JSON Lines / CSV), layout/arrow.hpp (Arrow C Data Interface),
// layout/e2e.hpp (AUTOSAR E2E protect/check). AUTOSAR I-PDU signals (byte order, factor/offset,
// multiplexing, update bits; plan::set / plan::encode) are optional description keys.
// See docs/LAYOUT.md.
#ifndef NANOM_LAYOUT_HPP_INCLUDED
#define NANOM_LAYOUT_HPP_INCLUDED

#include "layout/arrow.hpp"
#include "layout/decode.hpp"
#include "layout/desc.hpp"
#include "layout/e2e.hpp"
#include "layout/export.hpp"
#include "layout/json.hpp"
#include "layout/plan.hpp"

#endif
