// SPDX-License-Identifier: Apache-2.0
// A tiny C entry point over nanom::layout::export_arrow, built as a shared library so that
// tests/layout_arrow_lance.py can load it with ctypes, import the Arrow C Data structs into
// pyarrow and push them through pylance. Test-only; not part of the library.
#include <nanom/layout.hpp>

#include <cstdio>
#include <cstring>

namespace lay = nanom::layout;

static int fail(char* err, std::size_t n, const std::string& m) {
  if (err && n) std::snprintf(err, n, "%s", m.c_str());
  return 1;
}

/// enum_mode: 0 dictionary, 1 integer, 2 both. Returns 0 and fills *schema / *array, else 1 + err.
extern "C"
#if defined(_WIN32)
__declspec(dllexport)
#else
__attribute__((visibility("default")))
#endif
int nanom_layout_export_arrow(const char* desc_path, const char* enums_path, const char* raw_name,
                              const char* input_path, int enum_mode, int big_endian,
                              ArrowSchema* schema, ArrowArray* array, char* err, std::size_t errlen) {
  auto desc = lay::load_description(desc_path);
  if (!desc) return fail(err, errlen, desc.error().str());
  std::optional<lay::enum_catalog> enums;
  if (enums_path && *enums_path) {
    auto e = lay::load_enums(enums_path);
    if (!e) return fail(err, errlen, e.error().str());
    enums = std::move(*e);
  }
  lay::compile_options co;
  if (big_endian) co.order = std::endian::big;
  auto plan = lay::plan::compile(*desc, raw_name, enums ? &*enums : nullptr, co);
  if (!plan) return fail(err, errlen, plan.error().str());
  std::vector<std::byte> bytes;
  if (std::FILE* f = std::fopen(input_path, "rb")) {
    std::byte buf[1 << 16];
    std::size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) bytes.insert(bytes.end(), buf, buf + n);
    std::fclose(f);
  } else {
    return fail(err, errlen, std::string("cannot read ") + input_path);
  }
  auto t = lay::decode(*plan, bytes);
  if (!t) return fail(err, errlen, t.error().str());
  lay::arrow_options o;
  o.enums = enum_mode == 1 ? lay::enum_mode::integer : enum_mode == 2 ? lay::enum_mode::both
                                                                       : lay::enum_mode::dictionary;
  lay::export_arrow(std::move(*t), schema, array, o);
  return 0;
}
