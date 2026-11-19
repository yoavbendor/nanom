// SPDX-License-Identifier: Apache-2.0
// nanom/layout/arrow.hpp — hand a decoded table to Arrow through the C Data Interface.
//
// export_arrow(std::move(table), &schema, &array) produces a struct array ("+s") with one child per
// column, named by column name. Integer / float columns are exported zero-copy (the table's 64-byte
// aligned buffers become the Arrow data buffers); boolean columns are bit-packed into Arrow's
// LSB-first bitmap. Enum columns export their integer codes (no dictionary yet, see
// docs/LAYOUT.md). The table stays alive until the consumer has released the struct and every
// child it moved out.
#ifndef NANOM_LAYOUT_ARROW_HPP_INCLUDED
#define NANOM_LAYOUT_ARROW_HPP_INCLUDED

#include "decode.hpp"

#ifndef ARROW_C_DATA_INTERFACE
#define ARROW_C_DATA_INTERFACE
#define ARROW_FLAG_DICTIONARY_ORDERED 1
#define ARROW_FLAG_NULLABLE 2
#define ARROW_FLAG_MAP_KEYS_SORTED 4
extern "C" {
struct ArrowSchema {
  const char* format;
  const char* name;
  const char* metadata;
  int64_t flags;
  int64_t n_children;
  struct ArrowSchema** children;
  struct ArrowSchema* dictionary;
  void (*release)(struct ArrowSchema*);
  void* private_data;
};
struct ArrowArray {
  int64_t length;
  int64_t null_count;
  int64_t offset;
  int64_t n_buffers;
  int64_t n_children;
  const void** buffers;
  struct ArrowArray** children;
  struct ArrowArray* dictionary;
  void (*release)(struct ArrowArray*);
  void* private_data;
};
}
#endif

namespace nanom::layout {

/// Arrow C Data format string of a column type.
inline const char* arrow_format(storage s) {
  switch (s) {
    case storage::u8: return "C";
    case storage::u16: return "S";
    case storage::u32: return "I";
    case storage::u64: return "L";
    case storage::i8: return "c";
    case storage::i16: return "s";
    case storage::i32: return "i";
    case storage::i64: return "l";
    case storage::f32: return "f";
    case storage::f64: return "g";
    case storage::boolean: return "b";
  }
  return "C";
}

namespace arrow_detail {
struct state {
  table t;
  std::vector<std::string> names;
  std::vector<std::vector<std::uint8_t>> bitmaps;
  std::vector<ArrowSchema> child_schema;
  std::vector<ArrowSchema*> child_schema_ptr;
  std::vector<ArrowArray> child_array;
  std::vector<ArrowArray*> child_array_ptr;
  std::vector<std::array<const void*, 2>> child_buffers;
  std::array<const void*, 1> struct_buffers{nullptr};
};
using holder = std::shared_ptr<state>;

inline void release_child_schema(ArrowSchema* s) {
  delete static_cast<holder*>(s->private_data);
  s->release = nullptr;
}
inline void release_child_array(ArrowArray* a) {
  delete static_cast<holder*>(a->private_data);
  a->release = nullptr;
}
inline void release_schema(ArrowSchema* s) {
  for (int64_t i = 0; i < s->n_children; ++i)
    if (s->children[i]->release) s->children[i]->release(s->children[i]);
  delete static_cast<holder*>(s->private_data);
  s->release = nullptr;
}
inline void release_array(ArrowArray* a) {
  for (int64_t i = 0; i < a->n_children; ++i)
    if (a->children[i]->release) a->children[i]->release(a->children[i]);
  delete static_cast<holder*>(a->private_data);
  a->release = nullptr;
}
}  // namespace arrow_detail

/// Move `t` into Arrow C Data structs (out params are overwritten; release them when done).
inline void export_arrow(table&& t, ArrowSchema* out_schema, ArrowArray* out_array) {
  using namespace arrow_detail;
  auto st = std::make_shared<state>(state{std::move(t), {}, {}, {}, {}, {}, {}, {}, {nullptr}});
  const std::size_t n = st->t.columns();
  const auto rows = std::int64_t(st->t.rows());
  st->names.reserve(n);
  st->child_schema.resize(n);
  st->child_array.resize(n);
  st->child_buffers.resize(n);
  st->bitmaps.resize(n);
  for (std::size_t c = 0; c < n; ++c) {
    st->names.push_back(st->t.column_field(c).column);
    const storage s = st->t.column_storage(c);
    const void* data = st->t.bytes(c).data();
    if (s == storage::boolean) {
      auto& bm = st->bitmaps[c];
      bm.assign((st->t.rows() + 7) / 8, 0);
      const auto col = st->t.column<bool>(c);
      for (std::size_t r = 0; r < col.size(); ++r)
        if (col[r]) bm[r / 8] |= std::uint8_t(1u << (r % 8));
      data = bm.data();
    }
    st->child_buffers[c] = {nullptr, data};
    st->child_schema[c] = ArrowSchema{arrow_format(s), st->names[c].c_str(), nullptr, 0, 0, nullptr,
                                      nullptr, &release_child_schema, new holder(st)};
    st->child_array[c] = ArrowArray{rows, 0, 0, 2, 0, st->child_buffers[c].data(), nullptr, nullptr,
                                    &release_child_array, new holder(st)};
  }
  for (std::size_t c = 0; c < n; ++c) {
    st->child_schema_ptr.push_back(&st->child_schema[c]);
    st->child_array_ptr.push_back(&st->child_array[c]);
  }
  *out_schema = ArrowSchema{"+s", "", nullptr, 0, std::int64_t(n), st->child_schema_ptr.data(),
                            nullptr, &release_schema, new holder(st)};
  *out_array = ArrowArray{rows, 0, 0, 1, std::int64_t(n), st->struct_buffers.data(),
                          st->child_array_ptr.data(), nullptr, &release_array, new holder(st)};
}

}  // namespace nanom::layout

#endif
