// SPDX-License-Identifier: Apache-2.0
// nanom/bindings — soa<T> -> Arrow C Data Interface (ArrowArrayStream), the reusable "Layer A".
//
// Every nanom soa<T> column is a contiguous, fixed-width host-order buffer already in Arrow layout,
// with its Arrow C-data format string in column_info::arrow ("I"/"L"/"w:6"/…). So an soa is exported
// zero-copy: one struct RecordBatch per soa chunk, each child array pointing straight into the chunk's
// column buffer. The soa is kept alive (shared_ptr) for as long as any exported batch lives, and the
// release callbacks free only the little wrapper structs we allocate — never the borrowed data.
//
// This file is domain-free (no packets, no pcapng): it turns ANY soa<Described T> into a stream. The
// Python glue (Arrow PyCapsule protocol) lives next to it in the nanobind module.
#ifndef NANOM_ARROW_HPP_INCLUDED
#define NANOM_ARROW_HPP_INCLUDED

#include <nanom/soa.hpp>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

// ---- Arrow C Data Interface (ABI-stable; copied verbatim from the Arrow spec) -----------------
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
struct ArrowArrayStream {
  int (*get_schema)(struct ArrowArrayStream*, struct ArrowSchema* out);
  int (*get_next)(struct ArrowArrayStream*, struct ArrowArray* out);
  const char* (*get_last_error)(struct ArrowArrayStream*);
  void (*release)(struct ArrowArrayStream*);
  void* private_data;
};
}

namespace nanom::arrow {

// A fully domain-erased snapshot of an soa: column names/formats + per-chunk borrowed column pointers,
// plus a shared_ptr that keeps the underlying soa (and thus those pointers) alive.
struct export_state {
  std::shared_ptr<void>                 keepalive;  // owns the soa<T>
  std::vector<std::string>              names;
  std::vector<std::string>              formats;
  struct batch { int64_t rows; std::vector<const void*> col_ptrs; };
  std::vector<batch>                    batches;
  std::size_t                           next = 0;
  std::string                           last_error;
};

// ---- ArrowSchema construction (self-owned: strings strdup'd, freed in release) -----------------
namespace detail {
inline void release_schema(ArrowSchema* s) {
  if (!s->release) return;
  std::free(const_cast<char*>(s->format));
  std::free(const_cast<char*>(s->name));
  for (int64_t i = 0; i < s->n_children; ++i)
    if (s->children[i]) {
      if (s->children[i]->release) s->children[i]->release(s->children[i]);
      delete s->children[i];
    }
  delete[] s->children;
  s->release = nullptr;
}
inline void init_leaf_schema(ArrowSchema* s, const char* format, const char* name) {
  *s = {};
  s->format = strdup(format);
  s->name = strdup(name);
  s->flags = 0;  // not nullable (soa columns carry no null bitmap)
  s->release = release_schema;
}
}  // namespace detail

inline int export_get_schema(ArrowArrayStream* self, ArrowSchema* out) {
  auto* st = static_cast<export_state*>(self->private_data);
  *out = {};
  out->format = strdup("+s");  // struct
  out->name = strdup("");
  out->n_children = static_cast<int64_t>(st->names.size());
  out->children = new ArrowSchema*[st->names.size()];
  for (std::size_t i = 0; i < st->names.size(); ++i) {
    out->children[i] = new ArrowSchema();
    detail::init_leaf_schema(out->children[i], st->formats[i].c_str(), st->names[i].c_str());
  }
  out->release = detail::release_schema;
  return 0;
}

// ---- ArrowArray construction (borrows soa buffers; keepalive holds the soa) --------------------
namespace detail {
inline void release_leaf_array(ArrowArray* a) {
  if (!a->release) return;
  delete[] a->buffers;
  a->release = nullptr;
}
inline void release_struct_array(ArrowArray* a) {
  if (!a->release) return;
  for (int64_t i = 0; i < a->n_children; ++i)
    if (a->children[i]) {
      if (a->children[i]->release) a->children[i]->release(a->children[i]);
      delete a->children[i];
    }
  delete[] a->children;
  delete[] a->buffers;
  delete static_cast<std::shared_ptr<void>*>(a->private_data);  // drop the soa keepalive
  a->release = nullptr;
}
}  // namespace detail

inline int export_get_next(ArrowArrayStream* self, ArrowArray* out) {
  auto* st = static_cast<export_state*>(self->private_data);
  if (st->next >= st->batches.size()) {  // end of stream: a released (empty) array
    *out = {};
    return 0;
  }
  const export_state::batch& b = st->batches[st->next++];
  *out = {};
  out->length = b.rows;
  out->null_count = 0;
  out->n_buffers = 1;              // struct: [validity], null (no nulls)
  out->buffers = new const void*[1]{nullptr};
  out->n_children = static_cast<int64_t>(b.col_ptrs.size());
  out->children = new ArrowArray*[b.col_ptrs.size()];
  for (std::size_t i = 0; i < b.col_ptrs.size(); ++i) {
    auto* c = new ArrowArray();
    *c = {};
    c->length = b.rows;
    c->null_count = 0;
    c->n_buffers = 2;             // primitive / fixed-size-binary: [validity=null, data]
    c->buffers = new const void*[2]{nullptr, b.col_ptrs[i]};
    c->release = detail::release_leaf_array;
    out->children[i] = c;
  }
  out->private_data = new std::shared_ptr<void>(st->keepalive);  // keep the borrowed data alive
  out->release = detail::release_struct_array;
  return 0;
}

inline const char* export_get_last_error(ArrowArrayStream* self) {
  return static_cast<export_state*>(self->private_data)->last_error.c_str();
}
inline void export_release_stream(ArrowArrayStream* self) {
  if (!self->release) return;
  delete static_cast<export_state*>(self->private_data);
  self->private_data = nullptr;
  self->release = nullptr;
}

// Build a self-contained ArrowArrayStream from an soa<T>. The stream (and every batch it yields) keeps
// `table` alive; the caller/importer owns the returned stream and must call its release (Arrow's
// PyCapsule consumer does this automatically).
template <class T>
void export_stream(std::shared_ptr<nanom::soa<T>> table, ArrowArrayStream* out) {
  auto* st = new export_state();
  st->keepalive = table;
  for (const auto& c : table->columns()) {
    st->names.push_back(c.name);
    st->formats.push_back(c.arrow);
  }
  table->for_each_chunk([&](const auto& ch) {
    export_state::batch b;
    b.rows = static_cast<int64_t>(ch.rows);
    for (std::size_t i = 0; i < ch.cols.size(); ++i) b.col_ptrs.push_back(ch.cols[i].data());
    st->batches.push_back(std::move(b));
  });
  *out = {};
  out->get_schema = export_get_schema;
  out->get_next = export_get_next;
  out->get_last_error = export_get_last_error;
  out->release = export_release_stream;
  out->private_data = st;
}

}  // namespace nanom::arrow

#endif  // NANOM_ARROW_HPP_INCLUDED
