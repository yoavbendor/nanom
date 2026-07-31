// SPDX-License-Identifier: Apache-2.0
#pragma once

// nanom_shark (Python) — true incremental streaming: a background C++ thread keeps decoding while
// Python concurrently consumes completed table chunks. Genuinely "C++ fills chunk t while Python
// reads chunk t-1," with real backpressure — not the batch design's one-shot handoff.
//
// The key simplification: soa<T> (include/nanom/soa.hpp) has ZERO thread-safety (no mutex/atomic
// anywhere). Rather than retrofitting locks around it, this design keeps it single-threaded BY
// CONSTRUCTION: only the background producer thread ever calls push()/seal()/chunk_count()/
// chunk_at(). The instant a chunk is confirmed sealed, the producer extracts its raw column
// pointers + row count (still producer-thread-only, no lock needed for this step) into a small,
// plain, already-immutable ChunkDescriptor — and ONLY this descriptor crosses the thread boundary,
// via a bounded, thread-safe queue. The consumer thread never touches soa<T>, sidestepping the
// whole reallocation-race concern entirely rather than mitigating it.
//
// One subtlety chunk_at() forces on any producer-side polling: chunk_at(i) for i < chunk_count()
// can be either a genuinely sealed (immutable-forever) chunk OR, for the LAST index, the still-
// growing open chunk. The safe rule: only ever deliver chunk i once chunk_count() > i + 1 — a
// later chunk existing proves seal() ran and moved chunk i into sealed_ (which only happens when
// a new, empty open_ chunk is created right after). At end-of-decode, force one seal() per table
// to flush whatever's left, then deliver up to the new chunk_count().
//
// Backpressure: each table has its OWN bounded queue (different tables seal at very different
// rates — forcing them through one shared queue would let a slow table stall a fast one). When a
// table's queue is full, the producer's push blocks before decoding further packets, directly
// throttling the producer to the pace of the slowest actively-consumed table. Bound 2 is literally
// double buffering.
//
// GIL discipline: the producer thread NEVER touches Python/nanobind objects — only AllTables/
// soa<T> (exclusively) and plain std::mutex/condition_variable/std::deque. Only the original
// Python-calling thread ever constructs Arrow/nanobind objects, inside get_next(), with the GIL
// released only around the blocking wait.

#include "chunk_queue.hpp"
#include "nanom_arrow.hpp"

// Raw CPython API for releasing/reacquiring the GIL around get_next()'s blocking wait. Deliberately
// NOT nb::gil_scoped_release: that guard assumes it runs through nanobind's own call dispatch, which
// sets up nanobind-internal GIL-state bookkeeping first. get_next() is invoked as a bare C function
// pointer by pyarrow's C++ core via the Arrow C Stream ABI, entirely bypassing that dispatch, so
// nanobind's guard gets confused about whether the GIL is actually held (confirmed: it aborts with
// "the function must be called with the GIL held, but the GIL is released"). Py_BEGIN_ALLOW_THREADS/
// Py_END_ALLOW_THREADS (== PyEval_SaveThread/PyEval_RestoreThread) depend on nothing but raw CPython
// internals and are correct regardless of calling convention.
#include <Python.h>

#include <nanom_shark/decode_options.hpp>
#include <nanom_shark/l2l3_nodes.hpp>
#include <nanom_shark/pcap.hpp>
#include <nanom_shark/protocol.hpp>
#include <nanom_shark/streaming.hpp>

#include <nanobind/nanobind.h>

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <stop_token>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

namespace nanom_shark_py {

namespace nb = nanobind;
namespace nm = nanom;
namespace ns = nanom_shark;

// ChunkDescriptor and ChunkQueue live in chunk_queue.hpp — a small, Python/nanobind-free header so
// their producer/consumer logic can be stress-tested in isolation under ThreadSanitizer
// (test_chunk_queue_tsan.cpp) without dragging a CPython build through TSan instrumentation.

// The ONE bound class for a streaming table, reused for every table regardless of Row type —
// exactly the same type-erasure property the batch binding's `Table` class relies on. `pop_next`
// is the only thing that differs from the batch `Table::build`: it blocks on a live queue instead
// of replaying a pre-built list.
struct StreamingTable {
  std::string                   name;
  std::vector<std::string>      column_names;
  std::vector<std::string>      column_formats;
  std::shared_ptr<ChunkQueue>   queue;

  std::string repr() const { return "<nanom_shark.StreamingTable '" + name + "'>"; }

  // Arrow PyCapsule protocol: a live, blocking ArrowArrayStream. Each call builds a genuinely
  // independent stream state (its own `get_schema` uses the fixed schema; `get_next` blocks on
  // THIS table's shared queue) — multiple concurrent readers of the same table would race for
  // chunks from one shared queue (first-come, first-served), which is a real, documented
  // limitation of "one live producer, multiple independent streaming consumers of the same table"
  // — the intended usage is one consumer per table, matching one background decode per session.
  nb::capsule arrow_c_stream(nb::object /*requested_schema*/) const {
    auto* state = new StreamState{column_names, column_formats, queue};
    auto* c_stream = static_cast<ArrowArrayStream*>(std::malloc(sizeof(ArrowArrayStream)));
    if (!c_stream) {
      delete state;
      throw std::bad_alloc();
    }
    *c_stream = {};
    c_stream->get_schema = &StreamState::get_schema;
    c_stream->get_next = &StreamState::get_next;
    c_stream->get_last_error = &StreamState::get_last_error;
    c_stream->release = &StreamState::release;
    c_stream->private_data = state;
    return nb::capsule(c_stream, "arrow_array_stream", [](void* p) noexcept {
      auto* s = static_cast<ArrowArrayStream*>(p);
      if (s->release) s->release(s);
      std::free(s);
    });
  }

 private:
  struct StreamState {
    std::vector<std::string>    names, formats;
    std::shared_ptr<ChunkQueue>  queue;
    std::string                  last_error;

    static int get_schema(ArrowArrayStream* self, ArrowSchema* out) {
      auto* st = static_cast<StreamState*>(self->private_data);
      nm::arrow::build_struct_schema(st->names, st->formats, out);
      return 0;
    }
    static int get_next(ArrowArrayStream* self, ArrowArray* out) {
      auto* st = static_cast<StreamState*>(self->private_data);
      ChunkDescriptor d;
      bool have = false;
      // No GIL handling here at all, in either direction: get_next() is invoked as a bare C
      // function pointer directly by the Arrow C Stream consumer (pyarrow's C++ core), which
      // releases the GIL itself before calling ANY stream callback (confirmed empirically -- the
      // GIL is already released on entry here, so PyEval_SaveThread would be a double-release and
      // aborts with "the GIL is released (thread state is NULL)"). Nothing below touches a Python/
      // nanobind object -- ArrowArray/ArrowSchema are plain C structs -- so there is nothing that
      // needs the GIL in this function at all.
      try {
        have = st->queue->pop(d);
      } catch (const std::exception& e) {
        st->last_error = e.what();
        return -1;  // Arrow C Stream protocol: nonzero == error, check get_last_error
      }
      if (!have) {  // clean end of stream
        *out = {};
        return 0;
      }
      // No keepalive needed here beyond the queue's own shared_ptr chain: the pointers in `d` were
      // extracted from a chunk that is sealed (immutable) forever once delivered, and the
      // underlying AllTables is kept alive by the producer thread's own capture until it exits —
      // plus, defensively, by this StreamState's queue shared_ptr (whose existence implies the
      // session/producer that owns AllTables is still referenced by at least this stream).
      nm::arrow::build_struct_array(d.rows, d.col_ptrs, st->queue, out);
      return 0;
    }
    static const char* get_last_error(ArrowArrayStream* self) {
      return static_cast<StreamState*>(self->private_data)->last_error.c_str();
    }
    static void release(ArrowArrayStream* self) {
      delete static_cast<StreamState*>(self->private_data);
      self->release = nullptr;
    }
  };
};

// Owns the background decode thread and every table's queue. Constructed with the whole capture
// already resident in memory (Python handed us a complete `bytes` object) — this is about
// incremental OUTPUT consumption, not incremental input feeding; buffer-lifetime tokens
// (defrag::Token / StreamingDecodeSession's retire() contract) are a separate, already-solved
// problem for a caller feeding packets from a small reusable pool, which does not apply here since
// `capture_` outlives the whole session regardless.
class StreamingArrowSession {
 public:
  StreamingArrowSession(std::vector<std::uint8_t> capture, ns::DecodeOptions opts,
                       std::size_t queue_bound)
      : capture_(std::move(capture)), opts_(std::move(opts)) {
    tables_ = std::make_shared<ns::AllTables>();
    // Schema (names/formats) is known statically per table right now; rows arrive later. Build one
    // StreamingTable (+ its queue) per registered table, in for_each_table's fold order, then start
    // the producer thread. This is the only place a per-Row C++ type exists in this whole class —
    // the rest is fully type-erased, exactly like the batch binding's Table.
    tables_->for_each_table([&](std::string_view name, const auto& soa) {
      StreamingTable st;
      st.name.assign(name);
      for (const auto& c : soa.columns()) {
        st.column_names.push_back(c.name);
        st.column_formats.push_back(c.arrow);
      }
      st.queue = std::make_shared<ChunkQueue>(queue_bound);
      tables_out_.push_back(st);
    });
    // One producer-side pollers_ entry per table, built in the SAME fold (where the concrete Row
    // type is still known) — each closure captures the owning tables_ shared_ptr (keeps AllTables
    // alive for the producer thread's whole run) plus a stable pointer to that one soa<Row>
    // sub-object (table_set privately inherits fixed slots: no reallocation, no moves) and that
    // table's queue. `last_delivered` is a plain size_t owned by the closure itself (mutable
    // lambda) -- purely producer-thread state, touched by nothing else.
    std::size_t idx = 0;
    tables_->for_each_table([&](std::string_view, const auto& soa) {
      using SoaType = std::remove_cvref_t<decltype(soa)>;
      const SoaType* table = &soa;
      std::shared_ptr<ChunkQueue> queue = tables_out_[idx].queue;
      std::size_t last_delivered = 0;
      pollers_.push_back(
          [table, queue, last_delivered](const std::stop_token& stop, bool final_flush) mutable -> bool {
            const std::size_t cur = table->chunk_count();
            // chunk_at(i) for i < chunk_count()-1 is always a genuinely sealed (immutable-forever)
            // chunk; the LAST index might instead be the still-growing open chunk, so it's only
            // safe to read once a LATER chunk exists (proof seal() already ran for it) -- except on
            // the final flush, where the producer loop has truly finished and nothing will ever
            // push() again, so the current "open" tail (if any) is *already* permanently frozen
            // without needing to call soa<T>::seal() (which isn't reachable here anyway: for_each_
            // table only ever hands out const soa<Row>&).
            const std::size_t deliverable = final_flush ? cur : (cur > 0 ? cur - 1 : 0);
            while (last_delivered < deliverable) {
              const auto& ch = table->chunk_at(last_delivered);
              ChunkDescriptor d;
              d.rows = static_cast<std::int64_t>(ch.rows);
              d.col_ptrs.reserve(ch.cols.size());
              for (const auto& col : ch.cols) d.col_ptrs.push_back(col.data());
              if (!queue->push(std::move(d), stop)) return false;  // cancelled
              ++last_delivered;
            }
            return true;
          });
      ++idx;
    });

    worker_ = std::jthread([this](std::stop_token st) { this->run(st); });
  }

  ~StreamingArrowSession() {
    worker_.request_stop();
    for (auto& st : tables_out_) st.queue->wake_all();
    // The background thread never touches Python, so joining it can never deadlock on the GIL --
    // but release it anyway while waiting, as a matter of discipline (a future change to the
    // producer must not silently reintroduce a GIL dependency here without this breaking loudly).
    // Raw CPython API, not nb::gil_scoped_release: object destruction can be triggered from
    // contexts (e.g. GC) where nanobind's own GIL-state bookkeeping may not be set up the way its
    // guard expects -- see get_next()'s identical concern in the same file. PyEval_SaveThread /
    // PyEval_RestoreThread depend on nothing but raw CPython internals.
    PyThreadState* saved = PyEval_SaveThread();
    if (worker_.joinable()) worker_.join();
    PyEval_RestoreThread(saved);
  }

  nb::dict table_dict() const {
    nb::dict d;
    for (const StreamingTable& t : tables_out_) d[nb::str(t.name.c_str())] = nb::cast(t);
    return d;
  }
  std::vector<std::string> table_names() const {
    std::vector<std::string> v;
    for (const StreamingTable& t : tables_out_) v.push_back(t.name);
    return v;
  }
  std::size_t size() const { return tables_out_.size(); }

 private:
  void run(std::stop_token stop) {
    std::string error;
    bool ok = true;
    const nm::bytes file(reinterpret_cast<const std::byte*>(capture_.data()), capture_.size());
    std::vector<nmpcap::BlockRef> refs;
    if (!nmpcap::scan_blocks(file, refs, error)) ok = false;

    if (ok) {
      ns::SinkHub sink{nullptr};
      ns::StreamingDecodeSession<ns::default_decoder> session(*tables_, sink, opts_);
      for (const nmpcap::BlockRef& ref : refs) {
        if (stop.stop_requested()) break;
        const std::size_t off = std::size_t(ref.file_offset);
        if (off > capture_.size()) continue;
        const std::size_t avail = capture_.size() - off;
        const std::size_t want =
            ref.kind == nmpcap::Kind::Idb ? std::max<std::size_t>(ref.length, 28) : ref.length;
        const std::size_t take = std::min<std::size_t>(want, avail);
        const nanom::bytes block = file.subspan(off, take);

        if (ref.kind == nmpcap::Kind::Shb) {
          session.feed_shb(block);
          continue;
        }
        if (ref.kind == nmpcap::Kind::Idb) {
          session.feed_idb(block, ref.little_endian, ref.length);
          continue;
        }
        if (ref.kind != nmpcap::Kind::Epb && ref.kind != nmpcap::Kind::PcapRecord) continue;

        session.feed_epb(block, ref.little_endian, ns::defrag::kNoToken, ref.kind, ref.file_offset);

        // Producer-only: check every table for newly-confirmed-sealed chunks and enqueue them,
        // blocking (backpressure) if a queue is full. If cancelled mid-poll, stop feeding more
        // packets entirely.
        for (auto& poll : pollers_) {
          if (!poll(stop, /*final_flush=*/false)) {
            ok = false;  // treated as a clean stop, not an error -- see finish() call below
            goto done_feeding;
          }
        }
      }
    }
  done_feeding:
    const bool cancelled = stop.stop_requested();
    // Final flush: force-seal every table's still-open chunk and deliver the rest, UNLESS the
    // session was cancelled (nothing more should be produced once a caller has asked to stop).
    if (!cancelled) {
      for (auto& poll : pollers_) poll(stop, /*final_flush=*/true);
    }
    for (auto& st : tables_out_) st.queue->finish(ok || cancelled ? std::string{} : error);
  }

  std::vector<std::uint8_t>          capture_;
  ns::DecodeOptions                  opts_;
  std::shared_ptr<ns::AllTables>      tables_;
  std::vector<StreamingTable>         tables_out_;
  std::vector<std::function<bool(const std::stop_token&, bool)>> pollers_;
  std::jthread                       worker_;
};

}  // namespace nanom_shark_py
