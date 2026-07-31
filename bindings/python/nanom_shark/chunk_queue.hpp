// SPDX-License-Identifier: Apache-2.0
#pragma once

// The producer/consumer handoff primitive for py_nanom_shark's streaming binding
// (streaming_arrow.hpp) — pulled into its own header, with NO Python/nanobind dependency, so it can
// be built and stress-tested in isolation under ThreadSanitizer (see
// test_chunk_queue_tsan.cpp) without dragging in a CPython build. streaming_arrow.hpp includes this
// unchanged; nothing here differs between the two translation units.
//
// One table's bounded producer/consumer handoff queue. Every method is safe to call from either
// thread; the only thing that ever crosses the boundary is a ChunkDescriptor — a small, plain,
// already-immutable snapshot of one sealed chunk (never the soa<T> itself, which stays
// single-threaded by construction — see streaming_arrow.hpp's header comment).

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <utility>
#include <vector>

namespace nanom_shark_py {

struct ChunkDescriptor {
  std::int64_t              rows = 0;
  std::vector<const void*>  col_ptrs;
};

class ChunkQueue {
 public:
  explicit ChunkQueue(std::size_t bound) : bound_(bound) {}

  // Producer side. Blocks (polling the stop token every few ms — no dependency on
  // condition_variable_any's stop_token overload, which varies across stdlib versions) while the
  // queue is full. Returns false if the caller should stop (cancellation requested).
  bool push(ChunkDescriptor d, const std::stop_token& stop) {
    std::unique_lock<std::mutex> lk(mu_);
    for (;;) {
      if (stop.stop_requested()) return false;
      if (q_.size() < bound_) break;
      cv_producer_.wait_for(lk, std::chrono::milliseconds(5));
    }
    q_.push_back(std::move(d));
    lk.unlock();
    cv_consumer_.notify_one();
    return true;
  }

  // Producer side: called exactly once, when decode finishes (successfully, with an error, or
  // cancelled) — wakes every consumer so a get_next() blocked with nothing left to produce returns
  // (or raises) instead of hanging forever.
  void finish(std::string error) {
    std::lock_guard<std::mutex> lk(mu_);
    done_ = true;
    error_ = std::move(error);
    cv_consumer_.notify_all();
  }

  // Consumer side. Caller must have released the GIL before calling this (the wait can block for
  // an arbitrary time). Returns true with `out` populated if a chunk was dequeued; false at a
  // clean end of stream (queue drained, no error). Throws std::runtime_error if the producer
  // recorded an error and the queue has fully drained.
  bool pop(ChunkDescriptor& out) {
    std::unique_lock<std::mutex> lk(mu_);
    cv_consumer_.wait(lk, [&] { return !q_.empty() || done_; });
    if (!q_.empty()) {
      out = std::move(q_.front());
      q_.pop_front();
      lk.unlock();
      cv_producer_.notify_one();
      return true;
    }
    if (!error_.empty()) {
      std::string msg = error_;
      lk.unlock();
      throw std::runtime_error(msg);
    }
    return false;
  }

  // Wake anyone blocked, without marking done — used on cancellation before finish() is called by
  // the (about-to-exit) producer, so a destructor tearing things down doesn't have to wait for the
  // normal 5ms poll granularity.
  void wake_all() {
    std::lock_guard<std::mutex> lk(mu_);
    cv_producer_.notify_all();
    cv_consumer_.notify_all();
  }

 private:
  std::mutex               mu_;
  std::condition_variable  cv_producer_;  // producer waits here for room
  std::condition_variable  cv_consumer_;  // consumer waits here for data
  std::deque<ChunkDescriptor> q_;
  std::size_t               bound_;
  bool                      done_ = false;
  std::string               error_;
};

}  // namespace nanom_shark_py
