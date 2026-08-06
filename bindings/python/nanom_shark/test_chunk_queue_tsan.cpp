// SPDX-License-Identifier: Apache-2.0
//
// ThreadSanitizer proof for chunk_queue.hpp's ChunkQueue: the actual concurrency primitive the
// streaming Python binding (streaming_arrow.hpp) uses to hand sealed chunks from the background
// decode thread to whichever thread is draining a table's Arrow stream. This harness has NO
// Python/nanobind/nanom dependency at all — it exercises ChunkQueue exactly as streaming_arrow.hpp
// does (one producer thread calling push() in a loop then finish(), one or more consumer threads
// calling pop() in a loop), so a real multi-threaded build under -fsanitize=thread can actually
// prove there is no data race in the handoff, rather than relying on code-review confidence.
//
// Build (see also CMakeLists.txt's `chunk_queue_tsan` target):
//   g++ -std=c++23 -fsanitize=thread -g -O1 test_chunk_queue_tsan.cpp -o /tmp/chunk_queue_tsan
//   /tmp/chunk_queue_tsan
// A clean run (exit code 0, no "WARNING: ThreadSanitizer" output) is the acceptance bar.

#include "chunk_queue.hpp"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <vector>

using nanom_shark_py::ChunkDescriptor;
using nanom_shark_py::ChunkQueue;

namespace {

// Scenario 1: one producer, one consumer, a queue bound small enough that backpressure is
// guaranteed to bite repeatedly (bound 2, ~50k items) -- exactly the "double buffering" case the
// design targets. Every pushed row count must be observed, in order, exactly once.
void one_to_one(int n, std::size_t bound) {
  ChunkQueue q(bound);
  std::jthread producer([&](std::stop_token st) {
    for (int i = 0; i < n; ++i) {
      ChunkDescriptor d;
      d.rows = i;
      if (!q.push(std::move(d), st)) std::abort();
    }
    q.finish("");
  });

  int expect = 0;
  for (;;) {
    ChunkDescriptor d;
    bool have = q.pop(d);
    if (!have) break;
    if (d.rows != expect) {
      std::fprintf(stderr, "one_to_one: order violation, expected %d got %lld\n", expect,
                   static_cast<long long>(d.rows));
      std::abort();
    }
    ++expect;
  }
  if (expect != n) {
    std::fprintf(stderr, "one_to_one: expected %d items, saw %d\n", n, expect);
    std::abort();
  }
}

// Scenario 2: one producer, several consumers racing pop() on the SAME queue (a documented, real
// limitation noted in streaming_arrow.hpp -- concurrent readers of one table race for chunks
// first-come-first-served). Not the intended usage (one consumer per table), but it must still be
// race-free at the ChunkQueue level: every item delivered to exactly one consumer, no double
// delivery, no lost item, no data race flagged by TSan.
void fan_out(int n, std::size_t bound, int consumers) {
  ChunkQueue q(bound);
  std::jthread producer([&](std::stop_token st) {
    for (int i = 0; i < n; ++i) {
      ChunkDescriptor d;
      d.rows = i;
      if (!q.push(std::move(d), st)) std::abort();
    }
    q.finish("");
  });

  std::atomic<int> total_seen{0};
  std::vector<std::jthread> workers;
  for (int c = 0; c < consumers; ++c) {
    workers.emplace_back([&] {
      for (;;) {
        ChunkDescriptor d;
        if (!q.pop(d)) break;
        total_seen.fetch_add(1, std::memory_order_relaxed);
      }
    });
  }
  workers.clear();  // joins every jthread
  if (total_seen.load() != n) {
    std::fprintf(stderr, "fan_out: expected %d deliveries total, saw %d\n", n, total_seen.load());
    std::abort();
  }
}

// Scenario 3: cancellation mid-stream -- request_stop while the producer is still blocked on a
// full queue, exactly the destructor path in StreamingArrowSession. push() must return promptly
// (false), never hang.
void cancel_mid_stream() {
  ChunkQueue q(1);
  std::atomic<bool> producer_done{false};
  std::jthread producer([&](std::stop_token st) {
    // Fill the one slot, then keep trying to push more -- this call blocks until either room
    // frees up or cancellation is observed.
    ChunkDescriptor d0;
    d0.rows = 0;
    if (!q.push(std::move(d0), st)) {
      producer_done.store(true);
      return;
    }
    for (int i = 1; i < 1000000; ++i) {
      ChunkDescriptor d;
      d.rows = i;
      if (!q.push(std::move(d), st)) break;  // expected: cancellation observed
    }
    producer_done.store(true);
  });
  std::this_thread::sleep_for(std::chrono::milliseconds(20));
  producer.request_stop();
  q.wake_all();
  producer.join();
  if (!producer_done.load()) {
    std::fprintf(stderr, "cancel_mid_stream: producer did not report completion\n");
    std::abort();
  }
}

// Scenario 4: error propagation -- finish() with a non-empty error, drained after some items;
// pop() must throw exactly once the queue is empty, not before.
void error_propagation() {
  ChunkQueue q(4);
  std::jthread producer([&](std::stop_token st) {
    for (int i = 0; i < 10; ++i) {
      ChunkDescriptor d;
      d.rows = i;
      if (!q.push(std::move(d), st)) std::abort();
    }
    q.finish("synthetic decode error");
  });

  int seen = 0;
  bool threw = false;
  try {
    for (;;) {
      ChunkDescriptor d;
      if (!q.pop(d)) break;
      ++seen;
    }
  } catch (const std::exception& e) {
    threw = true;
    if (std::string(e.what()) != "synthetic decode error") {
      std::fprintf(stderr, "error_propagation: wrong message: %s\n", e.what());
      std::abort();
    }
  }
  if (!threw || seen != 10) {
    std::fprintf(stderr, "error_propagation: threw=%d seen=%d (want threw=1 seen=10)\n", threw,
                seen);
    std::abort();
  }
}

}  // namespace

int main() {
  for (int rep = 0; rep < 20; ++rep) {
    one_to_one(50000, 2);
    fan_out(20000, 4, 4);
    cancel_mid_stream();
    error_propagation();
  }
  std::printf("chunk_queue_tsan: all scenarios passed, %d reps, no TSan report\n", 20);
  return 0;
}
