// SPDX-License-Identifier: Apache-2.0
// segmented.hpp tests, Phase A+B: the seg_input cursor primitives must agree byte-for-byte with
// the contiguous cursor over EVERY segmentation of the same bytes (the exhaustive boundary
// property), and strct_seg/overlay_seg must agree with strct/overlay over every 2-way split of a
// struct's wire bytes (the differential parity property). If these hold, "pay only at the seams"
// is a pure optimization question, not a correctness one.

#include <nanom/nanom.hpp>

#include "../examples/nanotins_parity/nm_protocols.hpp"  // real wire structs (Ethernet/Ipv4/...)

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace nm = nanom;

namespace {

int failures = 0;
#define CHECK(cond)                                                \
  do {                                                              \
    if (!(cond)) {                                                  \
      std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
      ++failures;                                                   \
    }                                                                \
  } while (0)

// A recognizable 64-byte golden buffer (value == index, easy to eyeball on failure).
std::vector<std::byte> golden(std::size_t n = 64) {
  std::vector<std::byte> b(n);
  for (std::size_t i = 0; i < n; ++i) b[i] = std::byte(i);
  return b;
}

// Split `buf` at the given ascending offsets into a part array (empty parts allowed when two
// offsets coincide or an offset sits at 0/size -- exercised deliberately).
std::vector<std::span<const std::byte>> split(std::span<const std::byte> buf,
                                              std::vector<std::size_t> cuts) {
  std::vector<std::span<const std::byte>> parts;
  std::size_t at = 0;
  cuts.push_back(buf.size());
  for (std::size_t c : cuts) {
    parts.push_back(buf.subspan(at, c - at));
    at = c;
  }
  return parts;
}

// ---- cursor primitives vs contiguous, across every 2-way and sampled 3-way split --------------

template <std::size_t N>
void check_gather_at(nm::seg_input in, std::span<const std::byte> buf, std::size_t pos) {
  nm::seg_window<N> w;
  const bool ok = in.gather(w);
  CHECK(ok == (buf.size() - pos >= N));
  if (ok) CHECK(std::memcmp(w.data(), buf.data() + pos, N) == 0);
}

void check_segmentation(std::span<const std::byte> buf, std::vector<std::size_t> cuts) {
  const auto parts = split(buf, std::move(cuts));
  const nm::segments segs{std::span<const std::span<const std::byte>>(parts.data(), parts.size())};
  CHECK(segs.size() == buf.size());

  nm::seg_input in = nm::from(segs);
  CHECK(in.size() == buf.size());
  CHECK(in.offset() == 0);

  // indexed reads from the start
  for (std::size_t i = 0; i < buf.size(); ++i) CHECK(in[i] == std::uint8_t(buf[i]));
  CHECK(!in.safe_at(buf.size()).has_value());
  if (!buf.empty()) CHECK(in.safe_at(buf.size() - 1).has_value());

  // advance to every position; compare remainder semantics + windows + subranges there
  for (std::size_t pos = 0; pos <= buf.size(); ++pos) {
    const nm::seg_input at = in.advance(pos);
    CHECK(at.offset() == pos);
    CHECK(at.size() == buf.size() - pos);
    CHECK(at.empty() == (pos == buf.size()));
    if (pos < buf.size()) {
      CHECK(at[0] == std::uint8_t(buf[pos]));
      CHECK(!at.contiguous().empty());  // the cursor always sits on a non-empty part
    }
    check_gather_at<1>(at, buf, pos);
    check_gather_at<2>(at, buf, pos);
    check_gather_at<4>(at, buf, pos);
    check_gather_at<8>(at, buf, pos);
    check_gather_at<16>(at, buf, pos);
    check_gather_at<20>(at, buf, pos);
    check_gather_at<64>(at, buf, pos);

    // runtime-length gather
    if (buf.size() - pos >= 5) {
      std::array<std::byte, 5> dst{};
      CHECK(at.gather(std::span<std::byte>(dst)));
      CHECK(std::memcmp(dst.data(), buf.data() + pos, 5) == 0);
    }

    // checked_advance bounds
    CHECK(at.checked_advance(buf.size() - pos).has_value());
    CHECK(!at.checked_advance(buf.size() - pos + 1).has_value());

    // subrange: narrow to the next up-to-7 bytes and re-verify the narrowed view's bytes
    const std::size_t n = std::min<std::size_t>(7, buf.size() - pos);
    const auto sub = at.subrange(n);
    CHECK(sub.has_value());
    if (sub) {
      CHECK(sub->size() == n);
      const nm::segments sview = sub->view();
      nm::seg_input      sin   = nm::from(sview);
      for (std::size_t i = 0; i < n; ++i) CHECK(sin[i] == std::uint8_t(buf[pos + i]));
    }
  }
}

void test_cursor_all_splits() {
  const auto buf = golden();
  const std::span<const std::byte> b(buf.data(), buf.size());

  check_segmentation(b, {});  // single part (degenerate == contiguous)
  for (std::size_t c = 0; c <= buf.size(); ++c) check_segmentation(b, {c});  // every 2-way split
  // sampled 3-way splits, including coinciding cuts (an empty middle part)
  for (std::size_t c1 : {std::size_t(0), std::size_t(3), std::size_t(13), std::size_t(32)})
    for (std::size_t c2 : {c1, c1 + 1, std::size_t(33), std::size_t(64)})
      if (c2 >= c1) check_segmentation(b, {c1, c2});
}

void test_empty_and_tiny() {
  // all-empty parts == empty logical buffer
  const std::vector<std::span<const std::byte>> empties(3);
  const nm::segments segs{
      std::span<const std::span<const std::byte>>(empties.data(), empties.size())};
  nm::seg_input in = nm::from(segs);
  CHECK(in.size() == 0);
  CHECK(in.empty());
  CHECK(!in.safe_at(0).has_value());
  nm::seg_window<1> w;
  CHECK(!in.gather(w));

  // 1-byte-per-part
  const auto buf = golden(8);
  std::vector<std::span<const std::byte>> parts;
  for (std::size_t i = 0; i < 8; ++i)
    parts.emplace_back(std::span<const std::byte>(buf.data() + i, 1));
  const nm::segments s8{std::span<const std::span<const std::byte>>(parts.data(), parts.size())};
  nm::seg_input i8 = nm::from(s8);
  nm::seg_window<8> w8;
  CHECK(i8.gather(w8));
  CHECK(!w8.zero_copy());  // must have straddled
  CHECK(std::memcmp(w8.data(), buf.data(), 8) == 0);
}

void test_zero_copy_fastpath() {
  // window inside one part -> pointer INTO the part, no copy
  const auto buf = golden(32);
  const auto parts = split({buf.data(), buf.size()}, {16});
  const nm::segments segs{std::span<const std::span<const std::byte>>(parts.data(), parts.size())};
  nm::seg_input in = nm::from(segs);
  nm::seg_window<16> w;
  CHECK(in.gather(w));
  CHECK(w.zero_copy());
  CHECK(w.data() == buf.data());  // literally the segment memory
  // one byte later the same window size straddles -> stack copy
  nm::seg_window<16> w2;
  CHECK(in.advance(1).gather(w2));
  CHECK(!w2.zero_copy());
}

// ---- strct_seg / overlay_seg parity across every 2-way split of real wire structs -------------

template <class T>
void check_strct_parity(std::span<const std::byte> wire) {
  const std::size_t n = nm::wire_size_v<T>;
  CHECK(wire.size() >= n);
  const auto want = nm::strct<T>()(nm::from(wire));
  CHECK(bool(want));

  for (std::size_t cut = 0; cut <= n; ++cut) {
    const auto parts = split(wire, {cut});
    const nm::segments segs{
        std::span<const std::span<const std::byte>>(parts.data(), parts.size())};
    const auto got = nm::strct_seg<T>()(nm::from(segs));
    CHECK(bool(got));
    if (got && want) {
      CHECK(got->rest.offset() == n);
      // field-for-field equality via to_json (covers every field incl. bit fields/arrays)
      CHECK(nm::to_json(got->value) == nm::to_json(want->value));
    }

    // overlay: zero-copy view iff the whole struct sits in part 0 (cut==0 leaves an empty first
    // part, so the struct then sits in part 1 -- still contiguous)
    const auto v = nm::overlay_seg<T>()(nm::from(segs));
    const bool contiguous_window = (cut == 0) || (cut >= n);
    CHECK(bool(v) == contiguous_window);
    if (v) CHECK(nm::to_json(v->value.to_struct()) == nm::to_json(want->value));
  }

  // incomplete: short buffer reports incomplete-kind parity with the contiguous parser
  if (n >= 2) {
    const auto parts = split(wire.subspan(0, n - 1), {1});
    const nm::segments segs{
        std::span<const std::span<const std::byte>>(parts.data(), parts.size())};
    const auto got = nm::strct_seg<T>()(nm::from(segs));
    const auto want_short = nm::strct<T>()(nm::from(wire.subspan(0, n - 1)));
    CHECK(!got && !want_short);
    if (!got && !want_short) CHECK(got.error().kind == want_short.error().kind);
  }
}

void test_strct_overlay_parity() {
  // 64 bytes of varied wire data covers the largest struct tested here
  std::vector<std::byte> wire(64);
  for (std::size_t i = 0; i < wire.size(); ++i) wire[i] = std::byte((i * 37 + 11) & 0xFF);
  const std::span<const std::byte> w(wire.data(), wire.size());

  check_strct_parity<nmproto::Ethernet>(w);
  check_strct_parity<nmproto::VlanTag>(w);
  check_strct_parity<nmproto::Ipv4>(w);   // bit fields (version/ihl/dscp/ecn/flags/frag_offset)
  check_strct_parity<nmproto::Ipv6>(w);   // 40 bytes, 16-byte address arrays
  check_strct_parity<nmproto::Udp>(w);
  check_strct_parity<nmproto::Tcp>(w);
}

void test_streaming_and_render() {
  const auto buf = golden(4);
  const auto parts = split({buf.data(), buf.size()}, {2});
  const nm::segments segs{std::span<const std::span<const std::byte>>(parts.data(), parts.size())};

  // live cursor reports incomplete (not err) on short parses, same contract as input
  const auto r = nm::strct_seg<nmproto::Ethernet>()(nm::streaming(nm::from(segs)));
  CHECK(!r);
  if (!r) CHECK(r.error().kind == nm::errk::incomplete);
  const auto r2 = nm::strct_seg<nmproto::Ethernet>()(nm::from(segs));
  CHECK(!r2);
  if (!r2) CHECK(r2.error().kind == nm::errk::err);

  // render over segments produces the same message shape (offset + hex window)
  if (!r2) {
    const std::string msg = nm::render(r2.error(), segs);
    CHECK(msg.find("at offset 4") != std::string::npos);
    CHECK(msg.find("00 01 02 03") != std::string::npos);  // the hex window crosses the seam
  }
}

}  // namespace

int main() {
  test_cursor_all_splits();
  test_empty_and_tiny();
  test_zero_copy_fastpath();
  test_strct_overlay_parity();
  test_streaming_and_render();
  if (failures) {
    std::printf("%d failure(s)\n", failures);
    return 1;
  }
  std::printf("nanom_segmented_tests: OK\n");
  return 0;
}
