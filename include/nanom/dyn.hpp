// nanom/dyn.hpp — parsers composed at RUN TIME (layout read from a spec, a schema,
// a config file, …): a cheap type-erased parser handle plus combinators over
// runtime-length collections of parsers.
//
//   nm::dyn<T>                         type-erased (input) -> result<T>; any parser converts to it
//   nm::alt(range)                     first success over a runtime list (nom 8's alt([..]))
//   nm::seq(range) / nm::seq_fold(..)  every parser of a runtime list, in order
//   nm::length_fold(np, p, init, f)    count prefix, then that many p, folded (no vector)
//   nm::dispatch(key, arms[, other])   parse a key, jump to its arm (tag -> parser table)
//   nm::recursive<T>(build)            tie a recursive runtime grammar without leaking a cycle
//
// Everything here composes with the static combinators of nom.hpp in both
// directions: a dyn<T> is a Parser, and every Parser converts to a dyn<T>.
//
// Design (see docs/RUNTIME_COMPOSE.md for the measurements behind it):
//  * dyn<T> is two words: a function pointer and a pointer to an immutable,
//    heap-allocated node holding the concrete parser. Copies bump a NON-atomic
//    intrusive refcount (like Rust's Rc<dyn Fn>); calling never touches it.
//    Stateless parsers (nm::u8, nm::be_u16, captureless lambdas …) need no node.
//  * Calling is ONE indirect call through a thin convention,
//        bool fn(const void* node, input& in, T* out, error* err)
//    that writes the value / the error into caller-provided storage. A dyn
//    calling a dyn (the runtime combinators below calling their children)
//    never materializes an nm::result; only the outermost operator() does.
//  * The runtime combinators return small static parser objects that share
//    their (immutable) child list through the same refcount, so they are cheap
//    to copy, inline into static code, and convert to dyn<T> with no extra hop.
//
// Lifetime and threading rules:
//  * A dyn<T> owns (shares) its node; the node owns the parser by value.
//    Building a tree and returning the root keeps every node alive; there is no
//    separate arena or grammar object to keep around.
//  * Refcounts are not atomic: copying / destroying handles that share nodes
//    must not race (build a grammar on one thread). CALLING is const and
//    refcount-free: one grammar may be used concurrently from many threads,
//    provided the leaf parsers themselves are stateless (all of nanom's are).
//  * Values a parser returns may view the input (nm::bytes, string_view) as
//    usual; the grammar's lifetime is unrelated to the data's.
//  * nm::recursive: the `self` handle given to the builder does not own the
//    grammar (that would be a refcount cycle); it is valid while the dyn
//    returned by recursive() (or any copy of it) is alive.
//
// SPDX-License-Identifier: Apache-2.0
#ifndef NANOM_DYN_HPP_INCLUDED
#define NANOM_DYN_HPP_INCLUDED

#include "nom.hpp"

#include <algorithm>
#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <ranges>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

// The thin entry points are tiny forwarding shims; make sure GCC inlines the
// concrete parser into them (it otherwise sometimes keeps a call per layer).
#if defined(__GNUC__) || defined(__clang__)
# define NANOM_DYN_INLINE [[gnu::always_inline]] inline
#else
# define NANOM_DYN_INLINE inline
#endif

namespace nanom {

template <class T> class dyn;

namespace detail {

// ---------------------------------------------------------------------------
// shared immutable nodes: a header + payload, non-atomic intrusive refcount
// ---------------------------------------------------------------------------
struct dyn_node {
  std::size_t refs = 1;
  void (*destroy)(dyn_node*) noexcept = nullptr;
};
template <class X>
struct dyn_box final : dyn_node {
  X value;
  template <class... A>
  explicit dyn_box(A&&... a) : value(std::forward<A>(a)...) {
    destroy = [](dyn_node* n) noexcept { delete static_cast<dyn_box*>(n); };
  }
};

/// Owning handle to a dyn_node (Rc-like; not thread-safe to copy concurrently).
class node_ref {
  dyn_node* n_ = nullptr;
 public:
  node_ref() = default;
  explicit node_ref(dyn_node* n) noexcept : n_(n) {}
  node_ref(const node_ref& o) noexcept : n_(o.n_) { if (n_) ++n_->refs; }
  node_ref(node_ref&& o) noexcept : n_(std::exchange(o.n_, nullptr)) {}
  node_ref& operator=(node_ref o) noexcept { std::swap(n_, o.n_); return *this; }
  ~node_ref() { if (n_ && --n_->refs == 0) n_->destroy(n_); }
  dyn_node* get() const noexcept { return n_; }
  std::size_t use_count() const noexcept { return n_ ? n_->refs : 0; }
};

/// Typed shared pointer to an immutable payload X (the runtime combinators'
/// child lists / dispatch tables). Copying is one non-atomic increment.
template <class X>
class shared {
  node_ref ref_;
 public:
  shared() = default;
  template <class... A>
  static shared make(A&&... a) {
    shared s;
    s.ref_ = node_ref(new dyn_box<X>(std::forward<A>(a)...));
    return s;
  }
  const X& operator*() const noexcept { return static_cast<const dyn_box<X>*>(ref_.get())->value; }
  const X* operator->() const noexcept { return &**this; }
  std::size_t use_count() const noexcept { return ref_.use_count(); }
};

// ---------------------------------------------------------------------------
// uninitialized storage for the thin calling convention
// ---------------------------------------------------------------------------
template <class T>
union slot {
  T v;
  slot() noexcept {}
  ~slot() requires std::is_trivially_destructible_v<T> = default;
  ~slot() {}
  void destroy() noexcept { if constexpr (!std::is_trivially_destructible_v<T>) v.~T(); }
};

/// Has a native thin entry point producing exactly T.
template <class P, class T>
concept thin_parser = requires(const P& p, input& in, T* out, error* err) {
  { p.parse_into(in, out, err) } -> std::same_as<bool>;
};

/// Run any parser in the thin convention: on success construct *out and
/// advance `in`; on failure construct *err (`in` is then unspecified).
template <class T, class P>
NANOM_DYN_INLINE bool call_into(const P& p, input& in, T* out, error* err) {
  if constexpr (thin_parser<P, T>) {
    return p.parse_into(in, out, err);
  } else {
    auto r = p(in);
    if (!r) { std::construct_at(err, r.error()); return false; }
    std::construct_at(out, std::move(r->value));
    in = r->rest;
    return true;
  }
}

/// Build a result<T> from a thin entry point (the Parser-concept face of the
/// static combinator objects below and of dyn<T>).
template <class T, class F>
inline result<T> as_result(input in, F&& thin) {
  slot<T> v;
  slot<error> e;
  if (thin(in, &v.v, &e.v)) {
    result<T> r{done<T>{std::move(v.v), in}};
    v.destroy();
    return r;
  }
  return unexp(e.v);
}

/// Conversion into T that never narrows an arithmetic value silently.
template <class V, class T>
concept lossless_to = std::convertible_to<V, T> &&
    (!(std::is_arithmetic_v<std::remove_cvref_t<V>> && std::is_arithmetic_v<T>) ||
     requires(V&& v) { T{std::forward<V>(v)}; });

inline unexpected<error> no_alternatives(input in) { return make_err(in, "one of the alternatives"); }


}  // namespace detail

// ===========================================================================
// dyn<T> — type-erased parser handle
// ===========================================================================

/// A type-erased parser `(input) -> result<T>`: nanom's Rc<dyn Fn>. Two words,
/// cheap non-atomic copies, one indirect call per invocation. Any parser whose
/// value converts losslessly to T converts implicitly:
///
///     nm::dyn<std::uint64_t> p = nm::be_u16;                       // no allocation
///     nm::dyn<std::uint64_t> q = nm::map(nm::u8, [](auto b) { return b * 2u; });
///
/// A default-constructed dyn is empty; calling it fails with a recoverable error.
template <class T>
class dyn {
 public:
  using value_type = T;
  /// The thin calling convention (see the header comment): construct *out and
  /// advance `in` on success; construct *err on failure (`in` unspecified).
  using thin_fn = bool (*)(const void* self, input& in, T* out, error* err);

  dyn() = default;

  template <Parser P>
    requires(!std::same_as<std::remove_cvref_t<P>, dyn> &&
             detail::lossless_to<parsed_t<P>, T>)
  dyn(P p) {  // NOLINT(google-explicit-constructor): implicit by design
    if constexpr (std::is_empty_v<P> && std::is_default_constructible_v<P>) {
      fn_ = [](const void*, input& in, T* out, error* err) {
        const P stateless{};
        return detail::call_into<T>(stateless, in, out, err);
      };
    } else {
      node_ = detail::node_ref(new detail::dyn_box<P>(std::move(p)));
      fn_ = [](const void* node, input& in, T* out, error* err) {
        const auto& box = *static_cast<const detail::dyn_box<P>*>(static_cast<const detail::dyn_node*>(node));
        return detail::call_into<T>(box.value, in, out, err);
      };
    }
  }

  /// Parser-concept entry point.
  result<T> operator()(input in) const {
    return detail::as_result<T>(in, [this](input& i, T* o, error* e) { return fn_(node_.get(), i, o, e); });
  }
  /// Thin entry point for combinator authors: on success constructs *out (raw
  /// storage) and advances `in`; on failure constructs *err.
  bool parse_into(input& in, T* out, error* err) const { return fn_(node_.get(), in, out, err); }

  /// False for a default-constructed handle.
  explicit operator bool() const noexcept { return fn_ != &empty_fn; }
  /// Number of handles sharing this node (0 for stateless parsers / empty).
  std::size_t use_count() const noexcept { return node_.use_count(); }

 private:
  static bool empty_fn(const void*, input& in, T*, error* err) {
    std::construct_at(err, make_err(in, "a parser (empty nm::dyn called)").error());
    return false;
  }
  thin_fn fn_ = &empty_fn;
  detail::node_ref node_;
};

/// Alias spelled like the rest of the vocabulary.
template <class T> using dyn_parser = dyn<T>;

// ===========================================================================
// runtime-length combinators
// ===========================================================================

namespace detail {

template <class R>
using range_parser_t = std::remove_cvref_t<std::ranges::range_value_t<R>>;

template <class R>
concept parser_range = std::ranges::input_range<R> && Parser<range_parser_t<R>>;

template <class R>
auto to_shared_vector(R&& r) {
  using P = range_parser_t<R>;
  std::vector<P> v;
  if constexpr (std::ranges::sized_range<R>) v.reserve(std::ranges::size(r));
  for (auto&& p : r) v.emplace_back(std::forward<decltype(p)>(p));
  return shared<const std::vector<P>>::make(std::move(v));
}

/// Static parser objects below derive from this to expose the Parser face.
template <class Self, class T>
struct thin_base {
  using value_type = T;
  result<T> operator()(input in) const {
    return as_result<T>(in, [this](input& i, T* o, error* e) {
      return static_cast<const Self*>(this)->parse_into(i, o, e);
    });
  }
};

template <class P>
struct alt_range final : thin_base<alt_range<P>, parsed_t<P>> {
  using V = parsed_t<P>;
  shared<const std::vector<P>> kids;
  bool parse_into(input& in, V* out, error* err) const {
    bool have = false;
    slot<error> tmp;
    for (const P& k : *kids) {
      input cur = in;
      error* e = have ? &tmp.v : err;
      if (call_into<V>(k, cur, out, e)) { in = cur; return true; }
      if (e->kind != errk::err) {  // Failure / Incomplete: stop, propagate
        if (have) *err = *e;
        return false;
      }
      if (have && tmp.v.offset > err->offset) *err = tmp.v;  // keep the furthest error
      have = true;
    }
    if (!have) { std::construct_at(err, no_alternatives(in).error()); return false; }
    if (err->expected[0] == '\0') err->expected = "one of the alternatives";
    return false;
  }
};

template <class P, class Init, class F>
struct seq_fold_range final
    : thin_base<seq_fold_range<P, Init, F>, std::decay_t<std::invoke_result_t<const Init&>>> {
  using V = parsed_t<P>;
  using Acc = std::decay_t<std::invoke_result_t<const Init&>>;
  shared<const std::vector<P>> kids;
  Init init;
  F f;
  bool parse_into(input& in, Acc* out, error* err) const {
    Acc acc = init();
    for (const P& k : *kids) {
      slot<V> v;
      if (!call_into<V>(k, in, &v.v, err)) return false;
      f(acc, std::move(v.v));
      v.destroy();
    }
    std::construct_at(out, std::move(acc));
    return true;
  }
};

template <class Init, bool = std::invocable<const Init&, std::size_t>>
struct init_result { using type = std::decay_t<std::invoke_result_t<const Init&, std::size_t>>; };
template <class Init>
struct init_result<Init, false> { using type = std::decay_t<std::invoke_result_t<const Init&>>; };

template <class N, class P, class Init, class F>
struct length_fold_parser final
    : thin_base<length_fold_parser<N, P, Init, F>, typename init_result<Init>::type> {
  using V = parsed_t<P>;
  using Acc = typename init_result<Init>::type;
  N np;
  P p;
  Init init;
  F f;
  bool parse_into(input& in, Acc* out, error* err) const {
    using C = parsed_t<N>;
    slot<C> c;
    if (!call_into<C>(np, in, &c.v, err)) return false;
    const auto n = static_cast<std::size_t>(c.v);
    c.destroy();
    Acc acc = [&] {
      if constexpr (std::invocable<const Init&, std::size_t>) return init(n);
      else return init();
    }();
    for (std::size_t i = 0; i < n; ++i) {
      slot<V> v;
      const std::byte* before = in.first;
      if (!call_into<V>(p, in, &v.v, err)) return false;
      if (in.first == before) {  // nom's infinite-loop guard; also stops a hostile 2^64 count
        v.destroy();
        std::construct_at(err, make_err(in, "length_fold: element parser must consume input").error());
        return false;
      }
      f(acc, std::move(v.v));
      v.destroy();
    }
    std::construct_at(out, std::move(acc));
    return true;
  }
};

template <class K>
inline constexpr bool byte_key = sizeof(K) == 1 &&
    (std::is_integral_v<K> || std::is_enum_v<K>);

template <class K>
constexpr std::size_t byte_index(K k) noexcept {
  if constexpr (std::is_enum_v<K>) return static_cast<unsigned char>(static_cast<std::underlying_type_t<K>>(k));
  else return static_cast<unsigned char>(k);
}

/// Lookup table built once from the arms: a 256-slot array for 1-byte keys, a
/// dense offset vector for integral keys spanning <= 4096 values, else a
/// sorted vector (binary search). First arm wins on duplicate keys.
template <class KV, class KK, class T>
struct dispatch_table {
  using arm = std::pair<KK, dyn<T>>;
  static constexpr bool byte_keyed = byte_key<KV>;
  std::conditional_t<byte_keyed, std::array<dyn<T>, 256>, std::array<dyn<T>, 0>> byte_tab{};
  std::vector<dyn<T>> dense;  // integral keys: dense[k - lo]
  long long lo = 0;
  std::vector<arm> sorted;    // everything else
  dyn<T> otherwise;
  bool use_dense = false;

  dispatch_table(std::vector<arm> arms, dyn<T> other) : otherwise(std::move(other)) {
    if constexpr (byte_keyed) {
      for (auto& [k, p] : arms) {
        auto& s = byte_tab[byte_index(KV(k))];
        if (!s) s = std::move(p);
      }
      if (otherwise)
        for (auto& s : byte_tab) if (!s) s = otherwise;
    } else {
      if constexpr (std::is_integral_v<KV> && std::is_integral_v<KK>) {
        if (!arms.empty()) {
          auto [mn, mx] = std::ranges::minmax(arms, {}, [](const arm& a) { return static_cast<long long>(a.first); });
          const auto lo_k = static_cast<long long>(mn.first), hi_k = static_cast<long long>(mx.first);
          if (static_cast<unsigned long long>(hi_k - lo_k) < 4096) {
            use_dense = true;
            lo = lo_k;
            dense.resize(static_cast<std::size_t>(hi_k - lo_k) + 1);
            for (auto& [k, p] : arms) {
              auto& s = dense[static_cast<std::size_t>(static_cast<long long>(k) - lo)];
              if (!s) s = std::move(p);
            }
            if (otherwise)
              for (auto& s : dense) if (!s) s = otherwise;
            return;
          }
        }
      }
      std::ranges::stable_sort(arms, [](const arm& a, const arm& b) { return a.first < b.first; });
      auto dup = std::ranges::unique(arms, [](const arm& a, const arm& b) { return !(a.first < b.first) && !(b.first < a.first); });
      arms.erase(dup.begin(), dup.end());
      sorted = std::move(arms);
    }
  }

  const dyn<T>* find(const KV& k) const {
    if constexpr (byte_keyed) {
      return &byte_tab[byte_index(k)];
    } else {
      if constexpr (std::is_integral_v<KV> && std::is_integral_v<KK>) {
        if (use_dense) {
          const auto i = static_cast<unsigned long long>(static_cast<long long>(k) - lo);
          return i < dense.size() ? &dense[static_cast<std::size_t>(i)] : &otherwise;
        }
      }
      auto it = std::ranges::lower_bound(sorted, k, [](const auto& a, const auto& b) { return a < b; },
                                         &arm::first);
      if (it != sorted.end() && !(k < it->first)) return &it->second;
      return &otherwise;
    }
  }
};

template <class K, class KK, class T>
struct dispatch_parser final : thin_base<dispatch_parser<K, KK, T>, T> {
  using KV = parsed_t<K>;
  K key;
  shared<const dispatch_table<KV, KK, T>> table;
  bool parse_into(input& in, T* out, error* err) const {
    const input at = in;
    slot<KV> k;
    if (!call_into<KV>(key, in, &k.v, err)) return false;
    const dyn<T>* arm = table->find(k.v);
    k.destroy();
    if (!*arm) {
      std::construct_at(err, make_err(at, "a known dispatch key").error());
      return false;
    }
    return arm->parse_into(in, out, err);
  }
};

template <class T>
struct recursive_cell { dyn<T> body; };

template <class T>
struct recursive_ref {  // non-owning: points into a recursive_cell kept alive by the root
  const dyn<T>* target;
  bool parse_into(input& in, T* out, error* err) const { return target->parse_into(in, out, err); }
  result<T> operator()(input in) const { return (*target)(in); }
};
template <class T>
struct recursive_root {
  shared<recursive_cell<T>> cell;
  bool parse_into(input& in, T* out, error* err) const { return cell->body.parse_into(in, out, err); }
  result<T> operator()(input in) const { return cell->body(in); }
};

template <class P, class F>
struct thin_map final
    : thin_base<thin_map<P, F>, std::decay_t<std::invoke_result_t<const F&, parsed_t<P>&&>>> {
  using V = parsed_t<P>;
  using U = std::decay_t<std::invoke_result_t<const F&, V&&>>;
  P p;
  F f;
  bool parse_into(input& in, U* out, error* err) const {
    slot<V> v;
    if (!call_into<V>(p, in, &v.v, err)) return false;
    std::construct_at(out, f(std::move(v.v)));
    v.destroy();
    return true;
  }
};

}  // namespace detail

/// map(p, f) over a dyn<T> (or any runtime combinator below): same meaning as
/// nom.hpp's map, but keeps the thin calling convention so that converting the
/// result back to a dyn costs no intermediate nm::result. Selected
/// automatically (more constrained overload).
template <Parser P, class F>
  requires detail::thin_parser<P, parsed_t<P>>
constexpr auto map(P p, F f) {
  return detail::thin_map<P, F>{{}, std::move(p), std::move(f)};
}

/// alt(range) — nom 8's `alt([p1, p2, …])` over a list built at run time: the
/// first parser that succeeds wins; a recoverable error tries the next one;
/// Failure (cut) and Incomplete stop and propagate. When all fail, the error
/// that got furthest is reported (same as the variadic alt); an empty range
/// fails at the input with "one of the alternatives". The elements are copied
/// once into a shared immutable list, so the returned parser is cheap to copy.
template <class R>
  requires detail::parser_range<R>
auto alt(R&& parsers) {
  using P = detail::range_parser_t<R>;
  return detail::alt_range<P>{{}, detail::to_shared_vector(std::forward<R>(parsers))};
}

/// seq_fold(range, init, f) — run every parser of a runtime list in order,
/// folding the values: acc = init(); f(acc&, value) per parser (mutating, like
/// fold_many0). Any error propagates unchanged. An empty range yields init().
template <class R, class Init, class F>
  requires detail::parser_range<R> && std::invocable<const Init&> &&
           std::invocable<const F&, std::decay_t<std::invoke_result_t<const Init&>>&,
                          parsed_t<detail::range_parser_t<R>>&&>
auto seq_fold(R&& parsers, Init init, F f) {
  using P = detail::range_parser_t<R>;
  return detail::seq_fold_range<P, Init, F>{
      {}, detail::to_shared_vector(std::forward<R>(parsers)), std::move(init), std::move(f)};
}

/// seq(range) — run every parser of a runtime list in order and collect the
/// values into a std::vector (the runtime-length counterpart of seq(p...)'s
/// tuple). An empty range yields an empty vector without consuming input.
template <class R>
  requires detail::parser_range<R>
auto seq(R&& parsers) {
  using V = parsed_t<detail::range_parser_t<R>>;
  const std::size_t n = std::ranges::sized_range<R> ? std::size_t(std::ranges::size(parsers)) : 0;
  return seq_fold(std::forward<R>(parsers),
                  [n] { std::vector<V> v; v.reserve(n); return v; },
                  [](std::vector<V>& acc, V&& v) { acc.push_back(std::move(v)); });
}

/// length_fold(np, p, init, f) — np yields a count N, then exactly N runs of p
/// folded into an accumulator (the allocation-free sibling of length_count).
/// init is called as init(N) when it accepts the count, else init(). An element
/// that consumes nothing is an error (nom's infinite-loop guard).
template <Parser N, Parser P, class Init, class F>
  requires std::integral<parsed_t<N>>
constexpr auto length_fold(N np, P p, Init init, F f) {
  return detail::length_fold_parser<N, P, Init, F>{{}, std::move(np), std::move(p), std::move(init), std::move(f)};
}

/// dispatch(key, arms[, otherwise]) — parse a key, then run the arm registered
/// for it (tag byte -> payload parser): the runtime `switch`. `arms` is any
/// range of pair-likes {key, parser}; arm parsers convert to dyn<T>. 1-byte
/// keys use a 256-slot table, compact integral keys a dense table, anything
/// else (strings, wide sparse ints) a sorted table with binary search; the
/// first arm wins on duplicates. An unknown key runs `otherwise` if given, else
/// fails (recoverable) at the key's offset with "a known dispatch key". The
/// key parser's own errors and the arm's errors propagate unchanged.
template <Parser K, std::ranges::input_range R, class D = dyn<parsed_t<std::remove_cvref_t<
              std::tuple_element_t<1, std::ranges::range_value_t<R>>>>>>
  requires Parser<std::remove_cvref_t<std::tuple_element_t<1, std::ranges::range_value_t<R>>>>
auto dispatch(K key, R&& arms, D otherwise = {}) {
  using P = std::remove_cvref_t<std::tuple_element_t<1, std::ranges::range_value_t<R>>>;
  using T = parsed_t<P>;
  using KK = std::remove_cvref_t<std::tuple_element_t<0, std::ranges::range_value_t<R>>>;
  using KV = parsed_t<K>;
  using table = detail::dispatch_table<KV, KK, T>;
  std::vector<typename table::arm> v;
  for (auto&& a : arms) v.emplace_back(std::get<0>(a), dyn<T>(std::get<1>(a)));
  return detail::dispatch_parser<K, KK, T>{
      {}, std::move(key), detail::shared<const table>::make(std::move(v), dyn<T>(std::move(otherwise)))};
}
/// dispatch<T>(key, {{k1, p1}, {k2, p2}, …}) — braced-list form (T explicit).
template <class T, Parser K>
auto dispatch(K key, std::initializer_list<std::pair<parsed_t<K>, dyn<T>>> arms, dyn<T> otherwise = {}) {
  return dispatch(std::move(key), std::vector<std::pair<parsed_t<K>, dyn<T>>>(arms), std::move(otherwise));
}

/// recursive<T>(build) — tie a recursive grammar built at run time. `build`
/// receives a handle to the grammar being defined and returns its body:
///
///     nm::dyn<int> depth = nm::recursive<int>([](nm::dyn<int> self) {   // "((7))" -> 2
///       std::vector<nm::dyn<int>> b{
///           nm::map(nm::delimited(nm::chr('('), self, nm::chr(')')), [](int d) { return d + 1; }),
///           nm::value(0, nm::digit1)};
///       return nm::alt(b);
///     });
///
/// `self` does not own the grammar (no refcount cycle, nothing leaks); it is
/// valid as long as the returned dyn (or any copy of it) is alive.
template <class T, class B>
  requires std::invocable<B&, dyn<T>>
dyn<T> recursive(B&& build) {
  auto cell = detail::shared<detail::recursive_cell<T>>::make();
  auto& body = const_cast<dyn<T>&>(cell->body);  // the one write, before anyone can call it
  body = dyn<T>(std::forward<B>(build)(dyn<T>(detail::recursive_ref<T>{&cell->body})));
  return dyn<T>(detail::recursive_root<T>{std::move(cell)});
}

}  // namespace nanom

#endif  // NANOM_DYN_HPP_INCLUDED
