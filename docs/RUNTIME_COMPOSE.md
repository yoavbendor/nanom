# Parsers composed at run time: `nm::dyn` vs Rust nom

nanom's combinators are templates: the whole parser is one type, and the compiler sees all of it.
Sometimes the layout is not known when you build. It is read at run time from a schema, a
config file or a protocol description, and only the *parts* are known in advance. That needs
type erasure. Rust nom programs reach for `Rc<dyn Fn>` / `Box<dyn Parser>`. nanom's answer is
[`include/nanom/dyn.hpp`](../include/nanom/dyn.hpp), which the umbrella `nanom.hpp` includes.

## The API

| | signature | nom 8 |
|---|---|---|
| erased parser | `nm::dyn<T>` (alias `nm::dyn_parser<T>`): `(input) -> result<T>`, two words, implicit from any parser whose value converts to `T` without narrowing | `Rc<dyn Fn>` / `Box<dyn Parser>` |
| runtime alt | `alt(range)`: the first parser that succeeds wins. A recoverable error tries the next parser. Failure and Incomplete stop the alt. When every parser fails, it reports the error that got furthest. An empty range fails at the input. | `alt([p1, p2, …])` (array/slice) |
| runtime sequence | `seq(range)` → `std::vector<T>`; `seq_fold(range, init, f)` → accumulator | — (nom has none) |
| counted fold | `length_fold(np, p, init, f)`: `np` gives N, then N runs of `p`, folded into an accumulator. `init(N)` or `init()`. An element that consumes nothing is an error. | `length_count` + `fold` |
| dispatch | `dispatch(key, arms[, otherwise])`: arms is a range of `{key, parser}` pairs; also `dispatch<T>(key, {{k, p}, …})`. An unknown key without `otherwise` gives a recoverable error at the key's offset. | `switch!` (nom ≤ 6), winnow `dispatch!` |
| recursion | `recursive<T>([](nm::dyn<T> self) { return …self…; })` | closures / fn recursion |

`map` over a `dyn` (or over any of the objects above) picks a more-constrained overload that keeps the
thin calling convention (below). The meaning is the same as `nom.hpp`'s `map`.

The showcase is [`bench/runtime_compose_bench.cpp`](../bench/runtime_compose_bench.cpp). The whole
spec→parser translator is about 40 lines:

```cpp
nm::dyn<H> node() {
  const std::string n = name();
  if (n == "u8")    return nm::u8;                       // widened to H; stateless: no allocation
  if (n == "str8")  return nm::map(nm::length_data(nm::u8), hash_bytes);
  ...
  if (n == "seq") return nm::seq_fold(list(), [] { return H(0x5e9); }, mix_into);
  if (n == "rep") { nm::dyn<H> item = node(); eat(')');
    return nm::length_fold(nm::u8, item, [](std::size_t c) { return mix(0x52e9, c); }, mix_into); }
  if (n == "alt") { auto kids = list();
    for (std::size_t i = 0; i < kids.size(); ++i) kids[i] = nm::map(kids[i], [i](H v) { return mix(i, v); });
    return nm::alt(kids); }
  if (n == "tag") { std::vector<std::pair<std::uint8_t, nm::dyn<H>>> arms; ...
    return nm::dispatch(nm::u8, arms); }
}
```

## Design

* **Handle = function pointer + node pointer.** The node is an immutable heap object that holds
  the concrete parser. Copying a handle bumps a **non-atomic** intrusive refcount, like `Rc`.
  *Calling* never touches the refcount. Stateless parsers (`nm::u8`, `nm::be_u16`, captureless
  lambdas) get no node and no allocation.
* **One indirect call, no `result` in between.** The erased function uses a thin convention:
  `bool fn(const void* node, input& in, T* out, error* err)`. It constructs the value or the
  error in storage the caller provides. A dyn calling a dyn (what `alt`/`seq_fold`/`dispatch`/
  `length_fold`/`map` do with their children) never builds an `nm::result`. Only the outermost
  `operator()` does. Leaf parsers are inlined into their adapter (`[[gnu::always_inline]]`).
* **The runtime combinators return small static objects, not dyns.** They share their child list
  or table through the same refcount. So they are cheap to copy, they inline into static code,
  and they convert to `dyn<T>` without an extra hop.
* **Dispatch tables:** a 256-slot array for 1-byte keys; a dense offset vector for integral keys
  that span ≤ 4096 values; otherwise a sorted vector with binary search, which also handles
  heterogeneous lookups such as `std::string` arms against `string_view` keys. The first arm wins
  on duplicate keys.

**Why not an arena "grammar" object?** It was considered. A non-owning handle into an arena calls
exactly as fast as this design, because a call reads the same two words. But an arena handle cannot
offer `nm::dyn<T> p = nm::map(...)` without naming the arena, and it adds a lifetime rule
(the arena must outlive every handle) for no speed gain. The refcount costs one non-atomic
increment per copy, and copies happen at build time.

### Lifetime and threading rules

* The root `dyn` keeps the whole tree alive. There is nothing else to keep around.
* Refcounts are not atomic. Build (copy and destroy handles of) one grammar on one thread.
  **Calling** is const and refcount-free, so one grammar can serve many threads (tested).
* `recursive<T>`: the `self` handle passed to the builder does not own the grammar, which avoids a
  refcount cycle and a leak. It is valid while the returned dyn or a copy of it is alive.

## Benchmark

Spec: [`bench/runtime_compose_spec.txt`](../bench/runtime_compose_spec.txt). It uses tag
dispatch, seq, rep, alt, lit and u8/u16be/u32le/u64be/str8. The data comes from
[`runtime_compose_gen.py`](../bench/runtime_compose_gen.py) (1M messages, 17.3 MB, seeded).
Three parsers produce the same hash `a6340ce4bc20a2df`:

* `nm_runtime_compose_bench`: nanom, spec read at run time, `nm::dyn` tree.
* `nm_runtime_compose_static`: nanom, the same layout written statically, no erasure.
* `bench/rust_nom` binary `runtime_compose`: Rust nom 8, spec read at run time, `Rc<dyn Fn>` tree.

[`bench/runtime_compose_check.py`](../bench/runtime_compose_check.py) generates the data, **asserts
equal message count and hash**, then prints the timings. A 5000-message run is a ctest
(`bench_smoke_runtime_compose`).

```sh
cmake --build build --target nm_runtime_compose_bench nm_runtime_compose_static
(cd bench/rust_nom && cargo build --release --bin runtime_compose)
python3 bench/runtime_compose_check.py --dyn build/nm_runtime_compose_bench \
    --static build/nm_runtime_compose_static --rust bench/rust_nom/target/release/runtime_compose
```

### Results

Ir/msg is callgrind instructions per message, measured as Ir(2 reps) − Ir(1 rep) on 50k messages.
That makes it exact and immune to load. ns/msg is the best of 7 on 1M messages, on a shared
4-core cloud VM, so it is noisy at about ±5%. All builds use `-O2`, g++ 13.3, clang 18.1 and rustc
stable with LTO. "Default" is nanom's default safety profile (generation tracking on: a 48-byte
`input`). "Lean" is `NANOM_GENERATION=0 NANOM_GUARD_VIEWS=0`, which is the runtime the strict
profile also gets.

| parser | profile | g++ Ir/msg | clang Ir/msg | g++ ns/msg | clang ns/msg |
|---|---|---:|---:|---:|---:|
| previous hand-tuned `std::function` tree | default | 769 | 651 | 108–113 | 97–100 |
| **`nm::dyn` tree** | default | **586** | **387** | **79–83** | **48–49** |
| `nm::dyn` tree | lean | 503 | 364 | 69–72 | 46–48 |
| static nanom (no erasure) | default | 557 | 178 | 135–137 | 24 |
| static nanom (no erasure) | lean | 428 | 157 | 90–96 | 23 |
| Rust nom 8 `Rc<dyn Fn>` tree | — | 420 | | 49 | |

Readings:

* `nm::dyn` runs **24% (g++) and 40% (clang) fewer instructions** than the hand-tuned
  `std::function` version, and it is about 1.3–2× faster in wall time.
* With clang, the runtime-composed nanom parser is **at parity with Rust nom's** (387 vs 420 Ir/msg,
  48 vs 49 ns). The gap to the static clang build (about 2×) is the cost of erasure. Every node is
  an indirect call that the optimizer cannot see through. Rust pays the same cost.
* g++ trails clang throughout. It is worse on the *static* build than on the dyn one: g++ does not
  scalarize nanom's large `result` (an 88-byte `error` inside `std::expected`) across the deep
  inlining, and it copies the 48-byte `input` through the stack at every layer. That is the
  hot-path layout of `input`/`error`/`result` in `nom.hpp`, which is tracked separately. `dyn`'s
  thin convention already avoids most of it for erased calls.
