# Hot-path layout: `input`, `error`, `result<T>`

When the compiler inlines a whole parser (static composition), the layout of nanom's core structs
hardly matters: SROA turns them into registers. When it can *not* inline, it matters a lot. That
happens with parsers composed at run time (`nm::dyn`, `std::function`, a table of parsers built
from a spec), deep recursion, or with GCC's weaker inliner on large static trees. Then every
parser boundary copies an `input` in and a `result<T>` (holding `done<T>{value, rest}` or an
`error`) out, through memory. This page records the layout and why each piece is the way it is.

## Layout

| struct | before | after | contents now |
|---|---:|---:|---|
| `input` (default, `NANOM_GENERATION=1`) | 48 B | **40 B** | `first`, `last`, `pos` (offset \| streaming bit), `arena`, `gen` |
| `input` (`NANOM_GENERATION=0` / strict) | 32 B | **24 B** | `first`, `last`, `pos` |
| `error` | 88 B | **24 B** | `expected`, `offset`, `needed`, `kind`, `nctx`, `ctx_tag`, `ctx_end` |
| `result<u64>` (default, g++ / `std::expected`) | 96 B | **56 B** | |
| `result<u64>` (default, clang 18 + libstdc++ fallback) | 152 B | **56 B** | |
| `result<u64>` (lean) | 96 B / 136 B | **40 B** | |

### 1. `expected` fallback is a real union

clang 18 with libstdc++ 13 does not get `std::expected` (`__cpp_lib_expected` is gated off), so
nanom used its own stand-in, which was `std::optional<T>` **plus** an `E`. Every successful return
therefore also zero-initialized and copied a whole 88-byte error, and `result<u64>` was 152 bytes.
The stand-in is now a tagged union whose special members are trivial whenever `T`'s and `E`'s
are (C++20 conditionally-trivial members), so it has `std::expected`'s size and copy behaviour.

### 2. `error` keeps its `context()` chain out of line

`error` used to embed `std::array<frame, 4>` (64 bytes). `result<T>` is sized
`max(done<T>, error)`, so that array taxed every successful return, and every failing boundary
(`alt` backtracking) copied it. Now `context()` writes its frame into a fixed **per-thread ring**
of 256 frames (`detail::context_log`), and the error only records where its frames are
(`nctx`, `ctx_tag` = which thread's ring, `ctx_end` = position). `error::frames()` copies the chain
out as a `context_chain`, and `render()` prints it exactly as before.

The trade-off is spelled out in the `error` doc comment. The chain must be read (render it, or
copy it with `frames()`) **on the producing thread**, before about 256 more `context()` frames are
recorded there. If it is not, `frames().expired` is set and `render()` says the chain is no longer
available. It never prints a wrong chain: the thread tag and the ring position are checked. The
failure path still never allocates. `kind`, `offset`, `expected` and `needed` are always exact.
Errors stay trivially copyable.

### 3. `input` packs `base` and `live` into one word

`base` (only needed for absolute error offsets) and the `live` streaming flag became one 64-bit
`pos`: bits 0–62 hold `offset()` (`first - base`), bit 63 holds `live()`. `advance(n)` adds `n` to
both `first` and `pos`. `base()` is `first - offset()`. This removes 8 bytes and the odd 1-byte
field.

### 4. `input` copies field by field

This is the largest single win for clang. A trivially-copyable 24–48-byte struct is copied with
16-byte vector loads. At a non-inlined boundary the callee has just written `rest` with 8-byte
scalar stores (it computed `first`, and copied the other fields through registers). A 16-byte
load that spans two separate 8-byte stores cannot be store-forwarded, so it stalls for about
12 cycles, once or twice per boundary. In a runtime-composed tree with tens of boundaries per
message, that was most of clang's time. Measured: 87 → 67 ns/msg with an identical instruction
count. `input` therefore has a user-provided `noexcept` copy constructor and assignment that copy
field by field. The cost is the `std::is_trivially_copyable` property. `input` is still trivially
destructible, and inlined code is unchanged (SROA sees through it). Making `error` copy field-wise
too was measured and did not help, so `error` stays trivially copyable.

Not done (measured or considered):

* **`input` ≤ 16 bytes**, so it travels in two registers like Rust's `&[u8]`. That would need the
  base, streaming and arena metadata to live in a per-parse context outside the cursor, which
  changes `from()` and the ownership model. Out of scope.
* **Dropping `gen` from the generation-mode `input`** (taking the arena's generation when a span
  is created instead of when the input is created) would make it 32 bytes. It was rejected
  because it weakens the stale-buffer guarantee.

## API changes and migration

| before | after |
|---|---|
| `in.base` (field) | `in.base()` |
| `in.live` (field), `in.live = true` | `in.live()`, `in.set_live(true)` / `nm::streaming(in)` |
| `in.first = p` (direct move) | `in.with_range(p, in.last)` / `in.advance(n)` (keeps `offset()` right) |
| `e.ctx[i]`, `e.nctx` loop | `for (auto& f : e.frames())`, or `e.append_context(out)` |
| `std::is_trivially_copyable_v<nm::input>` | false now (see §4) |

`input(first, last, base, live)`, `offset()`, `size()`, `advance()`, `with_range()`, `arena`, `gen`,
`error::{kind, offset, expected, needed, push_context, render}` and every combinator are
unchanged. `seg_input` (segmented.hpp) keeps its fields.

## Measurements

Host: shared 4-core cloud VM (other builds running), g++ 13.3, clang 18.1 (libstdc++ 13, so clang
uses the `expected` fallback), rustc stable with LTO, nom 8. **Ir** = callgrind instructions per
message, computed as Ir(3 reps) − Ir(1 rep) over 50k messages. It is exact and immune to load, so
it is the primary metric. **ns** = best of 5 runs over 1M messages. Expect ±5–10% noise.
"Before" is `main` a9d2535 (plus agent #1's `dyn.hpp` for the `nm::dyn` rows), "after" is this
layout. All builds use `-O2` unless noted. Every row prints the same hash (`a6340ce4bc20a2df` on
the 1M-message file).

### Runtime-composed parsers

`bench/runtime_compose_bench.cpp` is an `nm::dyn` tree built from a spec at run time.
`runtime_compose_static.cpp` is the same layout composed statically. The `std::function` tree is a
hand-rolled `std::function<result<u64>(input)>` per node, the most naive erasure. Rust nom 8
(`Rc<dyn Fn>`): **420 Ir, ~49 ns**.

| parser | profile | g++ Ir before → after | clang Ir before → after | g++ ns before → after | clang ns before → after |
|---|---|---:|---:|---:|---:|
| `nm::dyn` tree | default | 585 → **499** | 387 → **359** | 77 → **47** | 47 → **40** |
| `nm::dyn` tree | strict | 502 → **440** | 364 → **343** | 69 → **46** | 46 → **41** |
| static nanom | default | 557 → **361** | 178 → **129** | 133 → **39** | 24 → **22** |
| static nanom | strict | 427 → **290** | 157 → **129** | 91 → **36** | 22 → **22** |
| `std::function` tree | default | 755 → **559** | 650 → **500** | 135 → **64** | 118 → **67** |
| `std::function` tree | generation off | 632 → **462** | 541 → **418** | 150 → **61** | 107 → **61** |
| bool-returning erased wrapper over `std::function` layout | default | 801 → **703** | 592 → **460** | | |
| static composition of the same layout (`st.cpp`) | default | 529 → **392** | 115 → 126 | 116 → **46** | 26 → 26 |

* With clang, the `nm::dyn` tree now runs **15% fewer instructions than Rust nom** and is about 20%
  faster. With g++ it went from 1.6× Rust's time to parity.
* g++ was the weak spot. Its static build was 5× slower than clang's and is now within 1.8×, at
  about 40 ns per message. Most of that comes from `error` no longer being 88 bytes (g++ did not
  scalarize the big `expected`) and from the smaller `input`.
* The one instruction regression is clang `st.cpp` (+10 Ir). It comes from the `expected` union and
  has no measurable time cost. `runtime_compose_static` on clang improved instead (178 → 129).
* The store-forwarding stall in §4 shows up as clang rows that are slower than their instruction
  count suggests. Before the field-wise copy, the `std::function` tree took 87 ns at 420 Ir. After,
  it took 67 ns.

### Statically composed benches (no regressions)

`-O3`, Ir from callgrind. The streaming pcapng bench uses the 224-packet SRL capture. Rust nom
(equal work, `rust_nom_bench … min`) measures **~82 ns/pkt** on the same host and run.

| bench | g++ Ir before → after | clang Ir before → after | g++ ns before → after | clang ns before → after |
|---|---:|---:|---:|---:|
| streaming_pcapng, full profile (per pkt) | 11710 → 11616 | 12388 → 12348 | 81.5 → 81.0 | 82.8 → 82.1 |
| streaming_pcapng, minimal profile (per pkt) | 11627 → 12228 | 12126 → 12040 | 81.1 → 80.8 | 82.4 → 82.5 |
| parse_bench `strct<>` walk (ns/pkt) | | | 83.2 → **54.5** | 50.2 → 51.6 |
| parse_bench `overlay<>` walk (ns/pkt) | | | 18.1 → 18.1 | 32.6 → 32.1 |
| parse_bench, both walks (Ir/pkt) | 475 → 418 | 1435 → 1415 | | |
| thrift_bench 100×50 footer (Ir per rep, M) | 64.74 → 64.84 | 65.43 → 65.62 | validate 2.86 → 3.09 ms | validate 2.60 → 2.55 ms |

pcapng and thrift are flat within noise. Thrift Ir moves by less than 0.3%. pcapng minimal on g++
runs 5% more instructions but takes the same time. The Thrift and protobuf codecs run on raw pointers and touch
`input` only at entry and exit. pcapng is dominated by hashing the option bytes. parse_bench
`strct<>` on g++ is 35% faster.
