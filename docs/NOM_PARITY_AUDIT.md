# nom parity audit

**Question this answers:** are nanom's combinators genuinely functional/usable like Rust
nom's, or do some (e.g. `alt`, `flat_map`) only superficially share a name while being
unusable for real dispatch (the concern that triggered this audit: "can `alt`/`flat_map`
actually multiplex a tag byte into differently-shaped rows")?

**Method:** Rust nom 8.0.0 ships a real `tests/` directory (16 files, no published
`examples/` — those are excluded from the crate). Using the copy already cached locally
from `bench/rust_nom`'s `Cargo.lock`
(`~/.cargo/registry/src/index.crates.io-*/nom-8.0.0/tests/`) as ground truth, each test
file's *behavior* was ported to an original C++ program against nanom, compiled under
`-Wall -Wextra -Wpedantic -Werror` with both g++-13 and clang++-18, and — for the
adversarial-input case — run under ASan+UBSan. The consolidated, CI-checked result lives
in `tests/test_nom_parity.cpp` (`ctest -R nanom_nom_parity_tests`).

## Verdict

**`alt` and `flat_map` are not broken.** Both require one common return type across
branches — but so does Rust's own `nom::alt`, for the same reason: a function typed
`impl Fn(I) -> IResult<I, O, E>` has exactly one `O`. Rust code that needs to dispatch a
tag into differently-shaped payloads doesn't fight this — it maps each branch into a
shared enum (`alt((map(parse_a, Msg::A), map(parse_b, Msg::B)))`, using the enum's
tuple-variant constructor as the mapping function). This is confirmed as nom's own
*canonical* pattern by reading its real tests, not assumed:

- `tests/json.rs:129-137` — `json_value` dispatches `null`/bool/string/number/array/object
  via exactly this shape.
- `tests/mp4.rs:281-292` — `box_type` dispatches 6 literal tags + a fallback the same way.
- `tests/mp4.rs:263-275` — and where the *shape itself* varies by a runtime condition
  nom's authors don't reach for `alt` at all — `mvhd_box` is a plain Rust `if`/`else`
  on `input.len()` calling `mvhd32()` or `mvhd64()` directly. This is the same manual
  dispatch nanom's own gPTP example already uses (`switch` on a message-type tag, calling
  a separate per-kind parse function) — independently arrived at, and it's what nom's own
  authors do too, not a workaround for a nanom limitation.

`tests/test_nom_parity.cpp::mp4_parity` and `::json_parity` port both idioms; both pass.
`json_parity` additionally proves the pattern scales to a **recursive** tagged union: a
`std::variant<..., std::vector<JsonValue>, ...>` can hold `std::vector<JsonValue>`
directly inside `JsonValue` itself, since C++17 allows `std::vector<T>` with an
incomplete `T` — the same "no manual indirection wrapper" property Rust gets from `Vec<T>`
being implicitly indirect. Naming each variant's payload constructor once (`Bool`, `Num`,
`Str`, `Array`) makes the `alt`/`map` call sites as terse as Rust's, since a C++ free
function is exactly as first-class as a Rust tuple-variant constructor here.

## `std::variant` vs Rust's enum: no extra friction found

The original worry (paraphrased): is the common-return-type constraint fine for Rust's
`enum` but awkward for C++'s `std::variant`, forcing extra conversion functions? Checked
directly — no. `map`'s `f` is unconstrained in its return type (nom.hpp's `map(P, F)`
returns `result<std::decay_t<std::invoke_result_t<const F&, parsed_t<P>&&>>>` — same as
Rust's `map`), so each branch maps to `JsonValue` (a `std::variant` wrapper) exactly as
cheaply as Rust maps each branch to `JsonValue::Bool(...)` etc. The one-line-per-branch
"constructor function" is optional convenience, not a variant-specific tax — Rust code
that inlines a closure instead of naming the tuple-variant constructor pays the same
line, so there's no asymmetry.

## `arithmetic_ast.rs`: explicit recursion, the `Box<T>` analog

Unlike `json.rs`'s implicit container-based recursion, a single recursive *value* (not a
list) needs explicit indirection in both languages: Rust uses `Box<Expr>`, C++ uses
`std::unique_ptr<Expr>`. `arith_ast_parity` in `tests/test_nom_parity.cpp` ports this
directly (`Expr::val`/`Expr::bin` factories, `fold_many0` building the tree
left-associatively) and confirms the resulting shape and evaluated value are correct for
both a flat expression and one with parens.

## Genuine findings (real divergences, now documented)

1. **`fold_many0`/`fold_many1`/`fold_many_m_n` mutate the accumulator by reference**
   (`f(acc&, value)`, return value discarded) — Rust's `nom::multi::fold` is *functional*
   (`fold_fn: FnMut(Acc, O) -> Acc`, returns the new accumulator). Porting
   `tests/arithmetic.rs`'s grammar naively with a Rust-style return-based lambda compiles
   cleanly and silently produces a wrong answer (the accumulator never updates — nanom
   discards the return value). This was confirmed live in `arithmetic_parity`: the fixed
   version's lambda is `[](std::int64_t& acc, auto pr) { acc = ...; }`, mutating `acc` and
   returning nothing. **Was undocumented** in `docs/CHEATSHEET.md` before this audit; now
   noted there next to the `multi` combinator list. This is the single sharpest gotcha
   this audit surfaced — a silent-wrong-answer footgun for anyone porting Rust nom code
   that uses `fold` idiomatically.
2. **Custom/generic error types are architecturally unsupported.** `tests/custom_errors.rs`
   defines `CustomError` implementing `ParseError<&str>` and parameterizes `IResult<&str,
   O, CustomError>` throughout. nanom's `error` (nom.hpp) is a single, fixed,
   allocation-free struct (`kind`, `nctx`, `offset`, `expected`, `needed`, a small
   fixed-size context array, `render()`) — not generic over an error type `E` the way
   Rust's `IResult<I, O, E>` is. This is a deliberate design trade-off (no
   allocation/vtable for error paths), not a bug, and there is no way to port
   `custom_errors.rs` without a core redesign. Out of scope for this audit; noted here as
   a known, permanent gap.
3. **`escaped`/`escaped_transform` don't exist** — confirmed zero matches for "escap"
   (case-insensitive) anywhere in `nom.hpp` or `docs/CHEATSHEET.md`. However, the exact
   behavior tested in `tests/escaped.rs` (consume digits, or a backslash + one escape
   char) is fully composable from existing primitives with no core changes —
   `escaped_parity` in `tests/test_nom_parity.cpp` builds it as
   `recognize(many0(alt(map(digit1, ...), map(preceded(chr('\\'), one_of("\"n\\")), ...))))`
   and confirms both the happy path and the "stop at an invalid escape" edge case. This is
   a missing convenience wrapper, not a structural limitation — a fine target for a future
   `nm::escaped`/`nm::escaped_transform` addition if it comes up in practice, but not
   pursued here since the composed form already works.
4. **`error::needed` is `std::uint32_t`.** `tests/overflow.rs`'s adversarial case (a
   length field that decodes to `u64::MAX`) is correctly handled — nanom returns
   `Err::Incomplete` exactly as nom does, and (confirmed under ASan+UBSan in
   `overflow_parity`) propagates that `Incomplete` *through* a streaming `many0` rather
   than silently stopping with partial results, matching nom's precise semantics that more
   data arriving might still complete the in-progress item. The only imperfection: the
   *diagnostic* "needed N more bytes" text truncates for requests beyond ~4 GiB, since
   `needed` is `uint32_t` not `size_t`. This doesn't affect the incomplete/success
   decision itself (that uses untruncated `size_t` comparisons internally) — only the
   human-readable message for a pathological multi-gigabyte single field. Not fixed here;
   noted as a low-priority cosmetic gap.

## Confirmed non-issues (behaved exactly as nom's tests expect)

- **Stateful/mutating parsers** (`tests/fnmut.rs`): nanom's `Parser` concept requires
  `std::invocable<const P&, input>`. A reference-capturing lambda (`[&counter]`, no
  `mutable`) satisfies this while still mutating the referenced external variable —
  the `operator()` stays `const` because only the *referent*, not the lambda's own
  members, changes. This is the correct C++ analog of Rust's `FnMut` closures; confirmed
  with `static_assert(nm::Parser<decltype(parser)>)` plus a live counter check in
  `fnmut_parity`.
- **`take_while_m_n` + `map_opt`** (`tests/css.rs`): hex-color parsing ports directly;
  `map_res` is documented as an alias of `map_opt` since C++ has no `std::Result` — the
  fallible-conversion combinator works identically to nom's `map_res`.
- **Binary + text float parsing** (`tests/float.rs`): `be_f32`/`le_f32`/`be_f64`/`le_f64`
  match nom's fixed hex-byte fixtures for `12.5` exactly in both endiannesses and widths;
  `double_` (nanom's text-float parser) parses `-2.5e2` correctly.
- **Structured grammars over `fold_many0`** (own fixtures, not nom's exact test data, out
  of IP-safety caution): an INI-style `[section]`/`key=value` config grammar
  (`ini_parity`) and a line-based reader (`multiline_parity`, `tests/multiline.rs`'s
  shape) both work once the mutate-by-reference contract above is understood.

## Files ported (in `tests/test_nom_parity.cpp`, `ctest -R nanom_nom_parity_tests`)

| nom test file | nanom port | what it proves |
|---|---|---|
| `mp4.rs` | `mp4_parity` | `alt`+`map`-into-enum tag dispatch |
| `json.rs` | `json_parity` | same idiom, recursive via `std::vector` |
| `fnmut.rs` | `fnmut_parity` | stateful/mutating parsers via ref-capture |
| `overflow.rs` | `overflow_parity` | adversarial huge-length safety (ASan+UBSan) |
| `arithmetic.rs` | `arithmetic_parity` | `fold_many0` grammar (mutate-by-ref, corrected) |
| `arithmetic_ast.rs` | `arith_ast_parity` | explicit recursion via `unique_ptr` (`Box<T>`) |
| `css.rs` | `css_parity` | `take_while_m_n` + `map_opt` |
| `float.rs` | `float_parity` | binary + text float parsing |
| `ini.rs` | `ini_parity` | structured grammar (own fixtures) |
| `multiline.rs` | `multiline_parity` | line-based reading |
| `escaped.rs` | `escaped_parity` | composed-from-primitives equivalent (combinator absent) |

## Judged out of scope (with reasons)

- **`custom_errors.rs`** — architecturally unsupported (see finding 2 above); not a gap
  that can be closed without redesigning nanom's error type.
- **`expression_ast.rs`** — depends on the separate `nom_language` crate, not nom's core
  combinator surface this audit is about.
- **`issues.rs`** — nom's own internal historical regression tests (bug-number-specific),
  not representative usage patterns.
- **`reborrow_fold.rs`** — tests a Rust-specific reborrow/lifetime idiom with no
  meaningful C++ analog.
- **`ini_str.rs`** — a near-duplicate of `ini.rs` already covered.

## Bottom line

Every meaningfully-distinct behavior in nom's real test suite has a working, verified
nanom equivalent. The one genuine, previously-undocumented functional divergence
(`fold_many0`'s mutate-by-reference contract) is now documented in
`docs/CHEATSHEET.md` and demonstrated correctly in `tests/test_nom_parity.cpp`. The
original worry — that `alt`/`flat_map` can't multiplex a tag into differently-shaped
payloads — does not hold: that's not what Rust's own `alt`/`flat_map` do either; the
map-into-shared-type idiom is nom's own answer to that problem, and it works identically
in nanom, including for recursive types.
