# FEATURE PLAN: nanom_shark as a native Wireshark postdissector plugin

Standalone feature plan. Independent of the stacked plans in
`creating-a-comprehensive-pcap-pcapng-idempotent-boole.md`; nothing here depends on the
py_nanom_shark / streaming work.

## Context

**The question:** could compile-time reflection generate Wireshark dissectors mirroring the nanom
parsers, given how closely dissectors and combinator parsers resemble each other?

**The answer: yes, but not by generating anything.** The first framing was Lua codegen. That was
rejected in favour of a native C++ plugin for two decisive reasons:

1. **Codegen reaches the headers, never the grammar.** Reflection can emit a field table, but
   `someip.hpp:106-121,214` (`while (opt + 3 <= opt_end)`, SD option walks, `while (!cur.empty())`),
   the port/ethertype dispatch, and IP defrag are imperative control flow. A generated dissector
   would silently cover only the easy half.
2. **A generated mirror is a circular oracle.** Lua emitted from the same `describe<T>` the decoder
   consumes agrees with the decoder on their *shared* mistakes — it validates the emitter, not the
   parser. A native plugin **calls the real parser**, so there is nothing to drift.

**The payoff** is that nanom_shark's decode becomes visible inside Wireshark/tshark on the same
packets Wireshark dissects natively. As a **postdissector** (runs after the built-ins rather than
replacing them), a single `tshark -T json` run emits both trees, which hands us Wireshark's own
mature dissectors as a genuinely *independent* differential oracle. That is the strongest available
check on the C++ parser and is unreachable from the whole-file NDJSON path tested today.

### Two structural facts make this far cheaper than it looks

Both confirmed by reading the code, not assumed:

- **There is already exactly one layer-emission seam.** Every protocol emits through
  `json->add_layer("gptp.sync", row)` (`gptp.hpp:136-191`; 30 call sites repo-wide) →
  `add_layer_json(name, nanom::to_json(value))` (`json_tree.hpp:37-43`). The value is always a
  `Described` struct, so ONE reflection-driven emitter covers every protocol, exactly as `to_json`
  does today.
- **The layer names are already Wireshark's convention.** `gptp.sync`, `someip.*` — dotted abbrevs,
  which is precisely what `hf_register_info` wants. Not a coincidence to engineer.

### Feasibility — verified in this sandbox, not assumed

| Requirement | Status |
|---|---|
| epan API headers | **`libwireshark-dev` 4.2.2** — 546 `epan/` headers incl. `packet.h`, `proto.h`, `tvbuff.h`, `exceptions.h` |
| Build integration | ships `pkgconfig/wireshark.pc` + `cmake/wireshark/WiresharkConfig.cmake` |
| Runtime for testing | `tshark` 4.2.2 available |
| glib-2.0 dev | already installed |
| Network egress | archive.ubuntu.com reachable (HTTP 206 on a range request) |
| Privileges | root |
| CI parity | GitHub `ubuntu-24.04` runners draw the same noble archive → byte-identical 4.2.2 |

One `apt-get install libwireshark-dev tshark` covers sandbox and CI identically.

> **Packaging trap — put this in the CI comment.** `wireshark-dev` is NOT the package you want: it
> ships codegen tools (asn2wrs/idl2wrs) and exactly ONE header (`config.h`), no `epan/` at all.
> The epan API lives in **`libwireshark-dev`**. Installing the former and concluding that
> out-of-tree plugins are unsupported on Debian/Ubuntu is the natural — and wrong — inference.

## Design

### A. Generalize the sink seam: `SinkHub` → a `LayerSink` concept

`SinkHub` (`packet_visitor.hpp:372-374`) is hardcoded to `std::vector<PacketJson>*`, and
`PacketJson*` is threaded through **29 parameter sites across 9 headers**, including the `Protocol`
concept's `parse(..., PacketJson*)` signature.

Replace with a **concept-constrained template parameter, not a virtual** — matching the standing
"compile-time type-list only, no type erasure / virtuals" decision that protects the ~43.9 ns/pkt hot
path. Today's `if (json) …` nullable-pointer branch already *is* the runtime cost; a concept keeps it
at exactly that and adds nothing.

```cpp
template <class S> concept LayerSink = requires(S& s, std::string_view n, std::string j) {
  s.add_layer_json(n, j);           // PacketJson satisfies this as-is, unchanged
};
```

`Protocol::parse`'s last parameter becomes `auto* sink`. `PacketJson` remains the default sink and
needs no modification.

**Acceptance bar: golden NDJSON byte-identical.** This refactor touches 9 headers and must be
provably output-neutral — the same regression net every prior phase used.

### B. `StreamingDecodeSession::feed_frame()` — the per-frame entry point

A postdissector is handed one frame plus an encapsulation type; it has no EPB wrapper. `feed_epb`
(`streaming.hpp:115-162`) already resolves `link_type` from `iface_link_` and then does the real work
at `:140-162` (frame layer + `nmproto::walk_packet_ext(link_type, pkt, visitor)`).

Extract that tail into a public `feed_frame(nanom::bytes frame, std::uint16_t link_type, …)` and have
`feed_epb` call it — the same "unify, don't fork" discipline used when `run_decode_pass` was
reimplemented on top of the session. The plugin then holds **one session per capture file**, so
defrag state, per-protocol states, and the packet-id counter persist across packets exactly as in a
whole-file pass.

### C. The proto_tree sink — reflection at runtime, not codegen

Wireshark requires every field to be registered **once at startup** as static `hf_register_info[]`
entries; fields cannot be minted per packet. So there are two reflection-driven passes:

- **Registration (once, at `plugin_register`):** reuse the existing
  `tables_of<Decoder>::for_each_table` fold — the same one the Python binding already uses — to
  enumerate every registered table's `Row` type, then `schema_of<Row>()` for its fields. Emit one
  `hf_register_info` per (layer, field) with abbrev `nanom.<layer>.<field>`, and keep a stable
  `(layer, field) → hf index` map.
- **Per packet:** the proto_tree counterpart of `add_layer_json` walks the same schema and issues
  `proto_tree_add_item(...)` per field.

**Prerequisite — close the `schema_field` gap first.** `schema_field` (`schema.hpp:26-34`) carries
`bits` but **erases endianness**: `scalar_kind<typename wire<F>::decoded>()` collapses `be<u32>` and
`le<u32>` to the same `dkind::u32`. Byte offsets live separately in `field_bit_offsets<T>()`.
`proto_tree_add_item` needs `ENC_BIG_ENDIAN`/`ENC_LITTLE_ENDIAN` plus an offset, and bitfields need a
mask derived from bit offset + width.

Fix additively: add endianness + bit offset to `schema_field`, populated in `field_schema<F>()`
(endianness from the `wire<endian_scalar<T,E>>` specialization; offsets zipped in from
`field_bit_offsets<T>()` inside `make_schema_fields`). Backward compatible — `arrow_format` and
`avro_field_json` simply ignore the new members. **Ship as its own small PR**: it is a core-header
change with value independent of this feature.

### D. Build target — `NANOM_BUILD_WIRESHARK_PLUGIN`, default OFF

Follows `NANOM_BUILD_FUZZERS` (`CMakeLists.txt:45`) exactly: default-OFF so `libwireshark-dev` +
glib-2.0 never touch the core build and the README's "no third-party code dependencies" claim stays
true.

- Discover via `pkg-config wireshark`, or `find_package(Wireshark)` using the shipped
  `WiresharkConfig.cmake`.
- Read the ABI version from `pkg-config --modversion wireshark` at configure time — **do not
  hardcode** `plugin_want_major`/`minor`.
- Export `plugin_version`, `plugin_want_major`, `plugin_want_minor`, `plugin_register`.
- Register via `register_postdissector()`.
- Load from `~/.local/lib/wireshark/plugins/4.2/epan/` or `WIRESHARK_PLUGIN_DIR` — no system install
  required to test.

### E. The two hazards that need designing around, not documenting away

1. **longjmp vs. RAII — the sharp one.** epan signals bounds errors with longjmp-based `THROW`
   (`epan/exceptions.h`), and longjmp across C++ frames holding non-trivial destructors is UB. For a
   C++23 RAII-heavy library this is a live correctness risk, not a theoretical one.
   **Firewall:** at plugin entry do ONE `tvb_memcpy`/`tvb_get_ptr` into a wmem buffer *before*
   constructing any C++ object, wrap it as `nanom::bytes`, and run pure nanom with **zero epan calls**
   until parsing completes; emit into the tree only afterwards. Every throwing call then lives
   outside every destructor scope. Symmetrically, no C++ exception may escape into epan — wrap the
   entry point in a catch-all.
2. **ABI pinned to Wireshark's minor version.** `plugin_want_major/minor` must match exactly; a 4.2
   build is *refused* by 4.4. A permanent rebuild-per-release cost, and the one place Lua would have
   won. Currently mitigated because sandbox and `ubuntu-24.04` runners both pin noble's 4.2.2, so dev
   and CI cannot silently diverge — but expect this to need attention whenever the runner image
   moves. State the supported range in the README.

## Open decision — licensing

Wireshark is **GPL-2.0-or-later**; nanom is **Apache-2.0**, which is incompatible with GPL-2.0-*only*
and works only via the "or later" → GPLv3 path. The plugin subdirectory must therefore be
deliberately licensed GPL-2.0-or-later rather than inheriting the repo's Apache-2.0 header, with a
`NOTICE` / `THIRD-PARTY.md` update. Not a blocker, but an explicit choice to make before merging —
**confirm before implementing step 3.**

## Verification

Every step is runnable locally *and* in CI (see the feasibility table above).

1. **Sink refactor (A):** all golden NDJSON fixtures byte-identical; `ctest` green. Non-negotiable —
   the refactor spans 9 headers and must be provably output-neutral.
2. **`schema_field` extension (C):** existing Arrow/Avro schema tests unchanged; new unit test
   asserting a `be<u32>` and an `le<u32>` field now report distinct endianness and correct bit
   offsets.
3. **`feed_frame` (B):** golden fixtures still byte-identical through the `feed_epb` → `feed_frame`
   path, proving the extraction was behaviour-preserving.
4. **Plugin load smoke test:** `tshark -G plugins` lists the plugin; a truncated/malformed-packet
   fixture must not crash tshark (this is what exercises the longjmp firewall).
5. **The differential payoff — the real prize:** one `tshark -T json -r <fixture>` with the plugin
   loaded, diffing the `nanom.*` subtree against Wireshark's own
   `eth.*`/`ip.*`/`udp.*`/`someip.*`/`ptp.*`/`lldp.*` fields on the same packets. Field-name mapping
   is a small hand-written table per protocol.
   **Expect real disagreements on the first run.** Some will be nanom bugs; some will be Wireshark
   interpreting an ambiguous field differently. Triage them before treating any as a CI gate — land
   the job advisory (`continue-on-error: true`) first, exactly as the existing `python-bindings` and
   `clang-tidy` jobs do, and promote to blocking once the diff is understood and clean.

## Sequencing — three independently reviewable PRs

Mirrors how Phases 1-3 and the PR #27-#31 chain were run.

1. **`schema_field` endianness + bit offset** — core, small, useful on its own.
2. **`LayerSink` generalization + `feed_frame`** — core refactor; golden tests are the entire proof.
3. **Plugin target + CI differential job** — all new dependencies land here, behind the OFF option.
   Requires the licensing decision resolved first.

## Non-goals

- Replacing Wireshark's built-in dissectors — the postdissector runs *alongside* them, by design.
- Lua codegen — superseded, for the reasons in Context.
- Dissecting protocols nanom_shark does not already decode.
- A GUI/Wireshark-UI story beyond what the postdissector tree gives for free.
