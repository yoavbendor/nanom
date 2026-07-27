// SPDX-License-Identifier: Apache-2.0
#pragma once

// nanom_shark/l2l3_nodes.hpp — the DEFAULT decoder: which protocols are registered, and therefore
// which tables exist.
//
// This used to be a hand-written `AllTables` struct with one member per table, which is exactly the
// thing Phase 2 removes: `tables_of<decoder<...>>` now DERIVES the table set from the registered
// protocol type list, so adding a protocol adds its tables with no edit here. The Node<> aliases
// for the base L2-L4 walk moved to core_protocols.hpp, next to the table_spec that declares them.

#include <nanom_shark/core_protocols.hpp>
#include <nanom_shark/gptp.hpp>
#include <nanom_shark/lldp.hpp>
#include <nanom_shark/protocol.hpp>
#include <nanom_shark/someip.hpp>

namespace nanom_shark {

// The type list IS the registry. Order matters only in that a dispatch point folds over it in this
// order -- kept matching the old hand-written if-chain (gPTP before LLDP at the Ethernet payload,
// SOME/IP at the L4 payload) so JSON layer order and Avro row order are byte-identical.
//
// Adding a protocol is `decoder<CoreL2L3, Someip, Gptp, Lldp, FooProto>` -- one token, in the ONE
// place a build declares which protocols it wants. A build that wants a different set writes its
// own `decoder<...>` at its own call site and never touches this header (see
// tests/nanom_shark_test_ergonomics.cpp, which does exactly that).
using default_decoder = decoder<CoreL2L3, Someip, Gptp, Lldp>;

/// Every registered protocol's tables, concatenated. `t.get<"eth">()`, `t.get<"someip_sd_entry">()`,
/// `t.for_each_table(f)`.
using AllTables = tables_of<default_decoder>;

/// Per-decode-pass mutable protocol state (gPTP's running message index, ...).
using AllStates = states_of<default_decoder>;

}  // namespace nanom_shark
