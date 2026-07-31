// SPDX-License-Identifier: Apache-2.0
// nanom_shark (Python) — the whole nanom_shark decode pass, exposed to Python as a set of zero-copy
// Arrow streams.
//
// The point of this binding, and the reason it is so short: it contains NO per-protocol and NO
// per-table code at all. `nanom_shark::table_set::for_each_table` is a compile-time fold over every
// table `default_decoder` registers (24 today), and Arrow's C Data Interface is a runtime,
// type-erased description of schema + buffers. So the fold runs ONCE, inside C++, at parse time, and
// collapses 24 distinct C++ Row types into 24 runtime instances of ONE nanobind class (`Table`).
// Registering a 25th table in `default_decoder` needs zero new lines here — it just shows up as one
// more entry in `DecodeResult.tables`.
//
// Zero-copy: each `Table` hands Python an ArrowArrayStream whose batches point straight into the
// soa<Row> chunk buffers; the owning `AllTables` aggregate is kept alive by the shared_ptr every
// exported batch carries.
#include "nanom_arrow.hpp"

#include <nanom_shark/decode_pass.hpp>

#include <nanobind/nanobind.h>
#include <nanobind/stl/optional.h>
#include <nanobind/stl/string.h>
#include <nanobind/stl/vector.h>

#include <cstdint>
#include <cstdlib>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace nb = nanobind;
namespace nm = nanom;
namespace ns = nanom_shark;

namespace {

// ---- the ONE bound table class, reused for every table regardless of its C++ Row type ----------
//
// `build` is the type-erasure boundary: it is created inside the `for_each_table` fold below, where
// the concrete `Row` is still statically known, and captures (a) the owning shared_ptr to the whole
// `AllTables` aggregate and (b) a pointer to that one `soa<Row>` sub-object. `table_set` privately
// inherits one fixed slot per table, so that sub-object address is stable for the aggregate's entire
// lifetime — no reallocation, no moves.
struct Table {
  std::string                             name;
  std::int64_t                            rows = 0;
  std::function<void(ArrowArrayStream*)>  build;

  std::size_t num_rows() const { return static_cast<std::size_t>(rows); }

  // Arrow PyCapsule protocol. A FRESH stream is built on every call, deliberately:
  // ArrowArrayStream::get_next() is stateful (export_state carries a `next` chunk cursor), so a
  // stream cached at construction time would be exhausted by the first importer and hand the second
  // one an empty table. `pa.table(t); pa.table(t)` must both return the full table.
  nb::capsule arrow_c_stream(nb::object /*requested_schema*/) const {
    auto* c_stream = static_cast<ArrowArrayStream*>(std::malloc(sizeof(ArrowArrayStream)));
    if (!c_stream) throw std::bad_alloc();
    build(c_stream);
    return nb::capsule(c_stream, "arrow_array_stream", [](void* p) noexcept {
      auto* s = static_cast<ArrowArrayStream*>(p);
      if (s->release) s->release(s);
      std::free(s);
    });
  }

  std::string repr() const {
    return "<nanom_shark.Table '" + name + "' rows=" + std::to_string(rows) + ">";
  }
};

// ---- the result of one decode pass: the owning tables + one Table handle per declared table ------
struct DecodeResult {
  std::shared_ptr<ns::AllTables> tables;
  std::vector<Table>             handles;

  nb::dict table_dict() const {
    nb::dict d;
    for (const Table& h : handles) d[nb::str(h.name.c_str())] = nb::cast(h);
    return d;
  }
  std::vector<std::string> table_names() const {
    std::vector<std::string> v;
    v.reserve(handles.size());
    for (const Table& h : handles) v.push_back(h.name);
    return v;
  }
  // Only the tables that actually got rows — the usual starting point interactively, since a typical
  // capture leaves most of the 24 empty.
  nb::dict non_empty() const {
    nb::dict d;
    for (const Table& h : handles)
      if (h.rows > 0) d[nb::str(h.name.c_str())] = nb::cast(h);
    return d;
  }
  const Table& at(const std::string& name) const {
    for (const Table& h : handles)
      if (h.name == name) return h;
    throw nb::key_error(name.c_str());
  }
  bool contains(const std::string& name) const {
    for (const Table& h : handles)
      if (h.name == name) return true;
    return false;
  }
  std::size_t size() const { return handles.size(); }
  std::size_t total_rows() const {
    std::size_t n = 0;
    for (const Table& h : handles) n += static_cast<std::size_t>(h.rows);
    return n;
  }
};

DecodeResult parse(nb::bytes capture,
                   std::optional<std::vector<std::uint16_t>> someip_ports,
                   std::optional<std::vector<std::uint16_t>> someip_tlv_ports) {
  // Same wiring as apps/nanom_shark_cli.cpp, minus the JSON/Avro sinks.
  auto tables = std::make_shared<ns::AllTables>();
  ns::SinkHub sink{nullptr};  // no PacketJson collection: Arrow is the only sink here
  ns::DecodeOptions opts{};
  if (someip_ports && !someip_ports->empty()) opts.someip_ports = *someip_ports;
  if (someip_tlv_ports) {
    opts.someip_tlv_ports = *someip_tlv_ports;
    // --someip-tlv-port implies --someip-port, exactly as the CLI does.
    for (std::uint16_t p : *someip_tlv_ports) {
      bool known = false;
      for (std::uint16_t q : opts.someip_ports) known = known || (q == p);
      if (!known) opts.someip_ports.push_back(p);
    }
  }

  const nm::bytes file(reinterpret_cast<const std::byte*>(capture.c_str()), capture.size());
  std::string error;
  bool ok = false;
  {
    // The decode pass touches no Python state at all; `capture` (and therefore `file`) is kept alive
    // by the argument itself for the whole call.
    nb::gil_scoped_release unlock;
    ok = ns::run_decode_pass(file, *tables, sink, opts, error);
  }
  if (!ok) throw std::runtime_error(error);

  DecodeResult result;
  result.tables = tables;
  std::shared_ptr<const void> keepalive = tables;

  // THE fold. This is the only place a per-Row type exists; everything downstream is type-erased.
  tables->for_each_table([&](std::string_view name, const auto& soa) {
    using SoaType = std::remove_cvref_t<decltype(soa)>;
    const SoaType* table = &soa;  // stable for the aggregate's lifetime (fixed table_set slots)
    Table h;
    h.name.assign(name);
    h.rows = static_cast<std::int64_t>(soa.rows());
    h.build = [table, keepalive](ArrowArrayStream* out) {
      nm::arrow::export_stream(*table, keepalive, out);  // const-ref + keepalive overload
    };
    result.handles.push_back(std::move(h));
  });
  return result;
}

}  // namespace

NB_MODULE(nanom_shark, m) {
  m.doc() =
      "nanom_shark: decode a pcap/pcapng capture end to end (Ethernet/VLAN/IPv4+defrag/IPv6+ext "
      "headers/TCP/UDP/SOME/IP/gPTP/LLDP) and hand Python every resulting table as a zero-copy "
      "Arrow stream.";

  nb::class_<Table>(m, "Table",
                    "One decoded table. Import with pa.table(t) / pl.from_arrow(t) (zero-copy); a "
                    "fresh Arrow stream is produced per import, so re-importing is safe.")
      .def_ro("name", &Table::name)
      .def("__len__", &Table::num_rows)
      .def_prop_ro("num_rows", &Table::num_rows)
      .def("__repr__", &Table::repr)
      .def("__arrow_c_stream__", &Table::arrow_c_stream, nb::arg("requested_schema") = nb::none(),
           "Arrow PyCapsule protocol: import with pa.table(t) / pl.from_arrow(t) (zero-copy).");

  nb::class_<DecodeResult>(m, "DecodeResult",
                           "The result of one decode pass: every table declared by the decoder, "
                           "keyed by name. Keeps the decoded data alive.")
      .def_prop_ro("tables", &DecodeResult::table_dict, "dict[str, Table] — all declared tables.")
      .def_prop_ro("non_empty", &DecodeResult::non_empty,
                   "dict[str, Table] — only the tables with rows > 0.")
      .def_prop_ro("table_names", &DecodeResult::table_names)
      .def_prop_ro("total_rows", &DecodeResult::total_rows)
      .def("__len__", &DecodeResult::size)
      .def("__getitem__", &DecodeResult::at, nb::arg("name"), nb::rv_policy::copy)
      .def("__contains__", &DecodeResult::contains, nb::arg("name"));

  m.def("parse", &parse, nb::arg("capture_bytes"), nb::arg("someip_ports") = nb::none(),
        nb::arg("someip_tlv_ports") = nb::none(),
        "Decode pcap/pcapng bytes in one pass and return a DecodeResult.\n\n"
        "someip_ports: UDP ports to attempt a SOME/IP parse on (default: {30490}).\n"
        "someip_tlv_ports: which of those carry the TLV serialization (implies someip_ports).");

  m.attr("table_count") = int(ns::AllTables::table_count);
}
