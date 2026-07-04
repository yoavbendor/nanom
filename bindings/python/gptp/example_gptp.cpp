// SPDX-License-Identifier: Apache-2.0
// nanom_gptp — the comprehensive stress test of "add your own C++ nanom parser and use it from
// Python": a full gPTP (IEEE 802.1AS) parser with 8 message kinds, a bit-packed tag byte, TLV walking,
// and a 48-bit timestamp, exposed as 9 zero-copy Arrow tables (one per message kind, plus one for
// Announce's PATH_TRACE entries). All parsing logic lives in gptp_parse.hpp/gptp_rows.hpp; this file is
// just the nanobind wiring — it reuses bindings/python/nanom_arrow.hpp completely unchanged.
#include "gptp_parse.hpp"
#include "gptp_rows.hpp"

#include "../nanom_arrow.hpp"

#include <nanobind/nanobind.h>

#include <cstdlib>
#include <memory>

namespace nb = nanobind;
namespace ng = nmgptp;
namespace nm = nanom;

namespace {

// A capsule-exposing view over one soa<Row> table. `table` is an ALIASED shared_ptr (shares the
// refcount block of the whole GptpTables owner but points at just one of its soa<Row> members), so
// holding it — via any exported Arrow stream's keepalive — keeps the entire parsed GptpTables (and thus
// every table's buffers) alive for as long as any single table is still referenced from Python.
template <class Row>
struct TableView {
  std::shared_ptr<nm::soa<Row>> table;

  std::size_t num_rows() const { return table->rows(); }

  nb::capsule arrow_c_stream(nb::object /*requested_schema*/) const {
    auto* c_stream = static_cast<ArrowArrayStream*>(std::malloc(sizeof(ArrowArrayStream)));
    nm::arrow::export_stream(table, c_stream);
    return nb::capsule(c_stream, "arrow_array_stream", [](void* p) noexcept {
      auto* s = static_cast<ArrowArrayStream*>(p);
      if (s->release) s->release(s);
      std::free(s);
    });
  }
};

template <class Row>
TableView<Row> view_of(const std::shared_ptr<ng::GptpTables>& tables, nm::soa<Row> ng::GptpTables::*member) {
  return TableView<Row>{std::shared_ptr<nm::soa<Row>>(tables, &(tables.get()->*member))};
}

// The parsed-message-tables handle: one property per message kind + one for PATH_TRACE entries.
struct GptpMessages {
  std::shared_ptr<ng::GptpTables> tables;

  TableView<ng::SyncRow>               sync() const { return view_of(tables, &ng::GptpTables::sync); }
  TableView<ng::FollowUpRow>           follow_up() const { return view_of(tables, &ng::GptpTables::follow_up); }
  TableView<ng::DelayReqRow>           delay_req() const { return view_of(tables, &ng::GptpTables::delay_req); }
  TableView<ng::DelayRespRow>          delay_resp() const { return view_of(tables, &ng::GptpTables::delay_resp); }
  TableView<ng::PdelayReqRow>          pdelay_req() const { return view_of(tables, &ng::GptpTables::pdelay_req); }
  TableView<ng::PdelayRespRow>         pdelay_resp() const { return view_of(tables, &ng::GptpTables::pdelay_resp); }
  TableView<ng::PdelayRespFollowUpRow> pdelay_resp_follow_up() const {
    return view_of(tables, &ng::GptpTables::pdelay_resp_follow_up);
  }
  TableView<ng::AnnounceRow>           announce() const { return view_of(tables, &ng::GptpTables::announce); }
  TableView<ng::PathTraceEntryRow>     path_trace() const { return view_of(tables, &ng::GptpTables::path_trace); }
};

GptpMessages parse(nb::bytes pcapng_bytes) {
  auto tables = std::make_shared<ng::GptpTables>(
      ng::parse_pcapng_with_gptp(reinterpret_cast<const std::uint8_t*>(pcapng_bytes.c_str()),
                                  pcapng_bytes.size()));
  return GptpMessages{tables};
}

}  // namespace

NB_MODULE(nanom_gptp, m) {
  m.doc() = "nanom gPTP (IEEE 802.1AS) parser -> 9 zero-copy Arrow tables "
            "(example: adding a comprehensive tagged-union protocol to the nanom Python bindings)";

#define NM_GPTP_BIND_TABLE(PyName, RowT)                                             \
  nb::class_<TableView<ng::RowT>>(m, PyName)                                          \
      .def("__len__", &TableView<ng::RowT>::num_rows)                                 \
      .def_prop_ro("num_rows", &TableView<ng::RowT>::num_rows)                        \
      .def("__arrow_c_stream__", &TableView<ng::RowT>::arrow_c_stream,                \
           nb::arg("requested_schema") = nb::none())

  NM_GPTP_BIND_TABLE("SyncTable", SyncRow);
  NM_GPTP_BIND_TABLE("FollowUpTable", FollowUpRow);
  NM_GPTP_BIND_TABLE("DelayReqTable", DelayReqRow);
  NM_GPTP_BIND_TABLE("DelayRespTable", DelayRespRow);
  NM_GPTP_BIND_TABLE("PdelayReqTable", PdelayReqRow);
  NM_GPTP_BIND_TABLE("PdelayRespTable", PdelayRespRow);
  NM_GPTP_BIND_TABLE("PdelayRespFollowUpTable", PdelayRespFollowUpRow);
  NM_GPTP_BIND_TABLE("AnnounceTable", AnnounceRow);
  NM_GPTP_BIND_TABLE("PathTraceTable", PathTraceEntryRow);
#undef NM_GPTP_BIND_TABLE

  nb::class_<GptpMessages>(m, "GptpMessages")
      .def_prop_ro("sync", &GptpMessages::sync)
      .def_prop_ro("follow_up", &GptpMessages::follow_up)
      .def_prop_ro("delay_req", &GptpMessages::delay_req)
      .def_prop_ro("delay_resp", &GptpMessages::delay_resp)
      .def_prop_ro("pdelay_req", &GptpMessages::pdelay_req)
      .def_prop_ro("pdelay_resp", &GptpMessages::pdelay_resp)
      .def_prop_ro("pdelay_resp_follow_up", &GptpMessages::pdelay_resp_follow_up)
      .def_prop_ro("announce", &GptpMessages::announce)
      .def_prop_ro("path_trace", &GptpMessages::path_trace);

  m.def("parse", &parse, nb::arg("pcapng_bytes"),
        "Parse a pcapng capture containing gPTP-over-Ethernet frames (ethertype 0x88F7) and return a "
        "GptpMessages handle with one zero-copy Arrow table per message kind.");
}
