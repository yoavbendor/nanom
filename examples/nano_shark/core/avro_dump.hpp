// SPDX-License-Identifier: Apache-2.0
#pragma once

// nano_shark/core/avro_dump.hpp — dumps every non-empty AllTables table to its own Avro Object
// Container File (<stem>_<table>.avro), draining the SAME soa<T>/nm::soa<T> storage the JSON sink
// draws from -- one decode pass, multiple sinks.

#include "avro_ocf.hpp"
#include "l2l3_nodes.hpp"

#include <string>

namespace nano_shark {

template <nanom::Described Row>
inline void dump_avro_table(const std::string& path, const nanom::soa<Row>& soa) {
  if (soa.rows() == 0) return;  // matches the existing "no file for an empty table" convention
  AvroOcfWriter<Row> w(path);
  if (!w.ok()) return;
  soa.for_each_chunk([&](const auto& c) { w.write_chunk(c); });
  w.close();
}

inline void dump_all_tables_avro(const std::string& stem, const AllTables& t) {
  dump_avro_table(stem + "_eth.avro", t.eth.soa());
  dump_avro_table(stem + "_vlan.avro", t.vlan.soa());
  dump_avro_table(stem + "_ipv4.avro", t.ipv4.soa());
  dump_avro_table(stem + "_ipv6.avro", t.ipv6.soa());
  dump_avro_table(stem + "_udp.avro", t.udp.soa());
  dump_avro_table(stem + "_tcp.avro", t.tcp.soa());
  dump_avro_table(stem + "_ipv4_frag.avro", t.ipv4_frag.soa());
  dump_avro_table(stem + "_ipv6_frag.avro", t.ipv6_frag.soa());
  dump_avro_table(stem + "_datagram.avro", t.datagram.soa());
  dump_avro_table(stem + "_someip.avro", t.someip.soa());
  dump_avro_table(stem + "_someip_sd_entry.avro", t.someip_sd_entry.soa());
  dump_avro_table(stem + "_someip_sd_option.avro", t.someip_sd_option.soa());
  dump_avro_table(stem + "_someip_tlv.avro", t.someip_tlv.soa());
  dump_avro_table(stem + "_lldp.avro", t.lldp.soa());
  dump_avro_table(stem + "_gptp_sync.avro", t.gptp.sync);
  dump_avro_table(stem + "_gptp_delay_req.avro", t.gptp.delay_req);
  dump_avro_table(stem + "_gptp_pdelay_req.avro", t.gptp.pdelay_req);
  dump_avro_table(stem + "_gptp_pdelay_resp.avro", t.gptp.pdelay_resp);
  dump_avro_table(stem + "_gptp_follow_up.avro", t.gptp.follow_up);
  dump_avro_table(stem + "_gptp_delay_resp.avro", t.gptp.delay_resp);
  dump_avro_table(stem + "_gptp_pdelay_resp_follow_up.avro", t.gptp.pdelay_resp_follow_up);
  dump_avro_table(stem + "_gptp_announce.avro", t.gptp.announce);
  dump_avro_table(stem + "_gptp_path_trace.avro", t.gptp.path_trace);
}

}  // namespace nano_shark
