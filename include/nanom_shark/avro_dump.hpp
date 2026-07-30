// SPDX-License-Identifier: Apache-2.0
#pragma once

// nanom_shark/avro_dump.hpp — dumps every non-empty table to its own Avro Object Container File
// (<stem>_<table>.avro), draining the SAME soa<T> storage the JSON sink draws from -- one decode
// pass, multiple sinks.

#include <nanom_shark/avro_ocf.hpp>
#include <nanom_shark/l2l3_nodes.hpp>

#include <string>
#include <string_view>

namespace nanom_shark {

template <nanom::Described Row>
inline void dump_avro_table(const std::string& path, const nanom::soa<Row>& soa) {
  if (soa.rows() == 0) return;  // matches the existing "no file for an empty table" convention
  AvroOcfWriter<Row> w(path);
  if (!w.ok()) return;
  soa.for_each_chunk([&](const auto& c) { w.write_chunk(c); });
  w.close();
}

// Generic over the decoder's table set: `for_each_table` walks every table every registered
// protocol declared, so a new protocol's tables land in Avro with NO edit here. (The heavier sinks
// in the downstream nanoshark repo -- Parquet, Lance -- now drive this same loop, so all four sinks
// derive their table set from one source of truth and cannot drift apart.) The stem is unchanged:
// <stem>_<table name>.avro, with the table name coming from the protocol's own table_decl<"...">.
template <class Tables>
inline void dump_all_tables_avro(const std::string& stem, const Tables& t) {
  t.for_each_table([&](std::string_view name, const auto& soa) {
    dump_avro_table(stem + "_" + std::string(name) + ".avro", soa);
  });
}

}  // namespace nanom_shark
