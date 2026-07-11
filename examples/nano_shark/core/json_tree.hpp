// SPDX-License-Identifier: Apache-2.0
#pragma once

// nano_shark/core/json_tree.hpp — a tshark `-T json`-shaped nested JSON tree for one packet.
//
// tshark's own `-T json` output is, per packet, {"_index":N,"_source":{"layers":{<proto>:{...},...}}}
// with protocol keys in decode order and a layer name repeated (VLAN stacking, IPv6 extension-header
// chains, LLDP TLVs, SRv6 segments, SOME/IP SD entries, ...) promoted to a JSON array on the second
// occurrence. This reuses nanom's existing nm::to_json<T>() verbatim for each layer's body — no new
// per-field emitter is needed for the common case, since walk_packet_ext already hands callbacks a
// fully materialized (not lazily-viewed) struct value.
//
// Scope note: field keys inside each layer stay as the struct's own bare field names ("dst",
// "ethertype") rather than tshark's fully-prefixed "eth.dst" global keys. Re-prefixing every field
// would require a hand-authored per-protocol name table -- exactly the kind of duplicated,
// hand-maintained schema this project avoids everywhere else. This sink matches tshark's SHAPE
// (envelope, nesting, decode order, repeated-layer array promotion), not its exact key spelling.

#include <nanom/nanom.hpp>

#include "node_row.hpp"

#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace nano_shark {

class PacketJson {
 public:
  explicit PacketJson(packet_id_t pid) : pid_(pid) {}

  // Reuses nm::to_json<T>() for the layer body. A second call with the same layer_name promotes
  // that layer from a JSON object to a JSON array (see add_layer_json for the promotion rule).
  template <nanom::Described T>
  void add_layer(std::string_view layer_name, const T& value) {
    add_layer_json(layer_name, nanom::to_json(value));
  }

  // Same promotion rule, for sinks (LLDP TLVs, SRv6 segments, ...) that build their own JSON body
  // by hand rather than through nm::to_json (see core/lldp.hpp in a later phase).
  void add_layer_json(std::string_view layer_name, std::string body_json) {
    for (Layer& l : layers_) {
      if (l.name == layer_name) {
        if (!l.is_array) {
          l.value = "[" + l.value + "]";
          l.is_array = true;
        }
        l.value.insert(l.value.size() - 1, "," + body_json);
        return;
      }
    }
    layers_.push_back(Layer{std::string(layer_name), std::move(body_json), false});
  }

  bool empty() const { return layers_.empty(); }
  packet_id_t packet_id() const { return pid_; }

  // {"_index":N,"_source":{"layers":{...}}} -- the tshark -T json per-packet envelope.
  std::string to_json() const {
    std::string out = "{\"_index\":";
    out += std::to_string(pid_);
    out += ",\"_source\":{\"layers\":{";
    bool first = true;
    for (const Layer& l : layers_) {
      if (!first) out += ',';
      first = false;
      out += '"';
      out += l.name;
      out += "\":";
      out += l.value;
    }
    out += "}}}";
    return out;
  }

 private:
  struct Layer {
    std::string name;
    std::string value;   // a JSON object, or (after promotion) a JSON array of objects
    bool        is_array;
  };
  packet_id_t        pid_;
  std::vector<Layer> layers_;
};

// Appends one packet's envelope to `out`: NDJSON (one line each) when array_mode is false, or a
// comma-separated element of a top-level `[...]` array (the caller writes the brackets) when true.
inline void append_packet(std::string& out, const PacketJson& pj, bool array_mode) {
  if (array_mode) {
    if (!out.empty()) out += ',';
    out += pj.to_json();
  } else {
    out += pj.to_json();
    out += '\n';
  }
}

}  // namespace nano_shark
