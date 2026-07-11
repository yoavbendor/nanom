// SPDX-License-Identifier: Apache-2.0

// nano_shark — the textbook nanom network analyzer. Decodes pcap/pcapng end to end (Ethernet,
// VLAN 802.1Q/QinQ, IPv4 with defragmentation, IPv6 with its full extension-header chain incl.
// SRv6, TCP/UDP, SOME/IP incl. Service Discovery, gPTP's all 8 message types, LLDP) in one pass,
// then drains the same in-memory tables into whichever sinks were requested: a tshark `-T
// json`-shaped nested JSON dump (--json / --json-array) and/or a real Avro Object Container File
// per table (--avro) -- both dependency-free. Parquet and Lance sinks live in a separate,
// dedicated repo that vendors this one, since they need heavier external libraries.

#include "../core/avro_dump.hpp"
#include "../core/decode_pass.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

bool read_file(const char* path, std::vector<std::uint8_t>& out) {
  std::FILE* f = std::fopen(path, "rb");
  if (!f) return false;
  std::uint8_t chunk[65536];
  std::size_t n = 0;
  while ((n = std::fread(chunk, 1, sizeof chunk, f)) > 0) out.insert(out.end(), chunk, chunk + n);
  std::fclose(f);
  return true;
}

void usage(const char* argv0) {
  std::fprintf(stderr,
              "usage: %s <input.pcap|pcapng> [--json out.ndjson | --json-array out.json] [--avro out-stem]\n"
              "  --json out.ndjson    : one JSON object per packet, newline-delimited\n"
              "  --json-array out.json: one JSON array of per-packet objects\n"
              "  --avro out-stem      : one <out-stem>_<table>.avro Object Container File per\n"
              "                         non-empty table (eth/ipv4/.../someip/gptp_sync/lldp/...)\n"
              "  (with no sink flag at all, --json is written to stdout; --json and --avro may\n"
              "  both be given, draining the same decode pass into both)\n",
              argv0);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    usage(argv[0]);
    return 2;
  }
  const char* input_path = nullptr;
  const char* json_path = nullptr;
  const char* avro_stem = nullptr;
  bool array_mode = false;
  bool json_requested = false;

  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    if (a == "--json" || a == "--json-array") {
      array_mode = (a == "--json-array");
      json_requested = true;
      if (i + 1 >= argc) {
        std::fprintf(stderr, "nano_shark: %s requires a path\n", a.c_str());
        return 2;
      }
      json_path = argv[++i];
    } else if (a == "--avro") {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "nano_shark: --avro requires a path stem\n");
        return 2;
      }
      avro_stem = argv[++i];
    } else if (!input_path) {
      input_path = argv[i];
    } else {
      std::fprintf(stderr, "nano_shark: unexpected argument '%s'\n", a.c_str());
      usage(argv[0]);
      return 2;
    }
  }
  if (!input_path) {
    usage(argv[0]);
    return 2;
  }
  const bool json_to_stdout = json_requested && !json_path;
  if (!json_requested && !avro_stem) json_requested = true;  // default sink when nothing was requested

  std::vector<std::uint8_t> bytes;
  if (!read_file(input_path, bytes)) {
    std::fprintf(stderr, "nano_shark: cannot open %s\n", input_path);
    return 1;
  }
  const nanom::bytes file(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size());

  nano_shark::AllTables tables;
  std::vector<nano_shark::PacketJson> json_packets;
  nano_shark::SinkHub sink{json_requested ? &json_packets : nullptr};
  nano_shark::DecodeOptions opts{};

  std::string error;
  if (!nano_shark::run_decode_pass(file, tables, sink, opts, error)) {
    std::fprintf(stderr, "nano_shark: %s\n", error.c_str());
    return 1;
  }

  if (json_requested) {
    std::string out;
    if (array_mode) out += '[';
    for (const nano_shark::PacketJson& pj : json_packets) nano_shark::append_packet(out, pj, array_mode);
    if (array_mode) out += ']';

    if (json_to_stdout) {
      std::fwrite(out.data(), 1, out.size(), stdout);
    } else {
      std::FILE* f = std::fopen(json_path, "wb");
      if (!f) {
        std::fprintf(stderr, "nano_shark: cannot open %s for writing\n", json_path);
        return 1;
      }
      std::fwrite(out.data(), 1, out.size(), f);
      std::fclose(f);
    }
  }

  if (avro_stem) nano_shark::dump_all_tables_avro(avro_stem, tables);

  return 0;
}
