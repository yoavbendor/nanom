// SPDX-License-Identifier: Apache-2.0

// dpar_lite — the nanom parity port of nanotins' dpar + lldp examples:
// Dynamic Parser Application Rules. Read a rules file and a capture; for
// every packet whose header fields match a rule, run the rule's parser over
// the selected payload region and tabulate the result (NDJSON rows +
// --stats hit counters).
//
// Same rule grammar and semantics as nanotins dpar:
//   <node>.<field> <op> <value> [&& ...] => <parser> <region> "<label>"
//   op: == < > <= >=          value: decimal or 0x-hex
//   parser: someip_tlv | raw_tlv | oddtlv | lldp
//   region: eth_payload | vlan_payload | udp_payload | tcp_payload | someip_payload
//
// What nanom brings vs the nanotins original:
//   - the rules file itself is parsed with nanom text combinators (the
//     original hand-tokenizes) — same lib for wire and DSL;
//   - <node>.<field> matching needs no hand-maintained field catalog: any
//     field of any described header struct is matchable via reflection;
//   - the TLV payload parsers are nanom combinators (LLDP's packed
//     [type:7][length:9] header is two ubits<> fields, not shift+mask);
//   - rows are described structs: nm::to_json emits them, nm::soa could
//     column-store them — no per-row hand-written dumper.

#include "nm_pcap.hpp"
#include "nm_protocols.hpp"

#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

namespace nm = nanom;
using u8 = std::uint8_t; using u16 = std::uint16_t;
using u32 = std::uint32_t; using u64 = std::uint64_t;

// ---------------------------------------------------------------------------
// generic field access: any field of any described struct, by runtime name
// ---------------------------------------------------------------------------
template <nm::Described T>
std::optional<u64> field_u64(const T& v, std::string_view name) {
  std::optional<u64> out;
  std::apply([&](auto... f) {
    auto one = [&](auto fld) {
      using F = nanom::detail::member_t<decltype(fld)::mem_ptr>;
      using D = typename nanom::detail::wire<F>::decoded;
      if constexpr (std::is_integral_v<D>) {                  // arrays etc. aren't matchable
        if (decltype(fld)::name == name) out = u64(D(v.*(decltype(fld)::mem_ptr)));
      }
    };
    (one(f), ...);
  }, nm::describe<T>::fields());
  return out;
}

// ---------------------------------------------------------------------------
// rules: parsed with nanom text combinators
// ---------------------------------------------------------------------------
enum class Op : u8 { eq, lt, gt, le, ge };

struct Pred  { std::string node, field; Op op; u64 value; };
struct Rule  {
  u32 rule_id = 0;
  std::vector<Pred> preds;
  std::string parser, region, label;
};

static nm::result<u64> p_value(nm::input in) {          // decimal or 0x-hex
  return nm::alt(nm::preceded(nm::tag("0x"), nm::hex<u64>()), nm::dec<u64>())(in);
}
static nm::result<Op> p_op(nm::input in) {
  return nm::alt(nm::value(Op::eq, nm::tag("==")), nm::value(Op::le, nm::tag("<=")),
                 nm::value(Op::ge, nm::tag(">=")), nm::value(Op::lt, nm::tag("<")),
                 nm::value(Op::gt, nm::tag(">")))(in);
}
static nm::result<std::string_view> p_ident(nm::input in) {
  return nm::map(nm::take_while1([](u8 b) {
    return nanom::detail::is_alnum(b) || b == '_';
  }), [](nm::bytes b) { return nm::as_str(b); })(in);
}

// one rule line: preds && ... => parser region "label"
static nm::result<Rule> p_rule(nm::input in) {
  auto ws   = nm::space0;
  auto pred = nm::map(
      nm::seq(nm::preceded(ws, p_ident), nm::preceded(nm::chr('.'), p_ident),
              nm::preceded(ws, p_op), nm::preceded(ws, p_value)),
      [](auto&& t) {
        return Pred{std::string(std::get<0>(t)), std::string(std::get<1>(t)),
                    std::get<2>(t), std::get<3>(t)};
      });
  auto preds = nm::separated_list1(nm::preceded(ws, nm::tag("&&")), pred);
  auto label = nm::delimited(nm::chr('"'),
                             nm::map(nm::take_while([](u8 b) { return b != '"'; }),
                                     [](nm::bytes b) { return std::string(nm::as_str(b)); }),
                             nm::chr('"'));
  auto line = nm::seq(preds, nm::preceded(ws, nm::cut(nm::tag("=>"))),
                      nm::preceded(ws, nm::cut(p_ident)), nm::preceded(ws, nm::cut(p_ident)),
                      nm::preceded(ws, nm::cut(label)));
  auto r = line(in);
  if (!r) return nm::unexp(r.error());
  Rule rule;
  rule.preds  = std::move(std::get<0>(r->value));
  rule.parser = std::string(std::get<2>(r->value));
  rule.region = std::string(std::get<3>(r->value));
  rule.label  = std::move(std::get<4>(r->value));
  return nm::done{std::move(rule), r->rest};
}

static bool load_rules(const std::string& text, std::vector<Rule>& out, std::string& err) {
  std::size_t lineno = 0, start = 0;
  while (start <= text.size()) {
    std::size_t nl = text.find('\n', start);
    std::string_view line(text.data() + start,
                          (nl == std::string::npos ? text.size() : nl) - start);
    start = nl == std::string::npos ? text.size() + 1 : nl + 1;
    ++lineno;
    // strip comments / blank lines
    if (auto h = line.find('#'); h != std::string_view::npos) line = line.substr(0, h);
    while (!line.empty() && (line.back() == ' ' || line.back() == '\t' || line.back() == '\r'))
      line.remove_suffix(1);
    while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) line.remove_prefix(1);
    if (line.empty()) continue;

    nm::input in = nm::from(line);
    auto r = nm::all_consuming(nm::terminated(p_rule, nm::space0))(in);
    if (!r) {
      err = "rules line " + std::to_string(lineno) + ":\n" + r.error().render(in);
      return false;
    }
    r->value.rule_id = u32(out.size());
    out.push_back(std::move(r->value));
  }
  return true;
}

// ---------------------------------------------------------------------------
// per-packet decoded state: last header of each node kind + region anchors
// ---------------------------------------------------------------------------
struct PacketState {
  std::optional<nmproto::Ethernet> eth;
  std::optional<nmproto::VlanTag>  vlan;   // first tag (matches dpar's catalog)
  std::optional<nmproto::Ipv4>     ipv4;
  std::optional<nmproto::Ipv6>     ipv6;
  std::optional<nmproto::Tcp>      tcp;
  std::optional<nmproto::Udp>      udp;
  std::size_t vlan_end = 0;                // offset just after the FIRST vlan tag
  std::size_t l4_payload = 0;              // from WalkResult
  bool        reached_l4 = false;
};

static std::optional<u64> node_field(const PacketState& st, const Pred& p) {
  if (p.node == "eth"  && st.eth)  return field_u64(*st.eth, p.field);
  if (p.node == "vlan" && st.vlan) return field_u64(*st.vlan, p.field);
  if (p.node == "ipv4" && st.ipv4) return field_u64(*st.ipv4, p.field);
  if (p.node == "ipv6" && st.ipv6) return field_u64(*st.ipv6, p.field);
  if (p.node == "tcp"  && st.tcp)  return field_u64(*st.tcp, p.field);
  if (p.node == "udp"  && st.udp)  return field_u64(*st.udp, p.field);
  return std::nullopt;
}
static bool eval(Op op, u64 a, u64 b) {
  switch (op) {
    case Op::eq: return a == b;
    case Op::lt: return a < b;
    case Op::gt: return a > b;
    case Op::le: return a <= b;
    case Op::ge: return a >= b;
  }
  return false;
}

// region -> [begin, end) within the packet; false when the anchor is absent
static bool region_of(const std::string& name, const PacketState& st, nm::bytes pkt,
                      std::size_t& b, std::size_t& e) {
  e = pkt.size();
  if (name == "eth_payload")  { if (!st.eth) return false;  b = nm::wire_size_v<nmproto::Ethernet>; return b <= e; }
  if (name == "vlan_payload") { if (!st.vlan) return false; b = st.vlan_end; return b <= e; }
  if (name == "udp_payload")  { if (!st.udp || !st.reached_l4) return false; b = st.l4_payload; return b <= e; }
  if (name == "tcp_payload")  { if (!st.tcp || !st.reached_l4) return false; b = st.l4_payload; return b <= e; }
  if (name == "someip_payload") {  // SOME/IP header = 16 bytes at the UDP payload; length at +4 covers bytes after +8
    if (!st.udp || !st.reached_l4) return false;
    const std::size_t aoff = st.l4_payload;
    auto len = nm::preceded(nm::take(4), nm::be_u32)(nm::from(pkt).advance(aoff));
    if (!len) return false;
    b = aoff + 16;
    e = std::min<std::size_t>(e, aoff + 8 + len->value);
    return b <= e;
  }
  return false;
}

// ---------------------------------------------------------------------------
// the parser kinds (rows are described structs -> nm::to_json for free)
// ---------------------------------------------------------------------------
struct SomeipTlvRow { u64 packet_id; u32 rule_id; u32 tlv_index; u16 data_id; u8 wire_type; u32 length; };
NANOM_DESCRIBE(SomeipTlvRow, packet_id, rule_id, tlv_index, data_id, wire_type, length);

struct RawTlvRow { u64 packet_id; u32 rule_id; u32 tlv_index; u8 type; u8 length; };
NANOM_DESCRIBE(RawTlvRow, packet_id, rule_id, tlv_index, type, length);

struct OddTlvRow { u64 packet_id; u32 rule_id; u32 elem_index; u16 array_id; u16 elem_size; u16 elem_count; u16 elem_data_id; };
NANOM_DESCRIBE(OddTlvRow, packet_id, rule_id, elem_index, array_id, elem_size, elem_count, elem_data_id);

struct LldpTlvRow {
  u64 packet_id; u32 rule_id; u32 tlv_index; u16 tlv_type; u16 tlv_length;
  u8 subtype; u16 value_offset;
  u16 ttl_seconds; u16 caps_supported; u16 caps_enabled;
  u8 mgmt_addr_subtype; u8 mgmt_iface_subtype; u32 mgmt_iface_number;
  std::array<u8, 32> value_head;
};
NANOM_DESCRIBE(LldpTlvRow, packet_id, rule_id, tlv_index, tlv_type, tlv_length, subtype,
               value_offset, ttl_seconds, caps_supported, caps_enabled, mgmt_addr_subtype,
               mgmt_iface_subtype, mgmt_iface_number, value_head);

// --- SOME/IP TLV member: [wt:3|id:12 tag] + width by wire type -------------
struct someip_tag { nm::ubits<1> rsvd; nm::ubits<3> wire_type; nm::ubits<12> data_id; };
NANOM_DESCRIBE(someip_tag, rsvd, wire_type, data_id);

struct someip_member { u16 data_id; u8 wire_type; nm::bytes value; };

static nm::result<someip_member> p_someip_member(nm::input in) {
  auto tag = nm::strct<someip_tag>()(in);
  if (!tag) return nm::unexp(tag.error());
  const u8 wt = u8(tag->value.wire_type);
  auto value = [&]() -> nm::result<nm::bytes> {
    switch (wt) {
      case 0: return nm::take(1)(tag->rest);
      case 1: return nm::take(2)(tag->rest);
      case 2: return nm::take(4)(tag->rest);
      case 3: return nm::take(8)(tag->rest);
      case 5: return nm::length_data(nm::u8)(tag->rest);
      case 6: return nm::length_data(nm::be_u16)(tag->rest);
      case 7: return nm::length_data(nm::be_u32)(tag->rest);
      default:  // wt 4: length width comes from IDL config — not skippable
        return nm::make_err(tag->rest, "someip wire type 4 (config-dependent width)");
    }
  }();
  if (!value) return nm::unexp(value.error());
  return nm::done{someip_member{tag->value.data_id, wt, value->value}, value->rest};
}

// --- LLDP TLV: [type:7][length:9] + value; End TLV (0) stops the walk -------
struct lldp_hdr { nm::ubits<7> type; nm::ubits<9> length; };
NANOM_DESCRIBE(lldp_hdr, type, length);

struct lldp_tlv { u16 type; u16 length; nm::bytes value; };

static nm::result<lldp_tlv> p_lldp_tlv(nm::input in) {
  return nm::flat_map(nm::verify(nm::strct<lldp_hdr>(), [](const lldp_hdr& h) { return h.type != 0; }),
                      [](lldp_hdr h) {
                        return nm::map(nm::take(h.length), [h](nm::bytes v) {
                          return lldp_tlv{u16(h.type), u16(h.length), v};
                        });
                      })(in);
}

// ---------------------------------------------------------------------------
// tables + dispatch
// ---------------------------------------------------------------------------
struct Tables {
  std::vector<SomeipTlvRow> someip_tlv;
  std::vector<RawTlvRow>    raw_tlv;
  std::vector<OddTlvRow>    oddtlv;
  std::vector<LldpTlvRow>   lldp;
};

static std::size_t run_kind(const std::string& kind, u64 pid, u32 rule_id, nm::bytes region,
                            Tables& tb) {
  nm::input in = nm::from(region);
  std::size_t rows = 0;

  if (kind == "someip_tlv") {
    auto r = nm::many0(p_someip_member)(in);
    if (r) {
      u32 idx = 0;
      for (auto& m : r->value)
        tb.someip_tlv.push_back({pid, rule_id, idx++, m.data_id, m.wire_type, u32(m.value.size())}), ++rows;
    }
  } else if (kind == "raw_tlv") {
    auto tlv = nm::flat_map(nm::pair(nm::u8, nm::u8), [](std::pair<u8, u8> h) {
      return nm::map(nm::take(h.second), [h](nm::bytes) { return h; });
    });
    auto r = nm::many0(tlv)(in);
    if (r) {
      u32 idx = 0;
      for (auto& h : r->value) tb.raw_tlv.push_back({pid, rule_id, idx++, h.first, h.second}), ++rows;
    }
  } else if (kind == "oddtlv") {  // len16 members whose value is [esz:2][cnt:2] + cnt fixed elements
    auto r = nm::many0(p_someip_member)(in);
    if (r) {
      for (auto& m : r->value) {
        if (m.wire_type != 6 || m.value.size() < 4) continue;
        auto hdr = nm::pair(nm::be_u16, nm::be_u16)(nm::from(m.value));
        const u16 esz = hdr->value.first, cnt = hdr->value.second;
        nm::input q = hdr->rest;
        for (u16 i = 0; i < cnt && q.size() >= esz; ++i) {
          auto er = nm::length_value(nm::success(esz), p_someip_member)(q);
          if (er) tb.oddtlv.push_back({pid, rule_id, i, m.data_id, esz, cnt, er->value.data_id}), ++rows;
          q = q.advance(esz);
        }
      }
    }
  } else if (kind == "lldp") {
    auto r = nm::many0(p_lldp_tlv)(in);
    if (r) {
      u32 idx = 0;
      for (auto& t : r->value) {
        LldpTlvRow row{};
        row.packet_id = pid; row.rule_id = rule_id; row.tlv_index = idx++;
        row.tlv_type = t.type; row.tlv_length = t.length;
        row.value_offset = u16(t.value.empty() ? 0 : std::size_t(t.value.data() - region.data()));
        if ((t.type == 1 || t.type == 2) && t.length >= 1) row.subtype = u8(t.value[0]);
        const std::size_t head = std::min<std::size_t>(t.length, row.value_head.size());
        std::memcpy(row.value_head.data(), t.value.data(), head);
        nm::input v = nm::from(t.value);
        if (t.type == 3 && t.length >= 2) row.ttl_seconds = nm::be_u16(v)->value;
        if (t.type == 7 && t.length >= 4) {
          auto c = nm::pair(nm::be_u16, nm::be_u16)(v);
          row.caps_supported = c->value.first; row.caps_enabled = c->value.second;
        }
        if (t.type == 8) {  // [addr_len:1][addr_subtype:1][addr..][if_subtype:1][if_num:4][oid..]
          auto m = nm::flat_map(nm::u8, [](u8 alen) {
            return nm::cond(alen >= 1, nm::pair(nm::u8, nm::preceded(nm::take(alen - 1),
                                                                     nm::pair(nm::u8, nm::be_u32))));
          })(v);
          if (m && m->value) {
            row.mgmt_addr_subtype   = m->value->first;
            row.mgmt_iface_subtype  = m->value->second.first;
            row.mgmt_iface_number   = m->value->second.second;
          } else if (t.length >= 2) {
            row.mgmt_addr_subtype = u8(t.value[1]);  // truncated: keep what's there
          }
        }
        tb.lldp.push_back(row); ++rows;
      }
    }
  }
  return rows;
}

// ---------------------------------------------------------------------------
int main(int argc, char** argv) {
  bool stats = false;
  std::vector<const char*> pos;
  for (int i = 1; i < argc; ++i)
    (std::string_view(argv[i]) == "--stats" ? (void)(stats = true) : pos.push_back(argv[i]));
  if (pos.size() < 2) {
    std::fprintf(stderr, "usage: %s [--stats] <rules.txt> <input.pcap|pcapng>\n", argv[0]);
    return 2;
  }
  auto slurp = [](const char* path, std::vector<u8>& out) {
    std::FILE* f = std::fopen(path, "rb");
    if (!f) return false;
    u8 chunk[65536]; std::size_t n;
    while ((n = std::fread(chunk, 1, sizeof chunk, f)) > 0) out.insert(out.end(), chunk, chunk + n);
    std::fclose(f); return true;
  };
  std::vector<u8> rules_bytes, cap;
  if (!slurp(pos[0], rules_bytes)) return std::fprintf(stderr, "cannot open %s\n", pos[0]), 1;
  if (!slurp(pos[1], cap)) return std::fprintf(stderr, "cannot open %s\n", pos[1]), 1;

  std::vector<Rule> rules;
  std::string err;
  if (!load_rules(std::string(rules_bytes.begin(), rules_bytes.end()), rules, err))
    return std::fprintf(stderr, "%s\n", err.c_str()), 1;

  const nm::bytes file(reinterpret_cast<const std::byte*>(cap.data()), cap.size());
  std::vector<nmpcap::BlockRef> refs;
  if (!nmpcap::scan_blocks(file, refs, err)) return std::fprintf(stderr, "%s\n", err.c_str()), 1;

  Tables tb;
  std::vector<u16> iface_link;
  struct RS { u64 matched = 0, rows = 0; };
  std::vector<RS> per_rule(rules.size());
  u64 pid = 0, seen = 0, matched_any = 0;

  for (const auto& ref : refs) {
    if (ref.kind == nmpcap::Kind::Shb) { iface_link.clear(); continue; }
    if (ref.kind == nmpcap::Kind::Idb) {
      nmpcap::IdbView idb{};
      if (nmpcap::parse_idb(file, ref, idb)) iface_link.push_back(idb.link_type);
      continue;
    }
    if (ref.kind != nmpcap::Kind::Epb && ref.kind != nmpcap::Kind::PcapRecord) continue;
    nmpcap::EpbView e{};
    if (!nmpcap::parse_epb(file, ref, e)) continue;
    const u16 link = e.interface_id < iface_link.size() ? iface_link[e.interface_id] : u16{0};
    const nm::bytes pkt = file.subspan(std::size_t(e.payload_file_offset), e.caplen);

    PacketState st;
    auto wr = nmproto::walk_packet(
        link, pkt,
        [&](const nmproto::Ethernet& x) { st.eth = x; },
        [&](const nmproto::VlanTag& x) {
          if (!st.vlan) {
            st.vlan = x;
            st.vlan_end = nm::wire_size_v<nmproto::Ethernet> + nm::wire_size_v<nmproto::VlanTag>;
          }
        },
        [&](const nmproto::Ipv4& x) { st.ipv4 = x; }, [&](const nmproto::Ipv6& x) { st.ipv6 = x; },
        [&](const nmproto::Tcp& x) { st.tcp = x; }, [&](const nmproto::Udp& x) { st.udp = x; });
    st.l4_payload = wr.l4_payload_offset;
    st.reached_l4 = wr.reached_l4;

    ++seen;
    bool any = false;
    for (const auto& rule : rules) {
      bool ok = true;
      for (const auto& p : rule.preds) {
        auto v = node_field(st, p);
        if (!v || !eval(p.op, *v, p.value)) { ok = false; break; }
      }
      if (!ok) continue;
      std::size_t b, en;
      if (!region_of(rule.region, st, pkt, b, en)) continue;
      any = true;
      ++per_rule[rule.rule_id].matched;
      per_rule[rule.rule_id].rows += run_kind(rule.parser, pid, rule.rule_id,
                                              pkt.subspan(b, en - b), tb);
    }
    matched_any += any;
    ++pid;
  }

  // NDJSON: one line per row, rendered by nanom's reflection (no hand dumper)
  std::string out;
  auto dump = [&](const char* table, const auto& rows) {
    for (const auto& r : rows) {
      out += "{\"table\":\""; out += table; out += "\",\"row\":";
      out += nm::to_json(r); out += "}\n";
    }
  };
  dump("someip_tlv", tb.someip_tlv);
  dump("raw_tlv", tb.raw_tlv);
  dump("oddtlv", tb.oddtlv);
  dump("lldp", tb.lldp);
  std::fwrite(out.data(), 1, out.size(), stdout);

  if (stats) {
    u64 rows_total = 0;
    for (auto& r : per_rule) rows_total += r.rows;
    std::fprintf(stderr, "dpar stats: packets_seen=%llu matched_any=%llu rows=%llu\n",
                 (unsigned long long)seen, (unsigned long long)matched_any,
                 (unsigned long long)rows_total);
    for (const auto& rule : rules)
      std::fprintf(stderr, "  rule %u \"%s\": matched=%llu rows=%llu\n", rule.rule_id,
                   rule.label.c_str(), (unsigned long long)per_rule[rule.rule_id].matched,
                   (unsigned long long)per_rule[rule.rule_id].rows);
  }
  return 0;
}
