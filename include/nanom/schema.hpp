// SPDX-License-Identifier: Apache-2.0
// nanom/schema.hpp — schemas & debug dumps for a described struct (an "extra", layered on reflect.hpp):
// the walkable schema tree + dkind, Arrow C-Data format strings (arrow_format), Avro JSON
// (avro_schema), and to_json / csv_header / csv_row. Nothing in nom.hpp / reflect.hpp depends on any
// of this — it is cleanly on top.
#ifndef NANOM_SCHEMA_HPP_INCLUDED
#define NANOM_SCHEMA_HPP_INCLUDED

#include "reflect.hpp"

namespace nanom {

// ---------------------------------------------------------------------------
// 21. schema — walkable description of a struct, for Arrow / Avro / debug
// ---------------------------------------------------------------------------

enum class dkind : std::uint8_t {
  u8, u16, u32, u64, i8, i16, i32, i64, f32, f64,
  fixed_bin,   ///< fixed-size byte array
  list,        ///< fixed-size list of a scalar element
  record       ///< nested described struct
};

struct schema_node;

struct schema_field {
  std::string_view   name;
  dkind              kind;
  std::uint32_t      bits   = 0;        ///< original wire width in bits
  std::uint32_t      size   = 0;        ///< fixed_bin bytes / list length
  dkind              elem   = dkind::u8;///< list element kind
  const schema_node* nested = nullptr;  ///< record only
};

struct schema_node {
  std::string_view              name;
  std::span<const schema_field> fields;
};

namespace detail {

template <class D>
constexpr dkind scalar_kind() {
  if constexpr (std::is_same_v<D, float>)  return dkind::f32;
  else if constexpr (std::is_same_v<D, double>) return dkind::f64;
  else if constexpr (std::is_signed_v<D>) {
    if constexpr (sizeof(D) == 1) return dkind::i8;
    else if constexpr (sizeof(D) == 2) return dkind::i16;
    else if constexpr (sizeof(D) == 4) return dkind::i32;
    else return dkind::i64;
  } else {
    if constexpr (sizeof(D) == 1) return dkind::u8;
    else if constexpr (sizeof(D) == 2) return dkind::u16;
    else if constexpr (sizeof(D) == 4) return dkind::u32;
    else return dkind::u64;
  }
}

template <Described T> struct schema_holder;

template <class F>
constexpr schema_field field_schema(std::string_view name) {
  schema_field s{};
  s.name = name;
  s.bits = std::uint32_t(wire<F>::bits);
  if constexpr (Described<F>) {
    s.kind = dkind::record;
    s.nested = &schema_holder<F>::node;
  } else if constexpr (is_std_array_v<F>) {
    using E = typename F::value_type;
    using ED = typename wire<E>::decoded;
    s.size = std::uint32_t(std::tuple_size_v<F>);
    if constexpr (sizeof(ED) == 1 && std::is_integral_v<ED>) {
      s.kind = dkind::fixed_bin;             // byte arrays -> fixed binary
    } else {
      s.kind = dkind::list;
      s.elem = scalar_kind<ED>();
    }
  } else {
    s.kind = scalar_kind<typename wire<F>::decoded>();
  }
  return s;
}

template <Described T>
constexpr auto make_schema_fields() {
  std::array<schema_field, field_count_v<T>> out{};
  std::size_t i = 0;
  for_each_field<T>([&](auto f) {
    out[i++] = field_schema<member_t<decltype(f)::mem_ptr>>(decltype(f)::name.sv());
  });
  return out;
}

template <Described T>
struct schema_holder {
  static constexpr auto fields = make_schema_fields<T>();
  static constexpr schema_node node{describe<T>::name(), fields};
};

}  // namespace detail

/// The schema of a registered struct — a compile-time constant tree.
template <Described T>
constexpr const schema_node& schema_of() { return detail::schema_holder<T>::node; }

// ---------------------------------------------------------------------------
// 22. schema emission — Arrow C data interface, Avro JSON, JSON/CSV debug
// ---------------------------------------------------------------------------

/// Arrow C Data Interface format string for one field ("S"=u16, "w:6"=fixed
/// binary…) — hand these to nanoarrow's ArrowSchemaSetFormat; Lance consumes
/// Arrow schemas directly.
inline std::string arrow_format(const schema_field& f) {
  auto scalar = [](dkind k) -> const char* {
    switch (k) {
      case dkind::u8:  return "C";  case dkind::u16: return "S";
      case dkind::u32: return "I";  case dkind::u64: return "L";
      case dkind::i8:  return "c";  case dkind::i16: return "s";
      case dkind::i32: return "i";  case dkind::i64: return "l";
      case dkind::f32: return "f";  case dkind::f64: return "g";
      default:         return "z";
    }
  };
  switch (f.kind) {
    case dkind::fixed_bin: return "w:" + std::to_string(f.size);
    case dkind::list:      return "+w:" + std::to_string(f.size);  // child: scalar(f.elem)
    case dkind::record:    return "+s";
    default:               return scalar(f.kind);
  }
}

namespace detail {
inline void avro_field_json(const schema_field& f, std::string& out);
inline void avro_record_json(const schema_node& n, std::string& out) {
  out += R"({"type":"record","name":")";
  out += n.name;
  out += R"(","fields":[)";
  bool first = true;
  for (const auto& f : n.fields) {
    if (!first) out += ',';
    first = false;
    out += R"({"name":")";
    out += f.name;
    out += R"(","type":)";
    avro_field_json(f, out);
    out += '}';
  }
  out += "]}";
}
inline void avro_field_json(const schema_field& f, std::string& out) {
  auto scalar = [](dkind k) -> const char* {
    switch (k) {
      case dkind::u8: case dkind::u16: case dkind::i8: case dkind::i16:
      case dkind::i32: return R"("int")";
      // u32 widens to long; u64 is emitted as long (Avro has no unsigned —
      // values above 2^63 wrap; use fixed_bin if that matters)
      case dkind::u32: case dkind::u64: case dkind::i64: return R"("long")";
      case dkind::f32: return R"("float")";
      case dkind::f64: return R"("double")";
      default: return R"("bytes")";
    }
  };
  switch (f.kind) {
    case dkind::fixed_bin:
      out += R"({"type":"fixed","name":")";
      out += f.name;
      out += R"(_fx","size":)" + std::to_string(f.size) + "}";
      break;
    case dkind::list:
      out += R"({"type":"array","items":)";
      out += scalar(f.elem);
      out += '}';
      break;
    case dkind::record: avro_record_json(*f.nested, out); break;
    default: out += scalar(f.kind);
  }
}
}  // namespace detail

/// Avro schema (JSON) for a registered struct.
template <Described T>
std::string avro_schema() {
  std::string out;
  detail::avro_record_json(schema_of<T>(), out);
  return out;
}

// --- JSON / CSV debug dumps -------------------------------------------------

namespace detail {

template <class F>
void json_value(const F& v, std::string& out) {
  if constexpr (Described<F>) {
    out += '{';
    bool first = true;
    for_each_field<F>([&](auto f) {
      out += first ? "" : ",";
      first = false;
      out += '"';
      out += decltype(f)::name.sv();
      out += "\":";
      json_value(v.*(decltype(f)::mem_ptr), out);
    });
    out += '}';
  } else if constexpr (is_std_array_v<F>) {
    using E = typename F::value_type;
    using ED = typename wire<E>::decoded;
    if constexpr (sizeof(ED) == 1 && std::is_integral_v<ED>) {
      static constexpr char hexd[] = "0123456789abcdef";  // bytes -> hex string
      out += '"';
      for (auto e : v) {
        auto b = std::uint8_t(typename wire<E>::decoded(e));
        out += hexd[b >> 4]; out += hexd[b & 15];
      }
      out += '"';
    } else {
      out += '[';
      bool first = true;
      for (const auto& e : v) {
        if (!first) out += ',';
        first = false;
        json_value(e, out);
      }
      out += ']';
    }
  } else if constexpr (std::floating_point<F>) {
    char buf[32];
    auto [p, ec] = std::to_chars(buf, buf + sizeof buf, double(v));
    out.append(buf, p);
  } else {  // integral / be / le / ubits / ibits — all convert to a number
    using D = typename wire<F>::decoded;
    D d = D(v);
    if constexpr (std::floating_point<D>) {
      char buf[32];
      auto [pe, ec] = std::to_chars(buf, buf + sizeof buf, double(d));
      (void)ec;
      out.append(buf, pe);
    } else if constexpr (std::is_signed_v<D>) {
      out += std::to_string(std::int64_t(d));
    } else {
      out += std::to_string(std::uint64_t(d));
    }
  }
}

template <class F>
void csv_names(std::string prefix, std::string_view name, std::string& out, bool& first) {
  if constexpr (Described<F>) {
    std::string p2 = prefix + std::string(name) + ".";
    for_each_field<F>([&](auto f) {
      csv_names<member_t<decltype(f)::mem_ptr>>(p2, decltype(f)::name.sv(), out, first);
    });
  } else {
    if (!first) out += ',';
    first = false;
    out += prefix;
    out += name;
  }
}

template <class F>
void csv_value(const F& v, std::string& out, bool& first) {
  if constexpr (Described<F>) {
    for_each_field<F>([&](auto f) { csv_value(v.*(decltype(f)::mem_ptr), out, first); });
  } else {
    if (!first) out += ',';
    first = false;
    json_value(v, out);  // scalar/array rendering is CSV-safe (no commas)
  }
}

}  // namespace detail

/// One-line JSON object for a parsed struct (debug).
template <Described T>
std::string to_json(const T& v) {
  std::string out;
  detail::json_value(v, out);
  return out;
}
/// CSV header ("dst,src,eth_type" — nested fields dotted) and one data row.
template <Described T>
std::string csv_header() {
  std::string out;
  bool first = true;
  detail::for_each_field<T>([&](auto f) {
    detail::csv_names<detail::member_t<decltype(f)::mem_ptr>>("", decltype(f)::name.sv(), out,
                                                              first);
  });
  return out;
}
template <Described T>
std::string csv_row(const T& v) {
  std::string out;
  bool first = true;
  detail::for_each_field<T>([&](auto f) { detail::csv_value(v.*(decltype(f)::mem_ptr), out, first); });
  return out;
}
}  // namespace nanom

#endif  // NANOM_SCHEMA_HPP_INCLUDED
