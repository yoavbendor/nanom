cmake_minimum_required(VERSION 3.20)
project(nanom VERSION 0.1.0 LANGUAGES CXX)

# ---- the library (header-only) --------------------------------------------
add_library(nanom INTERFACE)
add_library(nanom::nanom ALIAS nanom)
target_include_directories(nanom INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_compile_features(nanom INTERFACE cxx_std_23)

# ---- nanom_shark: the pcap/pcapng protocol-decoder library ----------------
# Header-only, nanom-only (no third-party deps). Promoted out of examples/ so subproject /
# FetchContent consumers get a real target — hence declared ABOVE the PROJECT_IS_TOP_LEVEL
# return below. Headers ship via the same install(DIRECTORY include/) rule as nanom's.
add_library(nanom_shark INTERFACE)
add_library(nanom::shark ALIAS nanom_shark)
target_link_libraries(nanom_shark INTERFACE nanom)
target_compile_features(nanom_shark INTERFACE cxx_std_23)
# Export as nanom::shark (not nanom::nanom_shark) so the installed package spells the target
# exactly like the build-tree ALIAS above — consumers use one name either way.
set_target_properties(nanom_shark PROPERTIES EXPORT_NAME shark)

# ---- install + package config (so downstreams can find_package(nanom)) -----
include(CMakePackageConfigHelpers)
include(GNUInstallDirs)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(TARGETS nanom nanom_shark EXPORT nanomTargets)
install(EXPORT nanomTargets NAMESPACE nanom:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/nanom)
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/nanomConfig.cmake"
  "include(CMakeFindDependencyMacro)\nfind_dependency(Threads)\ninclude(\"\${CMAKE_CURRENT_LIST_DIR}/nanomTargets.cmake\")\n")
write_basic_package_version_file("${CMAKE_CURRENT_BINARY_DIR}/nanomConfigVersion.cmake"
  VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)
install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/nanomConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/nanomConfigVersion.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/nanom)

if(NOT PROJECT_IS_TOP_LEVEL)
  return()
endif()

# ---- developer options (CI flips these on) --------------------------------
option(NANOM_WERROR         "Treat warnings as errors"                  OFF)
option(NANOM_BUILD_FUZZERS  "Build the libFuzzer targets (Clang only)"  OFF)
option(NANOM_MEMORY_SAFETY_UB_DEMOS "Build UB red-team demos (ASan only)" OFF)
option(NANOM_MEMORY_SAFETY_GAP_TESTS "Register WILL_FAIL gap safety tests in ctest" ON)
option(NANOM_GUARD_VIEWS "Enable runtime null/uninitialized view guards" ON)
option(NANOM_GENERATION "Enable wire-buffer generation lifetime tracking" ON)
option(NANOM_STRICT "Strict 'safe routes only' profile: compile-time restrictions buy a lean, fast runtime" OFF)
set(NANOM_SANITIZER "" CACHE STRING "Sanitizer: '', 'address,undefined', or 'thread'")
# C++26 P2996 reflection mode: the whole tree (tests, examples, parity ports) builds at C++26 with
# the reflection provider active — the macro-free nanom. Needs a P2996 compiler (today: the
# Bloomberg clang-p2996 fork; <meta> lives in its bundled libc++, hence the default flags). Add
# -DNANOM_DESCRIBE_FORCE_MACRO to CMAKE_CXX_FLAGS for the macro-parity crosscheck mode.
option(NANOM_CXX26_REFLECTION "Build in C++26 P2996 reflection mode" OFF)
set(NANOM_REFLECTION_FLAGS "-freflection-latest;-stdlib=libc++" CACHE STRING
    "Extra compile/link flags for NANOM_CXX26_REFLECTION")

# Warnings + sanitizer only (no safety-profile defines). Every flags target
# below builds on this so the whole tree is checked uniformly.
# -Wall/-Wextra/-Wpedantic is the strict set we gate on. -Wshadow/-Wconversion
# are deliberately NOT here: nanom exposes short global parser names (u8, rest,
# tag, ...) by design, so `auto rest = ...` in user code legitimately shadows
# them — gating on -Wshadow would punish the intended API. CI runs them as a
# separate advisory (non-blocking) lint instead.
add_library(nanom_warn_flags INTERFACE)
target_compile_options(nanom_warn_flags INTERFACE
  -Wall -Wextra -Wpedantic
  $<$<BOOL:${NANOM_WERROR}>:-Werror>)
if(NANOM_SANITIZER)
  target_compile_options(nanom_warn_flags INTERFACE -fsanitize=${NANOM_SANITIZER} -fno-omit-frame-pointer -g)
  target_link_options(nanom_warn_flags INTERFACE -fsanitize=${NANOM_SANITIZER})
endif()

# Default profile flags: warnings + the explicit NANOM_GUARD_VIEWS define.
add_library(nanom_common_flags INTERFACE)
target_link_libraries(nanom_common_flags INTERFACE nanom_warn_flags)
if(NANOM_GUARD_VIEWS)
  target_compile_definitions(nanom_common_flags INTERFACE NANOM_GUARD_VIEWS=1)
else()
  target_compile_definitions(nanom_common_flags INTERFACE NANOM_GUARD_VIEWS=0)
endif()

# Strict "safe routes only" flags: define ONLY NANOM_STRICT=1 and let prelude.hpp
# derive the lean runtime defaults (GENERATION=0, GUARD_VIEWS=0). Deliberately
# does NOT link nanom_common_flags/nanom_flags, which force the runtime nets on.
add_library(nanom_strict_flags INTERFACE)
target_link_libraries(nanom_strict_flags INTERFACE nanom_warn_flags)
target_compile_definitions(nanom_strict_flags INTERFACE NANOM_STRICT=1)

add_library(nanom_flags INTERFACE)
target_link_libraries(nanom_flags INTERFACE nanom_common_flags)
if(NANOM_GENERATION)
  target_compile_definitions(nanom_flags INTERFACE NANOM_GENERATION=1)
else()
  target_compile_definitions(nanom_flags INTERFACE NANOM_GENERATION=0)
endif()
if(NANOM_CXX26_REFLECTION)
  set(CMAKE_CXX_STANDARD 26)  # compile features declare a 23 minimum; this raises the whole tree
  # Apply reflection flags to the shared warn base so EVERY flags target (default,
  # strict, generation) inherits libc++ + the runtime rpath, not just nanom_flags.
  target_compile_options(nanom_warn_flags INTERFACE ${NANOM_REFLECTION_FLAGS})
  target_link_options(nanom_warn_flags    INTERFACE ${NANOM_REFLECTION_FLAGS})
  # Binaries must find the toolchain's own libc++ at runtime when it isn't the system one.
  get_filename_component(_nanom_p2996_bin "${CMAKE_CXX_COMPILER}" DIRECTORY)
  if(EXISTS "${_nanom_p2996_bin}/../lib/x86_64-unknown-linux-gnu/libc++.so")
    target_link_options(nanom_warn_flags INTERFACE
      "-Wl,-rpath,${_nanom_p2996_bin}/../lib/x86_64-unknown-linux-gnu")
  endif()
endif()

find_package(Threads REQUIRED)
enable_testing()

# helper: an executable linked against nanom + the shared flags
function(nanom_exe name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE nanom nanom_flags Threads::Threads)
endfunction()

# Like nanom_exe but with an explicit NANOM_GENERATION value (for gap-test profiles).
function(nanom_exe_generation name generation)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE nanom nanom_common_flags Threads::Threads)
  target_compile_definitions(${name} PRIVATE NANOM_GENERATION=${generation})
endfunction()

# Like nanom_exe but for the strict "safe routes only" profile (NANOM_STRICT=1;
# prelude derives the lean runtime defaults).
function(nanom_exe_strict name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE nanom nanom_strict_flags Threads::Threads)
endfunction()

set(parity_dir ${CMAKE_CURRENT_SOURCE_DIR}/examples/nanotins_parity)
set(td ${parity_dir}/testdata)

# ---- unit tests -----------------------------------------------------------
nanom_exe(nanom_tests tests/test_nanom.cpp)
add_test(NAME nanom_tests COMMAND nanom_tests)

# Segmented (scatter-gather) input: exhaustive boundary property (cursor primitives agree with
# the contiguous cursor over every split) + strct_seg/overlay_seg differential parity.
nanom_exe(nanom_segmented_tests tests/test_segmented.cpp)
add_test(NAME nanom_segmented_tests COMMAND nanom_segmented_tests)

# Variable-length integers, count guards, le_array, and the reflected tagged-message Thrift
# compact codec + Parquet metadata model (tagged.hpp, formats/parquet_thrift.hpp). Also built in
# the strict profile and with generation tracking off, so every safety profile covers the codec.
nanom_exe(nanom_tagged_tests tests/test_tagged.cpp)
add_test(NAME nanom_tagged_tests COMMAND nanom_tagged_tests)
nanom_exe_strict(nanom_tagged_tests_strict tests/test_tagged.cpp)
add_test(NAME nanom_tagged_tests_strict COMMAND nanom_tagged_tests_strict)
nanom_exe_generation(nanom_tagged_tests_nogen 0 tests/test_tagged.cpp)
add_test(NAME nanom_tagged_tests_nogen COMMAND nanom_tagged_tests_nogen)

# Writing fixed-layout structs (emit.hpp): byte round trips of every field kind and of the
# examples' layouts, computed fields (IPv4 length + checksum), range errors, constexpr encoding.
nanom_exe(nanom_emit_tests tests/test_emit.cpp)
add_test(NAME nanom_emit_tests COMMAND nanom_emit_tests)
nanom_exe_strict(nanom_emit_tests_strict tests/test_emit.cpp)
add_test(NAME nanom_emit_tests_strict COMMAND nanom_emit_tests_strict)

# Writing tagged messages (tagged_encode.hpp): round-trip properties over every Parquet model
# message generated by reflection, sink bounds (exact-size buffers) and error reporting.
nanom_exe(nanom_tagged_encode_tests tests/test_tagged_encode.cpp)
add_test(NAME nanom_tagged_encode_tests COMMAND nanom_tagged_encode_tests)
nanom_exe_strict(nanom_tagged_encode_tests_strict tests/test_tagged_encode.cpp)
add_test(NAME nanom_tagged_encode_tests_strict COMMAND nanom_tagged_encode_tests_strict)

# Columnar page decode kernels (bit unpacking, RLE hybrid, DELTA_BINARY_PACKED, BYTE_STREAM_SPLIT)
# and the dependency-free codecs (Snappy, LZ4 block), against reference implementations.
nanom_exe(nanom_columnar_tests tests/test_columnar.cpp)
add_test(NAME nanom_columnar_tests COMMAND nanom_columnar_tests)
nanom_exe_strict(nanom_columnar_tests_strict tests/test_columnar.cpp)
add_test(NAME nanom_columnar_tests_strict COMMAND nanom_columnar_tests_strict)

# Memory-safety regression suite: enforced guards (must pass).
nanom_exe(nanom_memory_safety_tests tests/test_memory_safety.cpp)
add_test(NAME nanom_memory_safety_tests COMMAND nanom_memory_safety_tests)

nanom_exe(nanom_generation_tests tests/test_memory_safety_generation.cpp)
target_compile_definitions(nanom_generation_tests PRIVATE NANOM_GENERATION_THROW=1)
add_test(NAME nanom_generation_tests COMMAND nanom_generation_tests)

# Streaming / incremental parser safety (short-prefix, refill boundaries).
nanom_exe(nanom_streaming_safety_tests tests/test_streaming_safety.cpp)
target_compile_definitions(nanom_streaming_safety_tests PRIVATE
  NANOM_GENERATION_THROW=1
  NANOM_STREAMING_FIXTURE="${td}/SRL_front_left_51_short.pcapng")
target_include_directories(nanom_streaming_safety_tests PRIVATE ${CMAKE_SOURCE_DIR}/bench)
add_test(NAME nanom_streaming_safety_tests COMMAND nanom_streaming_safety_tests)

# Strict "safe routes only" profile: compile-time restrictions + lean runtime.
# The test self-asserts the compile-time contract (removed raw-pointer entry,
# deleted owning-temporary overloads, lean bytes/flags) then parses via the
# safe routes.
nanom_exe_strict(nanom_strict_profile_tests tests/test_strict_profile.cpp)
add_test(NAME nanom_strict_profile_tests COMMAND nanom_strict_profile_tests)

# Negative compile tests: the strict profile MUST refuse these. Each is expected
# to FAIL to compile; ctest inverts the result (WILL_FAIL) so a regression that
# accidentally re-enables an unsafe route turns the suite red.
add_test(NAME nanom_strict_rejects_bulk
  COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target nanom_strict_neg_bulk)
set_tests_properties(nanom_strict_rejects_bulk PROPERTIES WILL_FAIL TRUE)
add_executable(nanom_strict_neg_bulk EXCLUDE_FROM_ALL tests/strict_neg/neg_bulk.cpp)
target_link_libraries(nanom_strict_neg_bulk PRIVATE nanom nanom_strict_flags)

add_test(NAME nanom_strict_rejects_raw_ptr
  COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target nanom_strict_neg_raw_ptr)
set_tests_properties(nanom_strict_rejects_raw_ptr PROPERTIES WILL_FAIL TRUE)
add_executable(nanom_strict_neg_raw_ptr EXCLUDE_FROM_ALL tests/strict_neg/neg_raw_ptr.cpp)
target_link_libraries(nanom_strict_neg_raw_ptr PRIVATE nanom nanom_strict_flags)

add_test(NAME nanom_strict_rejects_string_temp
  COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target nanom_strict_neg_string_temp)
set_tests_properties(nanom_strict_rejects_string_temp PROPERTIES WILL_FAIL TRUE)
add_executable(nanom_strict_neg_string_temp EXCLUDE_FROM_ALL tests/strict_neg/neg_string_temp.cpp)
target_link_libraries(nanom_strict_neg_string_temp PRIVATE nanom nanom_strict_flags)

if(NANOM_MEMORY_SAFETY_GAP_TESTS)
  # Gap suite: residual hazards from THREAT_MODEL.md — WILL_FAIL until hardened.
  nanom_exe_generation(nanom_memory_safety_gap_tests 0 tests/test_memory_safety_gaps.cpp)
  add_test(NAME nanom_memory_safety_gap_tests COMMAND nanom_memory_safety_gap_tests)
  set_tests_properties(nanom_memory_safety_gap_tests PROPERTIES WILL_FAIL TRUE)

  nanom_exe_generation(nanom_memory_safety_gap_generation_tests 1
                       tests/test_memory_safety_gaps_generation.cpp)
  target_compile_definitions(nanom_memory_safety_gap_generation_tests PRIVATE
    NANOM_GENERATION_THROW=1)
  add_test(NAME nanom_memory_safety_gap_generation_tests
           COMMAND nanom_memory_safety_gap_generation_tests)
  set_tests_properties(nanom_memory_safety_gap_generation_tests PROPERTIES WILL_FAIL TRUE)
endif()

if(NANOM_MEMORY_SAFETY_UB_DEMOS)
  nanom_exe(nanom_memory_safety_ub_demos tests/test_memory_safety_ub.cpp)
endif()

# Parity audit vs Rust nom 8.0.0's own test suite -- see docs/NOM_PARITY_AUDIT.md.
nanom_exe(nanom_nom_parity_tests tests/test_nom_parity.cpp)
add_test(NAME nanom_nom_parity_tests COMMAND nanom_nom_parity_tests)

# ---- worked examples (must run clean) -------------------------------------
foreach(ex ethernet elf fat16)
  nanom_exe(example_${ex} examples/${ex}.cpp)
  add_test(NAME example_${ex} COMMAND example_${ex})
endforeach()

# Parquet footer / page-header / offset-index dump via the reflected Thrift model, checked against
# pyarrow on a matrix of real files (codecs, page v1/v2, dictionary, nested + logical types, page
# index). Skipped (exit 77) when python3 or pyarrow is unavailable.
nanom_exe(parquet_meta examples/parquet_meta.cpp)
nanom_exe(codec_check tests/codec_check.cpp)
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
  # Snappy / LZ4-block decoders vs pyarrow's compressors on ~600 buffers.
  add_test(NAME codec_differential
           COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/codec_differential.py
                   $<TARGET_FILE:codec_check>)
  set_tests_properties(codec_differential PROPERTIES SKIP_RETURN_CODE 77)
  add_test(NAME parquet_differential
           COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tests/parquet_differential.py
                   $<TARGET_FILE:parquet_meta>)
  set_tests_properties(parquet_differential PROPERTIES SKIP_RETURN_CODE 77)
endif()

# ---- C++26 reflection mode only: the macro-free showcase + the provider-equivalence suite -----
if(NANOM_CXX26_REFLECTION)
  nanom_exe(example_reflect26 examples/reflect26.cpp)
  add_test(NAME example_reflect26 COMMAND example_reflect26)
  # Static-asserts that the reflection describe<T> == what NANOM_DESCRIBE would synthesize
  # (names, member pointers, qualified type names, eligibility fences, override semantics).
  nanom_exe(nanom_reflect26_tests tests/test_reflect26.cpp)
  add_test(NAME reflect26_equivalence COMMAND nanom_reflect26_tests)
endif()

# ---- nanotins parity ports (golden-diff + round-trip + bulk equality) -----
nanom_exe(nm_pcapng2json ${parity_dir}/pcapng2json.cpp)
nanom_exe(nm_dpar_lite   ${parity_dir}/dpar_lite.cpp)
nanom_exe(nm_pcap2columns ${parity_dir}/pcap2columns.cpp)
nanom_exe(nm_pcap_bulk    ${parity_dir}/pcap_bulk.cpp)

add_test(NAME parity_columns COMMAND nm_pcap2columns ${td}/ipv4_options_sample.pcap)
add_test(NAME bulk_parallel_equals_serial COMMAND nm_pcap_bulk ${td}/srv6_sample.pcap 200 5)

foreach(fx ipv4_options_sample srv6_sample)
  add_test(NAME parity_json_${fx}
    COMMAND ${CMAKE_COMMAND} -DEXE=$<TARGET_FILE:nm_pcapng2json>
      -DARGS=${td}/${fx}.pcap -DGOLDEN=${td}/${fx}.ndjson
      -P ${parity_dir}/diff_test.cmake)
endforeach()
add_test(NAME parity_dpar
  COMMAND ${CMAKE_COMMAND} -DEXE=$<TARGET_FILE:nm_dpar_lite>
    "-DARGS=${td}/dpar_rules.txt;${td}/dpar_sample.pcap"
    -DGOLDEN=${td}/dpar_sample.ndjson -P ${parity_dir}/diff_test.cmake)
add_test(NAME parity_lldp
  COMMAND ${CMAKE_COMMAND} -DEXE=$<TARGET_FILE:nm_dpar_lite>
    "-DARGS=${td}/lldp_rules.txt;${td}/dpar_sample.pcap"
    -DGOLDEN=${td}/lldp_sample.ndjson -P ${parity_dir}/diff_test.cmake)

# ---- nanom_shark: the pcap/pcapng decoder library's CLI + test suite ----------------------
# The library target (nanom::shark) is declared at the top of this file, above the
# PROJECT_IS_TOP_LEVEL return. Its headers live in include/nanom_shark/, so the targets below
# just link nanom::shark instead of hand-rolling include paths.
set(nanom_shark_td ${CMAKE_CURRENT_SOURCE_DIR}/tests/testdata/nanom_shark)

nanom_exe(nanom_shark_cli apps/nanom_shark_cli.cpp)
target_link_libraries(nanom_shark_cli PRIVATE nanom::shark)

# CLI-level regression test: with NO sink flag at all, the documented default ("--json is written to
# stdout") must actually happen -- catches a real bug where json_to_stdout was computed before the
# "default to JSON" fallback ran, so this exact no-flags invocation tried to fopen(nullptr, "wb").
add_test(NAME nanom_shark_cli_default_stdout
         COMMAND bash -c
             "$<TARGET_FILE:nanom_shark_cli> ${nanom_shark_td}/ipv4_fragments_sample.pcap | \
              grep -q '\"_index\":0'")

nanom_exe(nanom_shark_tests tests/nanom_shark_test_json_tree.cpp)
target_link_libraries(nanom_shark_tests PRIVATE nanom::shark)
target_compile_definitions(nanom_shark_tests PRIVATE NANOM_SHARK_TESTDATA="${td}")
add_test(NAME nanom_shark_tests COMMAND nanom_shark_tests)

# Phase 2: IPv4/IPv6 defragmentation, against fixtures synthesized by testdata/gen_fragments.py
# (no scapy dependency -- see that script's own header comment).
nanom_exe(nanom_shark_defrag_tests tests/nanom_shark_test_defrag.cpp)
target_link_libraries(nanom_shark_defrag_tests PRIVATE nanom::shark)
target_compile_definitions(nanom_shark_defrag_tests PRIVATE
  NANOM_SHARK_TESTDATA="${nanom_shark_td}")
add_test(NAME nanom_shark_defrag_tests COMMAND nanom_shark_defrag_tests)

# Phase 3: SOME/IP (header + SD entries/options + optional TLV members), gPTP (all 8 message
# kinds), LLDP (reusing the existing dpar_sample.pcap fixture).
# Phase 4: the EPB-at-a-time streaming session's buffer-reuse proof. Feeds the same synthetic
# capture through run_decode_pass (whole file resident) and through StreamingDecodeSession backed by
# an 8-slot pool that poisons + frees each buffer the instant the session reports its token
# released, then asserts the two decodes are byte-identical. Also built as nanom_shark_streaming_asan
# below, where ASan/UBSan turn any stale span into a hard failure instead of just wrong output.
nanom_exe(nanom_shark_streaming_tests tests/nanom_shark_test_streaming.cpp)
target_link_libraries(nanom_shark_streaming_tests PRIVATE nanom::shark)
add_test(NAME nanom_shark_streaming_tests COMMAND nanom_shark_streaming_tests)

nanom_exe(nanom_shark_protocols3_tests tests/nanom_shark_test_protocols3.cpp)
target_link_libraries(nanom_shark_protocols3_tests PRIVATE nanom::shark)
target_compile_definitions(nanom_shark_protocols3_tests PRIVATE
  NANOM_SHARK_TESTDATA="${nanom_shark_td}"
  # The LLDP case reuses nanotins_parity's dpar_sample.pcap; pass that directory explicitly
  # rather than walking up out of the nanom_shark testdata dir with a relative path.
  NANOM_PARITY_TESTDATA="${td}")
add_test(NAME nanom_shark_protocols3_tests COMMAND nanom_shark_protocols3_tests)

# Phase 8: golden-diff regression tests for nanom_shark's own JSON output on the defrag/SOME-IP/
# gPTP/LLDP fixtures -- these were previously checked only programmatically (CHECK() assertions on
# individual field values); this pins the exact NDJSON shape too, via the same diff_test.cmake
# helper nanotins_parity's own golden tests already use.
foreach(fx ipv4_fragments_sample ipv6_fragments_sample someip_fixture)
  add_test(NAME nanom_shark_golden_${fx}
    COMMAND ${CMAKE_COMMAND} -DEXE=$<TARGET_FILE:nanom_shark_cli>
      -DARGS=${nanom_shark_td}/${fx}.pcap -DGOLDEN=${nanom_shark_td}/${fx}.ndjson
      -P ${parity_dir}/diff_test.cmake)
endforeach()
add_test(NAME nanom_shark_golden_gptp_fixture
  COMMAND ${CMAKE_COMMAND} -DEXE=$<TARGET_FILE:nanom_shark_cli>
    -DARGS=${nanom_shark_td}/gptp_fixture.pcapng
    -DGOLDEN=${nanom_shark_td}/gptp_fixture.ndjson
    -P ${parity_dir}/diff_test.cmake)
# LLDP reuses nanotins_parity's already-golden-tested dpar_sample.pcap fixture (see parity_lldp)
# rather than a new one -- same fixture nanom_shark_test_protocols3.cpp's test_lldp_dpar_sample()
# decodes.
add_test(NAME nanom_shark_golden_lldp_dpar_sample
  COMMAND ${CMAKE_COMMAND} -DEXE=$<TARGET_FILE:nanom_shark_cli>
    -DARGS=${parity_dir}/testdata/dpar_sample.pcap
    -DGOLDEN=${nanom_shark_td}/dpar_sample_lldp.ndjson
    -P ${parity_dir}/diff_test.cmake)

# Phase 4: the Avro Object Container File sink.
# Phase 2 acceptance test: a brand-new protocol defined in ONE new file (this .cpp), registered in
# a decoder<...> type list, with ZERO edits to any header under include/nanom_shark/.
nanom_exe(nanom_shark_ergonomics_tests tests/nanom_shark_test_ergonomics.cpp)
target_link_libraries(nanom_shark_ergonomics_tests PRIVATE nanom::shark)
add_test(NAME nanom_shark_ergonomics_tests COMMAND nanom_shark_ergonomics_tests)

nanom_exe(nanom_shark_avro_tests tests/nanom_shark_test_avro.cpp)
target_link_libraries(nanom_shark_avro_tests PRIVATE nanom::shark)
add_test(NAME nanom_shark_avro_tests COMMAND nanom_shark_avro_tests)

# Phase 5: soa_columns.hpp's columns_of<T> -- the compile-time leaf-column type list the sibling
# `nanoshark` repo's Parquet/Lance sink bridges fold into their own column packs. Proves it agrees
# with nanom::soa<T>::columns() (name, order, per-row size) for every current node/row shape.
nanom_exe(nanom_shark_soa_columns_tests tests/nanom_shark_test_soa_columns.cpp)
target_link_libraries(nanom_shark_soa_columns_tests PRIVATE nanom::shark)
add_test(NAME nanom_shark_soa_columns_tests COMMAND nanom_shark_soa_columns_tests)

# ---- robustness fuzzer (self-contained; also a ctest) ---------------------
nanom_exe(nm_self_fuzz fuzz/self_fuzz.cpp)
add_test(NAME self_fuzz COMMAND nm_self_fuzz)

# Differential fuzz of the streaming session's buffer-release contract: the same fuzzer-built
# capture decoded whole-file vs one-block-at-a-time with every buffer poisoned + freed the instant
# its token is reported released. Built standalone (a PRNG driver instead of libFuzzer) so it runs
# in ctest; also in the libFuzzer target list below for coverage-guided runs.
nanom_exe(nm_streaming_defrag_fuzz fuzz/fuzz_streaming_defrag.cpp)
target_link_libraries(nm_streaming_defrag_fuzz PRIVATE nanom::shark)
target_compile_definitions(nm_streaming_defrag_fuzz PRIVATE NANOM_FUZZ_STANDALONE=1)
add_test(NAME streaming_defrag_fuzz COMMAND nm_streaming_defrag_fuzz 400)

# Thrift compact codec robustness + canonical round trip, through the Parquet metadata model.
nanom_exe(nm_thrift_fuzz fuzz/fuzz_thrift.cpp)
target_compile_definitions(nm_thrift_fuzz PRIVATE NANOM_FUZZ_STANDALONE=1)
add_test(NAME thrift_fuzz COMMAND nm_thrift_fuzz 20000)
nanom_exe(nm_emit_fuzz fuzz/fuzz_emit.cpp)
target_compile_definitions(nm_emit_fuzz PRIVATE NANOM_FUZZ_STANDALONE=1)
add_test(NAME emit_fuzz COMMAND nm_emit_fuzz 20000)
nanom_exe(nm_columnar_fuzz fuzz/fuzz_columnar.cpp)
target_compile_definitions(nm_columnar_fuzz PRIVATE NANOM_FUZZ_STANDALONE=1)
add_test(NAME columnar_fuzz COMMAND nm_columnar_fuzz 20000)

# ---- benchmarks: built always (so they can't rot) and smoke-tested with a
#      tiny iteration count; the bench.yml workflow runs them for real numbers.
nanom_exe(nm_parse_bench bench/parse_bench.cpp)
nanom_exe(nm_safety_microbench bench/safety_microbench.cpp)
nanom_exe(nm_bulk_bench  examples/nanotins_parity/pcap_bulk.cpp)  # reuse as bulk bench
nanom_exe(nm_segmented_bench bench/segmented_bench.cpp)  # stitch-vs-segments + per-wrap overhead
nanom_exe(nm_streaming_bench bench/streaming_bench.cpp)  # whole-file vs EPB-at-a-time: memory bound + ns/pkt
target_link_libraries(nm_streaming_bench PRIVATE nanom::shark)
nanom_exe(nm_thrift_bench bench/thrift_bench.cpp)  # Parquet footer decode: validate / full / one row group
add_test(NAME bench_smoke_parse COMMAND nm_parse_bench ${td}/srv6_sample.pcap 2)
add_test(NAME bench_smoke_safety COMMAND nm_safety_microbench 2)
add_test(NAME bench_smoke_bulk  COMMAND nm_bulk_bench  ${td}/srv6_sample.pcap 50 2)
add_test(NAME bench_smoke_segmented COMMAND nm_segmented_bench 2)
add_test(NAME bench_smoke_streaming COMMAND nm_streaming_bench 1 1)
add_test(NAME bench_smoke_thrift COMMAND nm_thrift_bench 10 5 1)

# ---- libFuzzer coverage-guided targets (Clang only, opt-in) ---------------
if(NANOM_BUILD_FUZZERS)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "NANOM_BUILD_FUZZERS requires Clang (libFuzzer)")
  endif()
  foreach(fz scan_walk streaming_pcapng defrag segmented streaming_defrag thrift columnar)
    add_executable(fuzz_${fz} fuzz/fuzz_${fz}.cpp)
    target_link_libraries(fuzz_${fz} PRIVATE nanom Threads::Threads)
    target_include_directories(fuzz_${fz} PRIVATE ${CMAKE_SOURCE_DIR}/bench)
    target_compile_options(fuzz_${fz} PRIVATE -g -O1 -fsanitize=fuzzer,address,undefined)
    target_link_options(fuzz_${fz}    PRIVATE   -fsanitize=fuzzer,address,undefined)
    if(fz STREQUAL streaming_pcapng)
      target_compile_definitions(fuzz_${fz} PRIVATE NANOM_GENERATION=1 NANOM_GUARD_VIEWS=1)
    endif()
  endforeach()
endif()
