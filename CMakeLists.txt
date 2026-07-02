cmake_minimum_required(VERSION 3.20)
project(nanom VERSION 0.1.0 LANGUAGES CXX)

# ---- the library (header-only) --------------------------------------------
add_library(nanom INTERFACE)
add_library(nanom::nanom ALIAS nanom)
target_include_directories(nanom INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_compile_features(nanom INTERFACE cxx_std_23)

# ---- install + package config (so downstreams can find_package(nanom)) -----
include(CMakePackageConfigHelpers)
include(GNUInstallDirs)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(TARGETS nanom EXPORT nanomTargets)
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
set(NANOM_SANITIZER "" CACHE STRING "Sanitizer: '', 'address,undefined', or 'thread'")

# One interface target carrying the warning + sanitizer flags, linked by every
# test/example/bench binary so the whole tree is checked uniformly.
add_library(nanom_flags INTERFACE)
# -Wall/-Wextra/-Wpedantic is the strict set we gate on. -Wshadow/-Wconversion
# are deliberately NOT here: nanom exposes short global parser names (u8, rest,
# tag, ...) by design, so `auto rest = ...` in user code legitimately shadows
# them — gating on -Wshadow would punish the intended API. CI runs them as a
# separate advisory (non-blocking) lint instead.
target_compile_options(nanom_flags INTERFACE
  -Wall -Wextra -Wpedantic
  $<$<BOOL:${NANOM_WERROR}>:-Werror>)
if(NANOM_SANITIZER)
  target_compile_options(nanom_flags INTERFACE -fsanitize=${NANOM_SANITIZER} -fno-omit-frame-pointer -g)
  target_link_options(nanom_flags    INTERFACE -fsanitize=${NANOM_SANITIZER})
endif()

find_package(Threads REQUIRED)
enable_testing()

# helper: an executable linked against nanom + the shared flags
function(nanom_exe name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE nanom nanom_flags Threads::Threads)
endfunction()

set(parity_dir ${CMAKE_CURRENT_SOURCE_DIR}/examples/nanotins_parity)
set(td ${parity_dir}/testdata)

# ---- unit tests -----------------------------------------------------------
nanom_exe(nanom_tests tests/test_nanom.cpp)
add_test(NAME nanom_tests COMMAND nanom_tests)

# ---- worked examples (must run clean) -------------------------------------
foreach(ex ethernet elf fat16)
  nanom_exe(example_${ex} examples/${ex}.cpp)
  add_test(NAME example_${ex} COMMAND example_${ex})
endforeach()

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

# ---- robustness fuzzer (self-contained; also a ctest) ---------------------
nanom_exe(nm_self_fuzz fuzz/self_fuzz.cpp)
add_test(NAME self_fuzz COMMAND nm_self_fuzz)

# ---- benchmarks: built always (so they can't rot) and smoke-tested with a
#      tiny iteration count; the bench.yml workflow runs them for real numbers.
nanom_exe(nm_parse_bench bench/parse_bench.cpp)
nanom_exe(nm_bulk_bench  examples/nanotins_parity/pcap_bulk.cpp)  # reuse as bulk bench
add_test(NAME bench_smoke_parse COMMAND nm_parse_bench ${td}/srv6_sample.pcap 2)
add_test(NAME bench_smoke_bulk  COMMAND nm_bulk_bench  ${td}/srv6_sample.pcap 50 2)

# ---- libFuzzer coverage-guided targets (Clang only, opt-in) ---------------
if(NANOM_BUILD_FUZZERS)
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "NANOM_BUILD_FUZZERS requires Clang (libFuzzer)")
  endif()
  foreach(fz scan_walk)
    add_executable(fuzz_${fz} fuzz/fuzz_${fz}.cpp)
    target_link_libraries(fuzz_${fz} PRIVATE nanom Threads::Threads)
    target_compile_options(fuzz_${fz} PRIVATE -g -O1 -fsanitize=fuzzer,address,undefined)
    target_link_options(fuzz_${fz}    PRIVATE   -fsanitize=fuzzer,address,undefined)
  endforeach()
endif()
