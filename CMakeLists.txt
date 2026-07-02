cmake_minimum_required(VERSION 3.20)
project(nanom VERSION 0.1.0 LANGUAGES CXX)

add_library(nanom INTERFACE)
add_library(nanom::nanom ALIAS nanom)
target_include_directories(nanom INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_compile_features(nanom INTERFACE cxx_std_23)

install(DIRECTORY include/ DESTINATION include)

if(PROJECT_IS_TOP_LEVEL)
  enable_testing()

  add_executable(nanom_tests tests/test_nanom.cpp)
  target_link_libraries(nanom_tests PRIVATE nanom)
  target_compile_options(nanom_tests PRIVATE -Wall -Wextra)
  add_test(NAME nanom_tests COMMAND nanom_tests)

  foreach(ex ethernet elf fat16)
    add_executable(example_${ex} examples/${ex}.cpp)
    target_link_libraries(example_${ex} PRIVATE nanom)
    add_test(NAME example_${ex} COMMAND example_${ex})
  endforeach()

  # nanotins parity ports: pcap/pcapng scan + L2-L4 walk on nanom. Each is
  # checked against a golden that was verified byte-identical to the upstream
  # nanotins example (see examples/nanotins_parity/README.md).
  set(parity_dir ${CMAKE_CURRENT_SOURCE_DIR}/examples/nanotins_parity)
  set(td ${parity_dir}/testdata)

  add_executable(nm_pcapng2json ${parity_dir}/pcapng2json.cpp)
  target_link_libraries(nm_pcapng2json PRIVATE nanom)
  add_executable(nm_dpar_lite ${parity_dir}/dpar_lite.cpp)
  target_link_libraries(nm_dpar_lite PRIVATE nanom)
  add_executable(nm_pcap2columns ${parity_dir}/pcap2columns.cpp)
  target_link_libraries(nm_pcap2columns PRIVATE nanom)
  # columnar (SoA) data path: soa<T> -> contiguous column buffers -> lossless
  # round-trip. Exit code is nonzero on any reconstruction mismatch.
  add_test(NAME parity_columns
    COMMAND nm_pcap2columns ${td}/ipv4_options_sample.pcap)

  foreach(fx ipv4_options_sample srv6_sample)
    add_test(NAME parity_json_${fx}
      COMMAND ${CMAKE_COMMAND}
        -DEXE=$<TARGET_FILE:nm_pcapng2json>
        -DARGS=${td}/${fx}.pcap
        -DGOLDEN=${td}/${fx}.ndjson
        -P ${parity_dir}/diff_test.cmake)
  endforeach()

  add_test(NAME parity_dpar
    COMMAND ${CMAKE_COMMAND}
      -DEXE=$<TARGET_FILE:nm_dpar_lite>
      "-DARGS=${td}/dpar_rules.txt;${td}/dpar_sample.pcap"
      -DGOLDEN=${td}/dpar_sample.ndjson
      -P ${parity_dir}/diff_test.cmake)
  add_test(NAME parity_lldp
    COMMAND ${CMAKE_COMMAND}
      -DEXE=$<TARGET_FILE:nm_dpar_lite>
      "-DARGS=${td}/lldp_rules.txt;${td}/dpar_sample.pcap"
      -DGOLDEN=${td}/lldp_sample.ndjson
      -P ${parity_dir}/diff_test.cmake)

  # robustness fuzzer (self-contained): random/mutated bytes must not crash the
  # scan + walk. Best run with -fsanitize=address,undefined.
  add_executable(nm_self_fuzz fuzz/self_fuzz.cpp)
  target_link_libraries(nm_self_fuzz PRIVATE nanom)
  add_test(NAME self_fuzz COMMAND nm_self_fuzz)

  # parse-only benchmark, built so it stays compiling (not run as a test)
  add_executable(nm_parse_bench bench/parse_bench.cpp)
  target_link_libraries(nm_parse_bench PRIVATE nanom)
endif()
