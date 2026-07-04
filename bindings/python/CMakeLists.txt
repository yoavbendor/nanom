# Build the nanom_pcap example extension (nanobind). Depends only on nanobind + the nanom headers —
# nanoarrow is deliberately NOT required: the Arrow C Data Interface bridge is hand-rolled in
# nanom_arrow.hpp so the extension stays tiny and dependency-light.
cmake_minimum_required(VERSION 3.18)
project(nanom_pcap LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

find_package(Python 3.9 REQUIRED COMPONENTS Interpreter Development.Module)

# Locate nanobind shipped with the active interpreter (pip install nanobind).
execute_process(
  COMMAND "${Python_EXECUTABLE}" -m nanobind --cmake_dir
  OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE nanobind_ROOT)
find_package(nanobind CONFIG REQUIRED)

nanobind_add_module(nanom_pcap STABLE_ABI NB_STATIC example_pcapng.cpp)
target_include_directories(nanom_pcap PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../../include"   # <nanom/...>
  "${CMAKE_CURRENT_SOURCE_DIR}")                # nanom_arrow.hpp

install(TARGETS nanom_pcap LIBRARY DESTINATION nanom_pcap)
