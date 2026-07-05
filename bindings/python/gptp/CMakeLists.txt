# Build the nanom_gptp example extension (nanobind). Depends only on nanobind + the nanom headers —
# reuses ../nanom_arrow.hpp (the generic soa<T> -> Arrow bridge) unmodified; no nanoarrow dependency.
cmake_minimum_required(VERSION 3.18)
project(nanom_gptp LANGUAGES CXX)

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

nanobind_add_module(nanom_gptp STABLE_ABI NB_STATIC example_gptp.cpp)
target_include_directories(nanom_gptp PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include"  # <nanom/...>
  "${CMAKE_CURRENT_SOURCE_DIR}/.."                # ../nanom_arrow.hpp
  "${CMAKE_CURRENT_SOURCE_DIR}")                  # gptp_rows.hpp / gptp_parse.hpp

install(TARGETS nanom_gptp LIBRARY DESTINATION nanom_gptp)
