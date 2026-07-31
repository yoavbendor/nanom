# Build the nanom_shark Python extension (nanobind). Depends only on nanobind + the nanom /
# nanom_shark headers — both are header-only INTERFACE libraries, so there is nothing to link and no
# find_package(nanom) needed: three include directories are the whole dependency story. nanoarrow is
# deliberately NOT required either; the Arrow C Data Interface bridge is hand-rolled in
# ../nanom_arrow.hpp (shared, unmodified, with the sibling nanom_pcap example).
cmake_minimum_required(VERSION 3.18)
project(nanom_shark LANGUAGES CXX)

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

nanobind_add_module(nanom_shark STABLE_ABI NB_STATIC nanom_shark_ext.cpp)
target_include_directories(nanom_shark PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}/../../../include"  # <nanom/...> and <nanom_shark/...>
  "${CMAKE_CURRENT_SOURCE_DIR}/.."                # ../nanom_arrow.hpp
  "${CMAKE_CURRENT_SOURCE_DIR}")

# Installed at the wheel ROOT (not into a same-named subdirectory) so the built wheel yields a
# directly importable top-level `nanom_shark` extension module — `import nanom_shark` after
# `pip install .` / `uv pip install .`.
install(TARGETS nanom_shark LIBRARY DESTINATION .)
