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
endif()
