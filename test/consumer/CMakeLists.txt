# Downstream smoke test: consume nanom via find_package after install.
cmake_minimum_required(VERSION 3.20)
project(nanom_consumer CXX)
find_package(nanom REQUIRED)
add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE nanom::nanom)
