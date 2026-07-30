# Downstream smoke test: consume nanom via find_package after install.
cmake_minimum_required(VERSION 3.20)
project(nanom_consumer CXX)
find_package(nanom REQUIRED)
add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE nanom::nanom)

# Same smoke test for the nanom_shark decoder library: nanom::shark must be exported by the
# installed package, and <nanom_shark/...> headers must resolve from the install tree.
add_executable(shark_consumer shark_main.cpp)
target_link_libraries(shark_consumer PRIVATE nanom::shark)
