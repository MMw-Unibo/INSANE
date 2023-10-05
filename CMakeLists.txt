cmake_minimum_required(VERSION 3.0.0)
project(dpdk-test VERSION 0.1.0)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/")
find_package(DPDK REQUIRED)

add_subdirectory(lib)
add_subdirectory(examples)
add_subdirectory(apps)
add_subdirectory(tests)

add_executable(nsnd main.c)

target_include_directories(nsnd PRIVATE "${CMAKE_CURRENT_LIST_DIR}/lib/")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(nsnd PRIVATE "-DLOG_LEVEL=500")
endif()

target_link_libraries(nsnd PRIVATE rdmacm ibverbs insane)
target_link_libraries(nsnd PRIVATE ${DPDK_LIBRARIES} "rt" "dl")
target_compile_options(nsnd PUBLIC "-march=native" "-mssse3" PRIVATE "-Wall" "-Wno-unused-function" "-Wno-write-strings")
