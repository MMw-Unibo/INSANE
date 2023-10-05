# nsn-perf
add_executable(nsn-perf nsn_perf.c)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(nsn-perf PRIVATE "-DLOG_LEVEL=500")
endif()

target_link_libraries(nsn-perf PRIVATE insane)

# nsn-perf-rel
add_executable(nsn-perf-rel nsn_perf_reliable.c)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(nsn-perf-rel PRIVATE "-DLOG_LEVEL=500")
endif()

target_link_libraries(nsn-perf-rel PRIVATE insane)