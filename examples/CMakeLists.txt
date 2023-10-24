# nsn-perf
add_executable(nsn-perf nsn_perf.c)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(nsn-perf PRIVATE "-DLOG_LEVEL=500")
endif()

target_link_libraries(nsn-perf PRIVATE insane)
