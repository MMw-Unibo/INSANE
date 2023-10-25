add_executable(dpdk-perftest "dpdk_perftest.c")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(dpdk-perftest PRIVATE "-DLOG_LEVEL=500")
endif()

target_include_directories(dpdk-perftest
    PRIVATE
    "${CMAKE_SOURCE_DIR}/lib"
    "${CMAKE_SOURCE_DIR}/include"
)
target_link_libraries(dpdk-perftest PRIVATE ${DPDK_LIBRARIES} "rt")
target_sources(dpdk-perftest
    PRIVATE
    ${CMAKE_SOURCE_DIR}/lib/logger.c
)

target_compile_options(dpdk-perftest
    PUBLIC "-mssse3"
    PRIVATE "-Wall" "-Wpedantic"
)

add_executable(socket-perftest "socket_perftest.c")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(socket-perftest PRIVATE "-DLOG_LEVEL=500")
endif()

target_include_directories(socket-perftest
    PRIVATE
    "${CMAKE_SOURCE_DIR}/lib"
    "${CMAKE_SOURCE_DIR}/include"
)
target_link_libraries(socket-perftest PRIVATE ${DPDK_LIBRARIES} "rt")
target_sources(socket-perftest
    PRIVATE
    ${CMAKE_SOURCE_DIR}/lib/logger.c
)

target_compile_options(socket-perftest
    PUBLIC "-mssse3"
    PRIVATE "-Wall" "-Wpedantic"
)