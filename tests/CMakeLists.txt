macro(add_test_queue name)
    add_executable(${name} "${name}.c")

    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        target_compile_definitions(${name} PRIVATE "-DLOG_LEVEL=500")
    endif()

    target_include_directories(${name}
        PRIVATE
        "${CMAKE_SOURCE_DIR}/lib" "${CMAKE_SOURCE_DIR}/include"
    )
    target_link_libraries(${name} PRIVATE ${DPDK_LIBRARIES} "rt")
    target_sources(${name}
        PRIVATE
        ${CMAKE_SOURCE_DIR}/lib/common.c
        ${CMAKE_SOURCE_DIR}/lib/queue.c
        ${CMAKE_CURRENT_LIST_DIR}/test_queue_base.c
        ${CMAKE_SOURCE_DIR}/lib/logger.c
    )
    target_compile_options(${name}
        PUBLIC "-mssse3"
        PRIVATE "-Wall" "-Wpedantic"
    )
endmacro(add_test_queue)

add_test_queue("test_queue")
add_test_queue("test_queue_cons")
add_test_queue("test_queue_prod")
add_test_queue("test_rte_ring_cons")

add_executable(test_rte_ring_prod "test_rte_ring_prod.cpp")
target_link_libraries(test_rte_ring_prod PRIVATE ${DPDK_LIBRARIES} "rt" "dl")
target_compile_options(test_rte_ring_prod PUBLIC "-mssse3" PRIVATE "-Wall" "-Wpedantic")

add_executable(test_socket "test_socket.c")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(test_socket PRIVATE "-DLOG_LEVEL=500")
endif()

target_include_directories(test_socket
    PRIVATE
    "${CMAKE_SOURCE_DIR}/lib" "${CMAKE_SOURCE_DIR}/include"
)
target_link_libraries(test_socket PRIVATE ${DPDK_LIBRARIES} "rt")
target_sources(test_socket
    PRIVATE
    ${CMAKE_SOURCE_DIR}/lib/logger.c
)

target_compile_options(test_socket
    PUBLIC "-mssse3"
    PRIVATE "-Wall" "-Wpedantic"
)

# add_executable(test_rdma "test_rdma.c")

# if (CMAKE_BUILD_TYPE STREQUAL "Debug")
# target_compile_definitions(test_rdma PRIVATE "-DLOG_LEVEL=500")
# endif()

# target_include_directories(test_rdma
# PRIVATE
# "${CMAKE_SOURCE_DIR}/lib" "${CMAKE_SOURCE_DIR}/include"
# )
# target_link_libraries(test_rdma PRIVATE ${DPDK_LIBRARIES} "rt" rdmacm ibverbs)
# target_sources(test_rdma
# PRIVATE
# ${CMAKE_SOURCE_DIR}/lib/logger.c
# )

# target_compile_options(test_rdma
# PUBLIC "-mssse3"
# PRIVATE "-Wall" "-Wpedantic"
# )
add_executable(test_dpdk "test_dpdk.c")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(test_dpdk PRIVATE "-DLOG_LEVEL=500")
endif()

target_include_directories(test_dpdk
    PRIVATE
    "${CMAKE_SOURCE_DIR}/lib"
    "${CMAKE_SOURCE_DIR}/include"
)
target_link_libraries(test_dpdk PRIVATE ${DPDK_LIBRARIES} "rt")
target_sources(test_dpdk
    PRIVATE
    ${CMAKE_SOURCE_DIR}/lib/logger.c
)

target_compile_options(test_dpdk
    PUBLIC "-mssse3"
    PRIVATE "-Wall" "-Wpedantic"
)

add_executable(test_dpdk_nl "test_dpdk_nolimit.c")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(test_dpdk_nl PRIVATE "-DLOG_LEVEL=500")
endif()

target_include_directories(test_dpdk_nl
    PRIVATE
    "${CMAKE_SOURCE_DIR}/lib"
    "${CMAKE_SOURCE_DIR}/include"
)
target_link_libraries(test_dpdk_nl PRIVATE ${DPDK_LIBRARIES} "rt")
target_sources(test_dpdk_nl
    PRIVATE
    ${CMAKE_SOURCE_DIR}/lib/logger.c
)

target_compile_options(test_dpdk_nl
    PUBLIC "-mssse3"
    PRIVATE "-Wall" "-Wpedantic"
)

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