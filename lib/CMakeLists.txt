file(GLOB HEADER_LIST CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/include/insane/*.h")

# set(HEADER_LIST "${CMAKE_SOURCE_DIR}/include/insane.h")

# Make an automatic library - will be static or dynamic based on user setting
add_library(insane insane.c ${HEADER_LIST})

target_sources(insane
    PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/appctx.c
    ${CMAKE_CURRENT_LIST_DIR}/arp.c
    ${CMAKE_CURRENT_LIST_DIR}/buffer.c
    ${CMAKE_CURRENT_LIST_DIR}/common.c
    ${CMAKE_CURRENT_LIST_DIR}/ip.c
    ${CMAKE_CURRENT_LIST_DIR}/logger.c
    ${CMAKE_CURRENT_LIST_DIR}/mem_manager.c
    ${CMAKE_CURRENT_LIST_DIR}/netdev.c
    ${CMAKE_CURRENT_LIST_DIR}/queue.c
    ${CMAKE_CURRENT_LIST_DIR}/route.c
    ${CMAKE_CURRENT_LIST_DIR}/udp.c
    ${CMAKE_CURRENT_LIST_DIR}/mapper.c
    ${CMAKE_CURRENT_LIST_DIR}/proto_trp.c
)

# We need this directory, and users of our library will need it too
target_include_directories(insane
    PUBLIC
    "${CMAKE_SOURCE_DIR}/include"
)

target_link_libraries(insane ${DPDK_LIBRARIES} "rt")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(insane PRIVATE "-DLOG_LEVEL=100" "-DDEBUG_ETH" "-DDEBUG_IP")
endif()

target_compile_options(insane
    PUBLIC "-mssse3"
    PRIVATE "-Wall" "-Wpedantic"
)
target_compile_features(insane PUBLIC c_std_11)