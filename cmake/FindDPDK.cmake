# Try to find dpdk
#
# Once done, this will define
#
# DPDK_FOUND
# DPDK_INCLUDE_DIR
# DPDK_LIBRARIES

find_path(DPDK_INCLUDE_DIR rte_config.h PATH_SUFFIXES dpdk)

message(${DPDK_INCLUDE_DIR})

find_library(DPDK_rte_hash_LIBRARY rte_hash)
find_library(DPDK_rte_kvargs_LIBRARY rte_kvargs)
find_library(DPDK_rte_mbuf_LIBRARY rte_mbuf)
find_library(DPDK_rte_ethdev_LIBRARY rte_ethdev)
find_library(DPDK_rte_mempool_LIBRARY rte_mempool)
find_library(DPDK_rte_ring_LIBRARY rte_ring)
find_library(DPDK_rte_eal_LIBRARY rte_eal)
find_library(DPDK_rte_cmdline_LIBRARY rte_cmdline)
find_library(DPDK_rte_ip_frag_LIBRARY rte_ip_frag)

set(check_LIBRARIES
        ${DPDK_rte_hash_LIBRARY}
        ${DPDK_rte_kvargs_LIBRARY}
        ${DPDK_rte_mbuf_LIBRARY}
        ${DPDK_rte_ethdev_LIBRARY}
        ${DPDK_rte_mempool_LIBRARY}
        ${DPDK_rte_ring_LIBRARY}
        ${DPDK_rte_eal_LIBRARY}
        ${DPDK_rte_cmdline_LIBRARY}
        ${DPDK_rte_ip_frag_LIBRARY}
)

mark_as_advanced(DPDK_INCLUDE_DIR
        DPDK_rte_hash_LIBRARY
        DPDK_rte_kvargs_LIBRARY
        DPDK_rte_mbuf_LIBRARY
        DPDK_rte_ethdev_LIBRARY
        DPDK_rte_mempool_LIBRARY
        DPDK_rte_ring_LIBRARY
        DPDK_rte_eal_LIBRARY
        DPDK_rte_cmdline_LIBRARY
        DPDK_rte_ip_frag_LIBRARY
)

if(EXISTS ${WITH_DPDK_MLX5})
        find_library(DPDK_rte_pmd_mlx5_LIBRARY rte_pmd_mlx5)
        list(APPEND check_LIBRARIES ${DPDK_rte_pmd_mlx5_LIBRARY})
        mark_as_advanced(DPDK_rte_pmd_mlx5_LIBRARY)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(DPDK DEFAULT_MSG
        DPDK_INCLUDE_DIR
        check_LIBRARIES)

if(DPDK_FOUND)
        if(EXISTS ${WITH_DPDK_MLX5})
                list(APPEND check_LIBRARIES -libverbs)
        endif()

        set(DPDK_LIBRARIES
                -Wl,--whole-archive ${check_LIBRARIES} -lpthread -Wl,--no-whole-archive)
endif(DPDK_FOUND)