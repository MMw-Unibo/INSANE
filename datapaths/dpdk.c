#include "../src/nsn_datapath.h"

#define NSN_LOG_IMPLEMENTATION_H
#include "../src/nsn_log.h"

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

struct rte_mempool *direct_pool;
int initialized = 0;

NSN_DATAPATH_INIT(dpdk)
{
    if (initialized) {
        printf("[DPDK MODULE] already initialized %d\n", 1);
        return -1;
    }

    logger_init(NULL);

    nsn_unused(ctx);
    char *rte_argv[] = {
        "nsnd_dpdk",
        "-c", "0x1",
        "-n", "4",
        "--proc-type=auto",
        "--log-level=8",
    };

    size_t rte_argc = array_count(rte_argv);
    int result      = rte_eal_init(rte_argc, rte_argv);
    if (result < 0) {
        log_error("[DPDK MODULE] rte_eal_init failed: %d", rte_strerror(rte_errno));
        return result;
    }

    if (rte_eth_dev_socket_id(0) >= 0 && rte_eth_dev_socket_id(0) != (int)rte_socket_id())
    {
        fprintf(stderr,
                "WARNING: port %u is on remote NUMA node "
                "to polling thread.\n"
                "\tPerformance will not be optimal.\n",
                0);
    }

    fprintf(stderr, "\nCore %u forwarding packets. [Ctrl+C to quit]\n", rte_lcore_id());


    direct_pool = rte_pktmbuf_pool_create("direct_pool", 10240, 64, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    initialized = 1;
    return result;
}

NSN_DATAPATH_TX(dpdk)
{
    nsn_unused(ctx);
    // do tx here
    return 0;
}

NSN_DATAPATH_DEINIT(dpdk)
{
    nsn_unused(ctx);
    rte_mempool_free(direct_pool);
    int res = rte_eal_cleanup();
    printf("[DPDK MODULE] cleaning up dpdk, res: %d", res);
    if (res < 0) {
        log_error("[DPDK MODULE] rte_eal_cleanup failed: %d", rte_strerror(rte_errno));
    }

    initialized = 0;
    return res;
}
