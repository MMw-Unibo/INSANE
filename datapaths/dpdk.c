#include "../src/nsn_datapath.h"

#define NSN_LOG_IMPLEMENTATION_H
#include "../src/nsn_log.h"

#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

struct rte_mempool *direct_pool;

NSN_DATAPATH_INIT(dpdk)
{
    logger_init(NULL);

    nsn_unused(ctx);
    char *rte_argv[] = {
        "nsnd_dpdk",
        "-c", "0x1",
        "-n", "4",
        "--proc-type=auto",
    };

    size_t rte_argc = array_count(rte_argv);
    int result = rte_eal_init(rte_argc, rte_argv);

    printf("#### rte_eal_init: %d\n", result);

    direct_pool = rte_pktmbuf_pool_create("direct_pool", 10240, 64, 0,
                                          RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

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
    return rte_eal_cleanup();
}
