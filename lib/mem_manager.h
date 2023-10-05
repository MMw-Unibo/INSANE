#ifndef INSANE_MEM_MANAGER_H
#define INSANE_MEM_MANAGER_H

#include <rte_mempool.h>

#include "common.h"
#include "ioctx.h"
#include "mem_info.h"
#include "pkt_meta.h"
#include "queue.h"

#include "insane/buffer.h"

#define TOTAL_SHM_SIZE 4096 * 4096
#define MAX_RX_QUEUES  128

typedef struct nsn_rx_queue {
    i64 source_id;
    // nsn_queue_t   *prod;
    // nsn_queue_t   *cons;
    struct rte_ring *prod;
    struct rte_ring *cons;
    mempool_type_t   mptype;
} nsn_rx_queue_t;

//--------------------------------------------------------------------------------------------------
// Memory Manager
//--------------------------------------------------------------------------------------------------
typedef struct nsn_memmanager {
    nsn_meminfo_t info;

    /* Index queues */
    nsn_meminfo_tx_t tx_info[2];
    nsn_rx_queue_t   rx_queues[MAX_RX_QUEUES];
    i32              n_sinks;

    /* Memory Pools */
    // DPDK. The ctx must be a pointer
    struct rte_mempool *dpdk_pool;
    nsn_ioctx_dpdk_t   *dpdk_ctx;
    // Socket. The ctx must NOT be a pointer
    nsn_meminfo_t     *socket_pool;
    nsn_ioctx_socket_t socket_ctx;

} nsn_memmanager_t;

//--------------------------------------------------------------------------------------------------

i32 mem_manager__init(nsn_memmanager_t *mm, const char *name);

void mem_manager__add_mempool(nsn_memmanager_t *mm, void *mempool, mempool_type_t mptype);

i32 mem_manager__consume(nsn_memmanager_t *mm, bool blocks, nsn_buffer_t *buf,
                         mempool_type_t mptype);

void mem_manager__release(nsn_memmanager_t *mm, nsn_buffer_t *buf, mempool_type_t mptype);

nsn_buffer_t mem_manager__acquire(nsn_memmanager_t *mm, mempool_type_t mptype);

void mem_manager__submit(nsn_memmanager_t *mm, nsn_buffer_t *buf, mempool_type_t mptype);

void mem_manager__delete(nsn_memmanager_t *mm);

#endif // INSANE_MEM_MANAGER_H
