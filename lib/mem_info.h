#ifndef INSANE_MEM_INFO_H
#define INSANE_MEM_INFO_H

#include "common.h"
#include "pkt_meta.h"
#include "queue.h"

//--------------------------------------------------------------------------------------------------
// Memory Info
//--------------------------------------------------------------------------------------------------
typedef struct nsn_meminfo {
    bool is_master;
    u8  *buffer;
    i64  shm_size;
    i64  used_memory;
    u32  shm_fd;
    char shm_name[SHM_MAX_PATH];
} nsn_meminfo_t;

typedef struct nsn_meminfo_tx {
    // nsn_queue_t   *tx_prod;
    // nsn_queue_t   *tx_cons;
    struct rte_ring *tx_prod;
    struct rte_ring *tx_cons;
    nsn_pktmeta_t   *tx_meta;
} nsn_meminfo_tx_t;

#endif // INSANE_MEM_INFO_H
