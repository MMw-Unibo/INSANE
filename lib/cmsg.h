#ifndef INSANE_CMSG_H
#define INSANE_CMSG_H

#include "common.h"

typedef enum cmsgtype_t {
    mtype_init,
    mtype_alloc_rxqueue,
} cmsgtype_t;

typedef struct cmsg {
    cmsgtype_t  type;
    nsn_appid_t appid;
    nsn_error_t error;
    char        payload[4096];
} cmsg_t;

typedef struct cmsg_init {
    i64  shm_size;
    char shm_name[SHM_MAX_PATH];
    i64  shm_socket_size;
    char shm_socket_name[SHM_MAX_PATH];
    struct {
        u64 prod_offset;
        u64 cons_offset;
        u64 meta_offset;
    } tx[2];
    u64 ioctx_dpdk_offset;
} cmsg_init_t;

typedef struct cmsg_alloc_rxqueue {
    mempool_type_t mptype;
    u32            sink_id;
    i64            source_id;
    u64            offset_prod;
    u64            offset_cons;
    char           prod_name[MAX_QUEUE_NAME_SIZE];
    char           cons_name[MAX_QUEUE_NAME_SIZE];
} cmsg_alloc_rxqueue_t;

#endif // INSANE_CMSG_H
