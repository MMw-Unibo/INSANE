#ifndef INSANE_APP_CTX_H
#define INSANE_APP_CTX_H

#include <sys/un.h>

#include "common.h"
#include "insane_priv.h"
#include "ioctx.h"
#include "list.h"
#include "mem_info.h"
#include "pkt_meta.h"
#include "queue.h"

#include "insane/buffer.h"
#include "insane/insane.h"

typedef struct nsn_appctx {
    nsn_appid_t id;

    nsn_meminfo_t    info;
    nsn_meminfo_tx_t tx_info[2];

    i32                ctrl_sockfd;
    struct sockaddr_un req_addr;
    struct sockaddr_un res_addr;
    char               ctrl_path[IPC_MAX_PATH_SIZE];

    /* Memory Pools */
    // DPDK
    struct rte_mempool *dpdk_pool;
    nsn_ioctx_dpdk_t   *dpdk_ctx;
    // Socket
    nsn_meminfo_t     *socket_pool;
    nsn_ioctx_socket_t socket_ctx;

} nsn_appctx_t;

//--------------------------------------------------------------------------------------------------
nsn_appctx_t *appctx__init();

i32 appctx__request_new_rx_queue(nsn_appctx_t *ctx, i64 port_id, nsn_sink_inner_t *sink);

i32 appctx__consume(nsn_appctx_t *ctx, bool blocks, nsn_buffer_t *buf, mempool_type_t mptype);

void appctx__release(nsn_appctx_t *ctx, nsn_buffer_t *buf, mempool_type_t mptype);

nsn_buffer_t appctx__acquire(nsn_appctx_t *ctx, mempool_type_t mptype);

void appctx__submit(nsn_appctx_t *ctx, nsn_buffer_t *buf, mempool_type_t mptype);

void appctx__delete(nsn_appctx_t *ctx);

list_head_t *appctx_get_sinks();

#endif // INSANE_APP_CTX_H