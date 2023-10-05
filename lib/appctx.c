#include "appctx.h"

#include <fcntl.h>

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <rte_errno.h>
#include <rte_mbuf.h>

#include "cmsg.h"
#include "common.h"

#include "insane/logger.h"

//--------------------------------------------------------------------------------------------------
#define REPLY_IPC_PATH   "/tmp/insane_ctrl_app"
#define REQUEST_IPC_PATH "/tmp/insane_control.socket"

static i32 __appctx__open_ctrlpath_ipc(nsn_appctx_t *ctx, char *path) {
    ctx->ctrl_sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (ctx->ctrl_sockfd < 0) {
        LOG_ERROR("cannot create control path IPC: %s", strerror(errno));
        return -1;
    }

    ctx->req_addr.sun_family = AF_UNIX;
    strncpy(ctx->req_addr.sun_path, path, sizeof(ctx->req_addr.sun_path) - 1);

    ctx->res_addr.sun_family = AF_UNIX;
    snprintf(ctx->ctrl_path, IPC_MAX_PATH_SIZE, "%s_%d", REPLY_IPC_PATH, getpid());
    strncpy(ctx->res_addr.sun_path, ctx->ctrl_path, IPC_MAX_PATH_SIZE);

    if (bind(ctx->ctrl_sockfd, (struct sockaddr *)&ctx->res_addr, sizeof(ctx->res_addr)) < 0) {
        LOG_ERROR("cannot bind ctrlpath reply IPC '%s': %s", ctx->res_addr.sun_path,
                  strerror(errno));
        return -1;
    }

    return 0;
}

//--------------------------------------------------------------------------------------------------
static i32 __appctx__req_init_info(nsn_appctx_t *ctx, cmsg_init_t *cminit) {
    cmsg_t msg = {
        .type  = mtype_init,
        .appid = getpid(),
    };

    if (sendto(ctx->ctrl_sockfd, &msg, sizeof(msg), 0, (struct sockaddr *)&ctx->req_addr,
               sizeof(ctx->req_addr)) < 0)
    {
        LOG_ERROR("Error sending the intialization request to the INSANE daemon");
        goto error;
    }

    if (recvfrom(ctx->ctrl_sockfd, &msg, sizeof(cmsg_t), 0, NULL, NULL) < 0) {
        LOG_ERROR("no reply received: %s", strerror(errno));
        goto error;
    }

    memcpy(cminit, msg.payload, sizeof(*cminit));

    return msg.appid;

error:
    cminit = NULL;
    return -1;
}

//--------------------------------------------------------------------------------------------------
nsn_appctx_t *appctx__init() {
    nsn_appctx_t *ctx = (nsn_appctx_t *)calloc(1, sizeof(nsn_appctx_t));

    if (__appctx__open_ctrlpath_ipc(ctx, REQUEST_IPC_PATH) < 0) {
        LOG_DEBUG("cannot open control path IPC");
        return NULL;
    }

    cmsg_init_t req;
    ctx->id = __appctx__req_init_info(ctx, &req);
    if (ctx->id < 0) {
        remove(ctx->ctrl_path);
        return NULL;
    }

    strncpy(ctx->info.shm_name, req.shm_name, SHM_MAX_PATH);
    ctx->info.shm_size = req.shm_size;

    nsn_meminfo_t *info = &ctx->info;

    info->shm_fd = shm_open(info->shm_name, O_RDWR, 0);
    if (info->shm_fd == -1) {
        LOG_ERROR("shm_open: %s", strerror(errno));
        return NULL;
    }

    if (ftruncate(info->shm_fd, info->shm_size) == -1) {
        return NULL;
    }

    info->buffer = mmap(NULL, info->shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, info->shm_fd, 0);
    if (info->buffer == MAP_FAILED) {
        return NULL;
    }

    /* DPDK */
    // ctx->tx_info[mempool_dpdk].tx_cons =
    //     (nsn_queue_t *)(info->buffer + req.tx[mempool_dpdk].cons_offset);
    // ctx->tx_info[mempool_dpdk].tx_prod =
    //     (nsn_queue_t *)(info->buffer + req.tx[mempool_dpdk].prod_offset);

    ctx->tx_info[mempool_dpdk].tx_cons = rte_ring_lookup("tx_cons_dpdk");
    ctx->tx_info[mempool_dpdk].tx_prod = rte_ring_lookup("tx_prod_dpdk");

    ctx->tx_info[mempool_dpdk].tx_meta =
        (nsn_pktmeta_t *)(info->buffer + req.tx[mempool_dpdk].meta_offset);
    ctx->dpdk_ctx = (nsn_ioctx_dpdk_t *)(info->buffer + req.ioctx_dpdk_offset);

    struct rte_mempool *mbuf_pool = rte_mempool_lookup("mbuf_pool");
    // FIXME(garbu): this works in Debug mode but not in Release mode.
    // if (mem_manager.mbuf_pool == NULL) {
    //     LOG_ERROR("cannot get mbuf_pool: %s (%d)",
    //               rte_strerror(rte_errno), rte_errno);
    //     goto exit;
    // }
    ctx->dpdk_pool = mbuf_pool;

    /* Socket */
    // ctx->tx_info[mempool_socket].tx_cons =
    //     (nsn_queue_t *)(info->buffer + req.tx[mempool_socket].cons_offset);
    // ctx->tx_info[mempool_socket].tx_prod =
    //     (nsn_queue_t *)(info->buffer + req.tx[mempool_socket].prod_offset);

    ctx->tx_info[mempool_socket].tx_cons = rte_ring_lookup("tx_cons_socket");
    ctx->tx_info[mempool_socket].tx_prod = rte_ring_lookup("tx_prod_socket");

    ctx->tx_info[mempool_socket].tx_meta =
        (nsn_pktmeta_t *)(info->buffer + req.tx[mempool_socket].meta_offset);

    // TODO(lr): free?
    ctx->socket_pool = malloc(sizeof(nsn_meminfo_t));

    strncpy(ctx->socket_pool->shm_name, req.shm_socket_name, SHM_MAX_PATH);
    ctx->socket_pool->shm_size = req.shm_socket_size;

    ctx->socket_pool->shm_fd = shm_open(ctx->socket_pool->shm_name, O_RDWR, 0);
    if (ctx->socket_pool->shm_fd == -1) {
        LOG_ERROR("shm_open: %s (%s)", strerror(errno), ctx->socket_pool->shm_name);
        return NULL;
    }

    if (ftruncate(ctx->socket_pool->shm_fd, ctx->socket_pool->shm_size) == -1) {
        return NULL;
    }

    ctx->socket_pool->buffer = mmap(NULL, ctx->socket_pool->shm_size, PROT_READ | PROT_WRITE,
                                    MAP_SHARED, ctx->socket_pool->shm_fd, 0);
    if (ctx->socket_pool->buffer == MAP_FAILED) {
        perror("Failed socket MMAP: ");
        return NULL;
    }

    for (size_t i = 0; i < RX_SOCK_SLOTS; i++) {
        ctx->socket_ctx.rx_mbuf[i] = &((struct nsn_mbuf *)ctx->socket_pool->buffer)[i];
    }
    for (size_t i = 0; i < TX_SOCK_SLOTS; i++) {
        ctx->socket_ctx.tx_mbuf[i] =
            &((struct nsn_mbuf *)ctx->socket_pool->buffer)[RX_SOCK_SLOTS + i];
    }
    ctx->socket_pool->used_memory = (RX_SOCK_SLOTS + TX_SOCK_SLOTS) * NSN_SLOT_SIZE;

    return ctx;
}

//--------------------------------------------------------------------------------------------------
static i32 __appctx__req_new_rx_queue(nsn_appctx_t *ctx, i64 source_id,
                                      cmsg_alloc_rxqueue_t *carxmsg) {

    cmsg_t msg = {
        .type  = mtype_alloc_rxqueue,
        .appid = ctx->id,
    };

    carxmsg->source_id = source_id;
    memcpy(msg.payload, carxmsg, sizeof(*carxmsg));

    if (sendto(ctx->ctrl_sockfd, &msg, sizeof(msg), 0, (struct sockaddr *)&ctx->req_addr,
               sizeof(ctx->req_addr)) < 0)
    {
        LOG_ERROR("Error sending the intialization request to the INSANE daemon");
        goto error;
    }

    if (recvfrom(ctx->ctrl_sockfd, &msg, sizeof(cmsg_t), 0, NULL, NULL) < 0) {
        LOG_ERROR("no reply received: %s", strerror(errno));
        goto error;
    }

    if (msg.error != 0) {
        LOG_ERROR("Received error when asking space for new sink: %d", msg.error);
        goto error;
    }

    memcpy(carxmsg, msg.payload, sizeof(*carxmsg));

    return carxmsg->sink_id;

error:
    carxmsg = NULL;
    return -1;
}

//--------------------------------------------------------------------------------------------------
i32 appctx__request_new_rx_queue(nsn_appctx_t *ctx, i64 source_id, nsn_sink_inner_t *sink) {
    cmsg_alloc_rxqueue_t req;
    // Send parameters
    req.mptype = sink->mptype;
    // Actual send and receive
    if (__appctx__req_new_rx_queue(ctx, source_id, &req) < 0) {
        remove(ctx->ctrl_path);
        goto error;
    }

    // Received parameters
    sink->id        = req.sink_id;
    sink->source_id = source_id;
    // sink->rx_cons   = (nsn_queue_t *)(ctx->info.buffer + req.offset_cons);
    // sink->rx_prod   = (nsn_queue_t *)(ctx->info.buffer + req.offset_prod);

    sink->rx_cons = rte_ring_lookup(req.cons_name);
    sink->rx_prod = rte_ring_lookup(req.prod_name);

    return 0;

error:
    sink = NULL;
    return -1;
}

//--------------------------------------------------------------------------------------------------
i32 appctx__consume(nsn_appctx_t *ctx, bool blocks, nsn_buffer_t *buf, mempool_type_t mptype) {
    if (blocks) {
        // buf->index = nsn_queue__pop(ctx->tx_info[mptype].tx_prod);
        while (rte_ring_dequeue(ctx->tx_info[mptype].tx_prod, (void **)&buf->index) < 0) {
            SPIN_LOOP_PAUSE();
        }
    } else {
        // i32 tmp_index = nsn_queue__try_pop(ctx->tx_info[mptype].tx_prod);

        i32 tmp_index;
        i32 res = rte_ring_dequeue(ctx->tx_info[mptype].tx_prod, (void **)&tmp_index);
        if (res < 0) {
            return -1;
        }
        buf->index = tmp_index;
    }

    // TODO: This is where Garbu's idea about "interface" should work
    switch (mptype) {
    case mempool_dpdk:
        buf->data = (uint8_t *)ctx->dpdk_ctx->tx_mbuf[buf->index];
        break;
    case mempool_socket:
        buf->data = (uint8_t *)ctx->socket_ctx.tx_mbuf[buf->index];
        break;
    }

    return 0;
}

//--------------------------------------------------------------------------------------------------
void appctx__release(nsn_appctx_t *ctx, nsn_buffer_t *buf, mempool_type_t mptype) {
    // nsn_queue__push(ctx->tx_info[mptype].tx_cons, buf->index);
    rte_ring_enqueue(ctx->tx_info[mptype].tx_cons, (void *)(i64)buf->index);
}

//--------------------------------------------------------------------------------------------------
nsn_buffer_t appctx__acquire(nsn_appctx_t *ctx, mempool_type_t mptype) {
    nsn_buffer_t buf;
    // buf.index = nsn_queue__pop(ctx->tx_info[mptype].tx_cons);
    while (rte_ring_dequeue(ctx->tx_info[mptype].tx_cons, (void **)&buf.index) > 0) {
        SPIN_LOOP_PAUSE();
    }

    // TODO: This is where Garbu's idea about "interface" should work
    switch (mptype) {
    case mempool_dpdk:
        buf.data = (uint8_t *)ctx->dpdk_ctx->tx_mbuf[buf.index];
        break;
    case mempool_socket:
        buf.data = (uint8_t *)ctx->socket_ctx.tx_mbuf[buf.index];
        break;
    }

    return buf;
}

//--------------------------------------------------------------------------------------------------
void appctx__submit(nsn_appctx_t *ctx, nsn_buffer_t *buf, mempool_type_t mptype) {
    // nsn_queue__push(ctx->tx_info[mptype].tx_prod, buf->index);
    rte_ring_enqueue(ctx->tx_info[mptype].tx_prod, (void *)(i64)buf->index);
}

//--------------------------------------------------------------------------------------------------
void appctx__delete(nsn_appctx_t *ctx) {
    LOG_TRACE("cleaning the applicaton context");

    close(ctx->ctrl_sockfd);

    LOG_TRACE("deleting IPC file %s", ctx->ctrl_path);
    if (remove(ctx->ctrl_path) != 0) {
        LOG_WARN("cannot delete IPC file: %s", strerror(errno));
    }

    munmap(ctx->info.buffer, ctx->info.shm_size);
    close(ctx->info.shm_fd);
}