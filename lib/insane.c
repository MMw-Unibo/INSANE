#include "insane/insane.h"

#include "appctx.h"
#include "common.h"
#include "ethernet.h"
#include "insane_priv.h"
#include "ip.h"
#include "mapper.h"
#include "udp.h"

#include "insane/logger.h"

#include <sys/mman.h>

#include <rte_eal.h>
#include <rte_mbuf.h>

#define ARG_LENGTH  64
#define MAX_SINKS   16
#define MAX_SOURCES 16

const char *app_name  = "app";
const char *proc_type = "--proc-type=secondary";

static nsn_appctx_t      *app_ctx;
static nsn_sink_inner_t   sinks[MAX_SINKS];
static nsn_source_inner_t sources[MAX_SOURCES];
static u32                n_sinks   = 0;
static u32                n_sources = 0;

//--------------------------------------------------------------------------------------------------
int nsn_init() {
    int   argc = 2;
    char *argv[argc];
    argv[0] = (char *)calloc(ARG_LENGTH, sizeof(char));
    argv[1] = (char *)calloc(ARG_LENGTH, sizeof(char));

    strncpy(argv[0], app_name, ARG_LENGTH);
    strncpy(argv[1], proc_type, ARG_LENGTH);

    /* Init the DPDK environment*/
    i32 ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        LOG_TRACE("cannot init EAL\n");
        return -1;
    }

    if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
        LOG_TRACE("process must be secondary\n");
        goto exit_with_err;
    }

    app_ctx = appctx__init();
    if (!app_ctx) {
        LOG_ERROR("cannot initialize the memory for the application");
        goto exit_with_err;
    }

    return 0;

exit_with_err:

    rte_eal_cleanup();
    return -1;
}

//--------------------------------------------------------------------------------------------------
int nsn_close() {
    munmap(app_ctx->socket_pool->buffer, app_ctx->info.shm_size);
    close(app_ctx->socket_pool->shm_fd);
    appctx__delete(app_ctx);
    return rte_eal_cleanup();
}

//--------------------------------------------------------------------------------------------------
nsn_stream_t nsn_create_stream(nsn_options_t *opts) {
    nsn_stream_t stream = {*opts};
    return stream;
}

//--------------------------------------------------------------------------------------------------
nsn_source_t nsn_create_source(nsn_stream_t *stream, uint32_t source_id) {
    sources[n_sources].id     = source_id;
    sources[n_sources].mptype = map_qos_to_transport(&stream->options);
    return n_sources++;
}

//--------------------------------------------------------------------------------------------------
int nsn_destroy_source(nsn_source_t source) {
    // TODO: implement this function
    LOG_ERROR("nsn_destroy_source is still unimplemented\n");
    return -1;
}

//--------------------------------------------------------------------------------------------------
nsn_buffer_t nsn_get_buffer(nsn_source_t source, size_t size, int flags) {
    nsn_buffer_t buf;
    memset(&buf, 0, sizeof(buf));

    // TODO(lr) Check max size wrt MTU

    nsn_source_inner_t *src = &sources[source];

    if (flags & NSN_BLOCKING) {
        while (rte_ring_dequeue(app_ctx->tx_info[src->mptype].tx_cons, (void **)&buf.index) < 0)
            SPIN_LOOP_PAUSE();
    } else {
        rte_ring_dequeue(app_ctx->tx_info[src->mptype].tx_cons, (void **)&buf.index);
    }

    switch (src->mptype) {
    case mempool_dpdk: {
        uint8_t         *mbuf_data = (uint8_t *)app_ctx->dpdk_ctx->tx_mbuf[buf.index];
        struct rte_mbuf *rte_mbuf  = (struct rte_mbuf *)mbuf_data;
        uint8_t         *data      = rte_pktmbuf_mtod(rte_mbuf, uint8_t *);
        buf.data =
            (data + ETHERNET_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + INSANE_HEADER_LEN);
    } break;
    case mempool_socket: {
        uint8_t *data = (uint8_t *)app_ctx->socket_ctx.tx_mbuf[buf.index];
        buf.data      = data + INSANE_HEADER_LEN;
    } break;
    }

    return buf;
}

//--------------------------------------------------------------------------------------------------
int nsn_emit_data(nsn_source_t source, nsn_buffer_t *buf) {

    nsn_source_inner_t *src = &sources[source];

    nsn_pktmeta_t *meta = &app_ctx->tx_info[src->mptype].tx_meta[buf->index];
    meta->proto         = nsn_proto_ipv4_udp;
    meta->payload_len   = buf->len + INSANE_HEADER_LEN;

    ((nsn_hdr_t *)(buf->data - INSANE_HEADER_LEN))->source_id = src->id;

    LOG_INFO("Sending buf with index %d and length %d (id=%ld)", buf->index, buf->len, src->id);

    while (rte_ring_enqueue(app_ctx->tx_info[src->mptype].tx_prod, (void *)(i64)buf->index) < 0)
        SPIN_LOOP_PAUSE();

    // nsn_queue__push(app_ctx->tx_info[src->mptype].tx_prod, buf->index);
    return 0;
}

int nsn_check_emit_outcome(nsn_source_t source, int id) {
    // TODO
    return 0;
}

//--------------------------------------------------------------------------------------------------
nsn_sink_t nsn_create_sink(nsn_stream_t *stream, int64_t source_id, handle_data_cb cb) {
    // TODO(lr): check params
    // TODO(lr): CALLBACKS!
    u32 new_sink_id = n_sinks++;

    // TODO: This should be a totally different thing. We shouls base this choice on user
    // preference, but also on the specific technologies available at deployment site. Like:
    // getMPTfromQoS()?
    if (stream->options.datapath == datapath_fast &&
        stream->options.consumption == consumption_high) {
        sinks[new_sink_id].mptype = mempool_dpdk;
    } else {
        sinks[new_sink_id].mptype = mempool_socket;
    }
    if (appctx__request_new_rx_queue(app_ctx, source_id, &sinks[new_sink_id]) < 0) {
        LOG_ERROR("cannot create a new sink");
        return -1;
    }

    return new_sink_id;
}

//--------------------------------------------------------------------------------------------------
int nsn_destroy_sink(nsn_sink_t sink) {
    // TODO: implement this function
    LOG_ERROR("nsn_destroy_sink is still unimplemented\n");
    return -1;
}

//--------------------------------------------------------------------------------------------------
int nsn_data_available(nsn_sink_t sink, int flags) {
    // TODO(lr): Requires a change to the underlying queue. Future work
    LOG_ERROR("Data Available: unimplemented data reception mode");
    return 0;
}

//--------------------------------------------------------------------------------------------------
nsn_buffer_t nsn_consume_data(nsn_sink_t sink, int flags) {
    // TODO(lr): Use flag to distinguish different reception mode
    // TODO(lr): check params
    nsn_sink_inner_t *snk = &sinks[sink];
    nsn_buffer_t      buf = {0};

    if (flags == 1) { // ASYNC
        if (rte_ring_dequeue(sinks[sink].rx_prod, (void **)&buf.index) < 0) {
            buf.index = -1;
            return buf;
        }
    } else {
        // buf.index             = nsn_queue__pop(sinks[sink].rx_prod);
        while (rte_ring_dequeue(sinks[sink].rx_prod, (void **)&buf.index) < 0) {
            SPIN_LOOP_PAUSE();
        }
    }

    LOG_TRACE("sink %d index is: %d", sinks[sink].id, buf.index);

    switch (snk->mptype) {
    case mempool_dpdk: {
        uint8_t         *mbuf_data = (uint8_t *)app_ctx->dpdk_ctx->rx_mbuf[buf.index];
        struct rte_mbuf *rte_mbuf  = (struct rte_mbuf *)mbuf_data;
        uint8_t         *data      = rte_pktmbuf_mtod(rte_mbuf, uint8_t *);
        buf.data =
            (data + ETHERNET_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + INSANE_HEADER_LEN);
    } break;
    case mempool_socket: {
        uint8_t *data = (uint8_t *)app_ctx->socket_ctx.rx_mbuf[buf.index];
        buf.data      = (data + INSANE_HEADER_LEN);
    } break;
    }

    return buf;
}

//--------------------------------------------------------------------------------------------------
void nsn_release_data(nsn_sink_t sink, nsn_buffer_t *buf) {
    // TODO(lr): check params
    // nsn_queue__push(sinks[sink].rx_cons, buf->index);
    while (rte_ring_enqueue(sinks[sink].rx_cons, (void *)(i64)buf->index) < 0) {
        SPIN_LOOP_PAUSE();
    }
}