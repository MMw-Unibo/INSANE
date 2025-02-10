#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_udp.h>

#include <tle_ctx.h>
#include <tle_event.h>
#include <tle_tcp.h>

// REDME: This test assumes that we pass the -a argument to the DPDK EAL,
// which selects the device to be used. If not passed, the test will select
// the device available on port_id = 0.

// A simple macro used to check if there are enough command line args
#define ENSURE_ONE_MORE_ARGUMENT(argc, argv, i, argName)                                           \
    if (i + 1 >= argc) {                                                                           \
        usage(argc, argv);                                                                         \
        fprintf(stderr, "! Error: missing value for %s argument\n", argName);                      \
        return false;                                                                              \
    }

#define MSG              "hello, DPDK!"
#define MTU              1500
#define MAX_PAYLOAD_SIZE 1472
#define MIN_PAYLOAD_SIZE 16

#define INSANE_PORT    9999
#define IP_DEFAULT_TTL 64

#define IP_SRC  RTE_IPV4(192, 168, 56, 211)
#define IP_DST  RTE_IPV4(192, 168, 56, 212)
#define MAC_SRC "b8:ce:f6:4d:ef:1c"
#define MAC_DST "b8:ce:f6:4d:ef:2e"

typedef enum role {
    role_sink,
    role_source,
    role_ping,
    role_pong,
} role_t;

static char *role_strings[] = {"SINK", "SOURCE", "PING", "PONG"};

typedef struct test_config {
    role_t   role;
    uint32_t payload_size;
    uint64_t sleep_time;
    uint64_t max_msg;
    uint16_t burst_size;
    uint16_t port_id;
    uint16_t queue_id;
} test_config_t;

struct test_data {
    uint64_t cnt;
    uint64_t tx_time;
};

// TEST STATE
volatile bool g_running  = true;
volatile bool queue_stop = false;

//--------------------------------------------------------------------------------------------------
// TLDK STATE
#define MAX_STREAMS         16
#define RSS_HASH_KEY_LENGTH 64
#define MAX_PKT_BURST       32

struct netbe_port {
    uint32_t              id;
    uint32_t              nb_lcore;
    uint32_t              lcore_id;
    uint32_t              mtu;
    uint64_t              rx_offload;
    uint64_t              tx_offload;
    uint32_t              ipv4;
    struct in6_addr       ipv6;
    struct rte_ether_addr mac;
    uint32_t              hash_key_size;
    uint8_t               hash_key[RSS_HASH_KEY_LENGTH];
};

struct tldk_ep {
    struct tle_ctx     *ctx;
    struct tle_dev     *dev;
    struct rte_mempool *head_mp;
    struct netbe_port  port;
};

struct tldk_stream_handle {
    struct tle_stream *stream;
    struct tle_evq    *ereq;
    struct tle_evq    *rxeq;
    struct tle_evq    *txeq;
};

static struct tldk_ep tldk_ctx;

//--------------------------------------------------------------------------------------------------
void handle(int signum) {
    (void)(signum);
    fprintf(stderr, "Received CTRL+C. Exiting!\n");
    g_running  = false;
    queue_stop = true;
}

//--------------------------------------------------------------------------------------------------
void usage(int argc, char *argv[]) {
    (void)(argc);
    printf("Usage: %s [EAL-ARGS] -- [MODE] [OPTIONS]    \n"
           "MODE: source|sink|ping|pong                 \n"
           "OPTIONS:                                    \n"
           "-h: display this message and exit           \n"
           "-s: message payload size in bytes           \n"
           "-n: max messages to send (0 = no limit)     \n"
           "-b: burst size for send and receive         \n"
           "-r: configure sleep time (s) in send        \n",
           argv[0]);
}

//--------------------------------------------------------------------------------------------------
static inline uint64_t get_clock_realtime_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

// Callback necessary for the TLDK context.
// This function returns the tle_dest info associated with the input address
// In their example, they use a routing table for that. We do not need this, as
// we plan to use this at end hosts, but we still need to provide the tle_dest info
static int prepare_dst_headers(void *data, const struct in_addr *addr, struct tle_dest *res) {

    // TODO: tldk_ctx is now a global variable. In the INSANE plugin, we will pass
    // the endpoint info as the opaque data pointer
    (void)data;
    struct tldk_ep *ctx = &tldk_ctx;

    // TODO: what are we supposed to do with addr?
    (void)addr;

    // This is the device that will be used to send out the packet
    // It must be set, or it will cause the caller to fail
    res->dev = ctx->dev;

    // These are necessary for header manipulations
    res->mtu    = 1514; // THIS MUST BE SET TO THE MTU OF THE DEVICE!!!! OR IT WILL FAIL
    res->l2_len = RTE_ETHER_HDR_LEN;
    res->l3_len = sizeof(struct rte_ipv4_hdr);

    /* Ethernet, IP headers*/
    struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)res->hdr;
    struct rte_ipv4_hdr  *ip_hdr  = (struct rte_ipv4_hdr *)(eth_hdr + 1);

    /* Ethernet header */
    rte_eth_macaddr_get(ctx->port.id, &eth_hdr->src_addr);
    rte_ether_unformat_addr(MAC_DST, &eth_hdr->dst_addr); // Only DPDK 23+
    // eth_parse(MAC_DST, &eth_hdr->dst_addr);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    /* IP header */
    ip_hdr->version_ihl     = RTE_IPV4_VHL_DEF;
    ip_hdr->type_of_service = 0;
    ip_hdr->fragment_offset = 0;
    ip_hdr->time_to_live    = 64;
    ip_hdr->next_proto_id   = IPPROTO_TCP;
    ip_hdr->packet_id       = 0;
    // TODO: These should be set later, right?
    // ip_hdr->total_length    = rte_cpu_to_be_16(pkt_len);
    // ip_hdr->src_addr        = rte_cpu_to_be_32(src_ip);
    // ip_hdr->dst_addr        = rte_cpu_to_be_32(dst_ip);

    // This is the mempool that will be used for fragmentation and acks
    res->head_mp = ctx->head_mp;

    // OL flags for individual mbufs
    // TODO: Is this necessary??
    // res->ol_flags = RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4;

    return 0;
}

// Helper function 
static void init_tldk_ctx(test_config_t *params) {
    /***** TLDK: Initialize the TLDK context, then open a stream. 
     * The context consists of 4 elements:
     *  1. rte_mempool  - Header pool for fragment headers and control packets
     *  2. tle_ctx      - Context of a TLK enpoint (one per thread)!
     *  3. netbe_port   - Device port info 
     *  4. tle_dev      - Device to send packets through
     */

    /* 1. Allocate the header mempool. TODO: only for headers? Please check! */
    tldk_ctx.head_mp = rte_pktmbuf_pool_create("frag_mempool", 10240, 64, 0,
                                                    RTE_MBUF_DEFAULT_DATAROOM, rte_socket_id());
    if (tldk_ctx.head_mp == NULL) {
        printf("RTE_ERROR: %s\n", rte_strerror(rte_errno));
        rte_exit(EXIT_FAILURE, "cannot create the frag mempool\n");
    }

    /* 2. Create the TCP context */
    uint16_t socket_id = rte_eth_dev_socket_id(params->port_id);
    struct tle_ctx_param ctx_params = {
        .socket_id         = socket_id,
        .proto             = TLE_PROTO_TCP,
        .max_streams       = 16, // TODO: This is the num of TCP connections?
        .free_streams      = {.max = 0, .min = 0},
        .max_stream_rbufs  = 1024,
        .max_stream_sbufs  = 1024,
        .send_bulk_size    = 32,
        .flags             = 0,
        .hash_alg          = TLE_JHASH,
        .secret_key.u64[0] = rte_rand(),
        .secret_key.u64[1] = rte_rand(),
        .lookup4           = prepare_dst_headers, // will be called by send() to get IPv4 packet destination info
        .lookup4_data      = NULL,                // opaque data pointer for lookup4() callback => The ctx itself
    };
    tldk_ctx.ctx = tle_ctx_create(&ctx_params);

    /* 3. Prepare the local TCP port */
    struct sockaddr_in local_ip;
    local_ip.sin_addr.s_addr = rte_cpu_to_be_32(IP_SRC);
    struct netbe_port netbe_port = {
        .id         = params->port_id,
        .nb_lcore   = 1,    // The lcore_id will be set later in the backend thread
        .mtu        = 1514, // This must be set to the device MTU
        .ipv4       = local_ip.sin_addr.s_addr,
        .tx_offload = RTE_ETH_RX_OFFLOAD_IPV4_CKSUM |
                      RTE_ETH_TX_OFFLOAD_TCP_CKSUM, // Very important! If not available,
                                                    // double-check the TLDK checksum logic...
    };
    rte_eth_macaddr_get(netbe_port.id, &netbe_port.mac);

    tldk_ctx.port = netbe_port;

    /* 4. Prepare the device, including event queues between frontend and backend threads */
    struct tle_dev_param dprm = (struct tle_dev_param){
        .rx_offload  = netbe_port.rx_offload,
        .tx_offload  = netbe_port.tx_offload,
        .local_addr4 = local_ip.sin_addr,
    };

    tldk_ctx.dev = tle_add_dev(tldk_ctx.ctx, &dprm);
    if (tldk_ctx.dev == NULL) {
        printf("tle_add_dev() failed\n");
    }
}

// Helper function
static struct tldk_stream_handle create_tldk_stream(uint16_t socket_id) {

    struct tle_evq_param eprm = {
        .max_events = 1024,
        .socket_id  = socket_id,
    };

    struct tle_evq *ereq = tle_evq_create(&eprm); // ER queue
    struct tle_evq *rxeq = tle_evq_create(&eprm); // RX queue
    struct tle_evq *txeq = tle_evq_create(&eprm); // TX queue
    if (ereq == NULL || rxeq == NULL || txeq == NULL) {
        printf("Error creating event queues\n");
        rte_exit(EXIT_FAILURE, "Error creating event queues\n");
    }
    
    // Allocate and initialize one event per TX, RX, ER queues.
    // TODO: These evq are linked lists protected by a lock. Why not use a rte_ring?
    struct tle_event *rxev = tle_event_alloc(rxeq, NULL);
    struct tle_event *txev = tle_event_alloc(txeq, NULL);
    struct tle_event *erev = tle_event_alloc(ereq, NULL);
    tle_event_active(txev, TLE_SEV_DOWN);
    tle_event_active(rxev, TLE_SEV_DOWN);
    tle_event_active(erev, TLE_SEV_DOWN);

    // Prepare SRC and DST address for the stream
    struct sockaddr_in src_addr;
    src_addr.sin_family      = AF_INET;
    src_addr.sin_port        = rte_cpu_to_be_16(INSANE_PORT);
    src_addr.sin_addr.s_addr = rte_cpu_to_be_32(IP_SRC);
    struct sockaddr_in dst_addr;    // TODO: Should we set this here? Or later at connect()/accept()?
    dst_addr.sin_family      = AF_INET;
    dst_addr.sin_port        = rte_cpu_to_be_16(INSANE_PORT);
    dst_addr.sin_addr.s_addr = rte_cpu_to_be_32(IP_DST);

    struct sockaddr_storage src_addr_tldk, dst_addr_tldk;
    memcpy(&src_addr_tldk, &src_addr, sizeof(src_addr));
    memcpy(&dst_addr_tldk, &dst_addr, sizeof(dst_addr));

    struct tle_tcp_stream_param stream_params = {
        .addr =
            {
                .local  = src_addr_tldk,
                .remote = dst_addr_tldk,
            },
        .cfg = // This associates the events queues to the stream
        {
            .nb_retries = 3,
            .err_ev     = erev,
            .recv_ev    = rxev,
            .send_ev    = txev,
        },

    };

    // Finally, open the stream
    struct tle_stream *stream = tle_tcp_stream_open(tldk_ctx.ctx, &stream_params);
    if (stream == NULL) {
        printf("Error opening TCP stream: (%d): %s\n", rte_errno, rte_strerror(rte_errno));
        exit(EXIT_FAILURE);
    }

    return (struct tldk_stream_handle){stream, ereq, rxeq, txeq};
}

/* (Logical) backend thread. */
static int be_tcp() {
    uint16_t         nb_rx, nb_valid, nb_tx, nb_arp, nb_tx_tcp, nb_tx_actual;
    struct rte_mbuf *rx_pkt[MAX_PKT_BURST];
    struct rte_mbuf *rp[MAX_PKT_BURST];
    int32_t          rc[MAX_PKT_BURST];
    struct rte_mbuf *tx_pkt[MAX_PKT_BURST];
    int              ret;

    (void)(nb_arp);

    tldk_ctx.port.lcore_id = rte_lcore_id();
    struct tle_dev *dev     = tldk_ctx.dev;

    // 1. Receive
    nb_arp = 0;
    nb_rx  = rte_eth_rx_burst(tldk_ctx.port.id, 0, rx_pkt, MAX_PKT_BURST);
    if (nb_rx) {
        // If they are TCP packets, set the l2, l3, l4 len accordingly and meet the
        // pre-conditions of tle_tcp_rx_bulk. Otherwise, drop the packet; if ARP, 
        // handle the request before discarding the packet.
        for (int i = 0; i < nb_rx; i++) {
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(rx_pkt[i], struct rte_ether_hdr *);
            // Check ethernet type
            if (rte_be_to_cpu_16(eth_hdr->ether_type) != RTE_ETHER_TYPE_IPV4) {
                // if (rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_ARP) {
                //     // Prepare ARP reply
                //     arp_reply(tldk_ctx.port->id, rx_pkt[i]);
                //     // Append the mbuf to the TX queue
                //     tx_pkt[nb_arp] = rx_pkt[i];
                //     nb_arp++;
                // }
                continue;
            }
            // Check IP protocol
            struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
            if (ip_hdr->next_proto_id != IPPROTO_TCP) {
                printf("IP Packet type not TCP: %d\n", ip_hdr->next_proto_id);
                continue;
            }

            // Check TCP flags (prereq of tle_tcp_rx_bulk)
            if ((rx_pkt[i]->packet_type & (RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L3_IPV6)) == 0) {
                printf("Packet type L3: %d (must be != 0)\n",
                       rx_pkt[i]->packet_type & (RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L3_IPV6));
                continue;
            }
            if ((rx_pkt[i]->packet_type & (RTE_PTYPE_L4_TCP)) == 0) {
                printf("Packet type L4: %d (must be != 0)\n",
                       rx_pkt[i]->packet_type & (RTE_PTYPE_L4_TCP));
                continue;
            }

            // Compute l2, l3 len (prereq of tle_tcp_rx_bulk)
            rx_pkt[i]->l2_len = RTE_ETHER_HDR_LEN;
            rx_pkt[i]->l3_len = sizeof(struct rte_ipv4_hdr);
            // Get the TCP header to compute the l4 len
            struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)(ip_hdr + 1);
            /* Data Off specifies the size of the TCP header in 32-bit words. Note that the
             * actual field only occupies the 4 most significant bits */
            rx_pkt[i]->l4_len = (uint16_t)(tcp_hdr->data_off >> 4) * 4;
        }

        // TCP processing
        nb_valid = tle_tcp_rx_bulk(dev, rx_pkt, rp, rc, nb_rx);

        // Drop packets that are not valid or not to be delivered
        for (int j = 0; j < (nb_rx - nb_valid); j++) {
            rte_pktmbuf_free(rp[j]);
        }
    }
    
    // 2. Progress the TCP state machine
    ret = tle_tcp_process(tldk_ctx.ctx, MAX_STREAMS);
    if (ret < 0) {
        printf("Error processing TCP state machine: %s\n", strerror(ret));
    }
    
    // 3. Transmit
    nb_tx_tcp = tle_tcp_tx_bulk(dev, tx_pkt + nb_arp, MAX_PKT_BURST - nb_arp);
    nb_tx = nb_arp + nb_tx_tcp;
    nb_tx_actual = 0;
    while (nb_tx_actual < nb_tx) {
        nb_tx_actual += rte_eth_tx_burst(tldk_ctx.port.id, 0, tx_pkt, nb_tx);
    }

    return 0;
}

//--------------------------------------------------------------------------------------------------
// source
void do_source(struct rte_mempool *mempool, struct tldk_stream_handle str_hdl, test_config_t *params) {
    uint64_t          counter = 0;
    struct test_data *data;
    int               ret;
    uint64_t          to_send, actual_burst;

    /* 1. Connect the stream to the destination */
    struct sockaddr_in dst_addr;
    dst_addr.sin_family      = AF_INET;
    dst_addr.sin_port        = rte_cpu_to_be_16(INSANE_PORT);
    dst_addr.sin_addr.s_addr = rte_cpu_to_be_32(IP_DST);

    ret = tle_tcp_stream_connect(str_hdl.stream, (struct sockaddr*)&dst_addr); // async!
    if (ret < 0) {
        printf("Error connecting TCP stream: (%d): %s\n", ret, strerror(ret));
        return;
    }

    /* 2. Wait for the connection to be established */
    // NOTE: We check the TX Queue as it will report the completions of our TX requests!
    uint32_t ne_tx, ne_err, np_tx;
    char     *evdata[32];
    do {
        be_tcp();
        ne_tx  = tle_evq_get(str_hdl.txeq, (const void**)evdata, MAX_PKT_BURST);
        ne_err = tle_evq_get(str_hdl.ereq, (const void**)evdata, MAX_PKT_BURST);
    } while (!ne_tx && !ne_err);

    if (ne_err > 0) {
        printf("Impossible to connect to the server\n");
        return;
    }

    fprintf(stderr, "\nClient connected!\n");
    sleep(1);

    // Pre-allocate the mbufs, populate them, and prepare headers
    struct rte_mbuf *mbuf[params->burst_size];
    uint64_t tx_time;
    uint16_t payload_offset = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
                                           sizeof(struct rte_tcp_hdr) + 20; // 20 bytes of options
    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {

        if (params->sleep_time) {
            sleep(params->sleep_time);
        }

        to_send      = params->max_msg - counter;
        actual_burst = (to_send >= params->burst_size) ? params->burst_size : to_send;
        tx_time = get_clock_realtime_ns();
        rte_pktmbuf_alloc_bulk(mempool, mbuf, actual_burst);

        // Allocate a burst of mbufs, prepare them (at least len), and fill payload
        for (uint16_t i = 0; i < actual_burst; i++) {
            // First set the mbuf len (or the adjust won't work)
            mbuf[i]->pkt_len = mbuf[i]->data_len = payload_offset + params->payload_size;

            data          = (struct test_data*)rte_pktmbuf_adj(mbuf[i], payload_offset);
            data->tx_time = tx_time;
            data->cnt     = counter++;
            rte_strscpy((char*)(data + 1), MSG, strlen(MSG));
        }

        /* Send the packet(s) to the TLDK stack */
        np_tx = 0;
        do {
            np_tx += tle_tcp_stream_send(str_hdl.stream, mbuf + np_tx, actual_burst - np_tx);
            be_tcp();
        } while(np_tx < actual_burst);
    }

    
    while(tle_tcp_stream_tx_pending(str_hdl.stream)) {
        be_tcp();
    }
    
    fprintf(stderr, "Sent %lu packets\n", counter);

    ret = tle_tcp_stream_close(str_hdl.stream);
    if (ret != 0) {
        printf("Close: %s\n", strerror(ret));
    }

    // Transmit the remaining packets
    be_tcp();
}

//--------------------------------------------------------------------------------------------------
// sink
void do_sink(struct rte_mempool *mempool, struct tldk_stream_handle str_hdl, test_config_t *params) {
    uint32_t                  nb_rx, nb_req, nb_syn, nb_err, ne_err, rx_size;
    uint64_t                  counter, first_time, last_time;
    int                       ret;
    struct tle_tcp_stream_cfg prm[MAX_PKT_BURST];
    struct tle_stream        *client_streams[MAX_PKT_BURST];
    char                     *data[MAX_PKT_BURST];
    struct rte_mbuf          *rx_buf[MAX_PKT_BURST];

    (void)(mempool);

    // Open the TCP connection as a server
    ret = tle_tcp_stream_listen(str_hdl.stream);
    if (ret != 0) {
        printf("Listen: %s\n", strerror(ret));
        return;
    }
    printf("TCP server waiting for connections\n");

    /* look for syn events */
    do {
        be_tcp();
        nb_syn = tle_evq_get(str_hdl.rxeq, (const void**)data, MAX_PKT_BURST);
        nb_err = tle_evq_get(str_hdl.ereq, (const void**)data, MAX_PKT_BURST);
    } while (!nb_syn && !nb_err);

    if (nb_err > 0) {
        printf("Error while waiting for incoming connections\n");
        return;
    }

    // Accept an incoming connection
    nb_req = tle_tcp_stream_accept(str_hdl.stream, client_streams, MAX_PKT_BURST);
    if (nb_req == 0) {
        printf("Accept: no client found\n");
        return;
    }    

    /* For each accepted connection, we must set the proper config */
    // Here I assume I only accept 1 connection
    struct tle_stream         *client_stream = client_streams[0];
    struct tle_tcp_stream_cfg *cfg           = &prm[0];
    // Allocate and activate the events from the same queue. "1" refers to the client stream and
    // is used to differentiate the event from syn connections
    cfg->err_ev  = tle_event_alloc(str_hdl.ereq, (void *)1);
    cfg->recv_ev = tle_event_alloc(str_hdl.rxeq, (void *)1);
    cfg->send_ev = tle_event_alloc(str_hdl.txeq, (void *)1);
    tle_event_active(cfg->send_ev, TLE_SEV_DOWN);
    tle_event_active(cfg->recv_ev, TLE_SEV_DOWN);
    tle_event_active(cfg->err_ev, TLE_SEV_DOWN);

    // Update the stream with the new configuration
    uint32_t res = tle_tcp_stream_update_cfg(client_streams, prm, nb_req);
    if (res != nb_req) {
        printf("Error updating the stream cfg\n");
        exit(1);
    }

    // TODO: It looks like this feature is not well implemented...
    // struct tle_tcp_stream_addr addr;
    // tle_tcp_stream_get_addr(stream, &addr);
    // struct sockaddr_in *client_addr = (struct sockaddr_in *)&addr.local;
    // struct sockaddr_in *server_addr = (struct sockaddr_in *)&addr.remote;
    // printf("Accepted connection from %s to %s\n", inet_ntoa(server_addr->sin_addr),
    //        inet_ntoa(client_addr->sin_addr));
    printf("Accepted connection!\n");

    rx_size = 0;
    counter = 0;
    first_time = 0;
    last_time = 0;
    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {

        be_tcp();

        // Check for errors
        if ((ne_err = tle_evq_get(str_hdl.ereq, (const void**)data, 1)) > 0 && ((uint64_t)data[0]) == 1) {
            printf("Connection error\n");
            tle_tcp_stream_close(client_stream);
            return;
        }

        // Receive
        nb_rx = tle_tcp_stream_recv(client_stream, (struct rte_mbuf**)&rx_buf, MAX_PKT_BURST);
        for (uint16_t i = 0; i < nb_rx; i++) {

            // printf("Received mbuf from pool %s nb %u and pkt_len %u\n", rx_buf[i]->pool->name,
            //        rx_buf[i]->nb_segs, rx_buf[i]->pkt_len);
            
            rx_size += rx_buf[i]->pkt_len;
            // We might receive mbufs belonging to different packets?
            if (rx_size >= params->payload_size) {
                rx_size -= params->payload_size;
                if (counter == 0) {
                    first_time = get_clock_realtime_ns();
                }
                counter++;
            }
            rte_pktmbuf_free(rx_buf[i]);
        }

    }
    last_time = get_clock_realtime_ns();

    // Close the stream
    ret = tle_tcp_stream_close(client_stream);
    if (ret != 0) {
        printf("Close: %s\n", strerror(ret));
    }

    ret = tle_tcp_stream_close(str_hdl.stream);
    if (ret != 0) {
        printf("Close: %s\n", strerror(ret));
    }

    be_tcp();

    /* Compute results */
    uint64_t elapsed_time_ns = last_time - first_time;
    double   mbps =
        ((counter * params->payload_size * 8) * ((double)1e3)) / ((double)elapsed_time_ns);
    double throughput = ((counter) * ((double)1e3)) / ((double)elapsed_time_ns);

    /* Print results */
    // fprintf(stdout,
    //         "[ TEST RESULT ]                 \n"
    //         "Received messages:   %lu        \n"
    //         "Elapsed time:        %.3f ms    \n"
    //         "Measured throughput: %.3f Mmsg/s\n"
    //         "Measured banwdidth:  %.3f Mbps  \n\n",
    //         counter, (double)elapsed_time_ns / ((double)1e6), throughput, mbps);
    fprintf(stdout, "%lu,%u,%.3f,%.3f,%.3f\n", counter, params->payload_size,
            (double)elapsed_time_ns / ((double)1e6), throughput, mbps);
}

//--------------------------------------------------------------------------------------------------
// ping
void do_ping(struct rte_mempool *mempool, struct tldk_stream_handle str_hdl, test_config_t *params) {
    char                *msg     = MSG;
    uint64_t             counter = 0;
    struct test_data    *data;
    uint64_t             send_time, response_time, latency;
    uint8_t              pong_received;
    int                  ret;

    /* 1. Connect the stream to the destination */
    struct sockaddr_in dst_addr;
    dst_addr.sin_family        = AF_INET;
    dst_addr.sin_port          = rte_cpu_to_be_16(INSANE_PORT);
    dst_addr.sin_addr.s_addr   = rte_cpu_to_be_32(IP_DST);

    ret = tle_tcp_stream_connect(str_hdl.stream, (struct sockaddr*)&dst_addr); // async!
    if (ret < 0) {
        printf("Error connecting TCP stream: (%d): %s\n", ret, strerror(ret));
        return;
    }

    /* 2. Wait for the connection to be established */
    // NOTE: We check the TX Queue as it will report the completions of our TX requests!
    uint32_t ne_tx, ne_err, np_tx;
    char     *evdata[MAX_PKT_BURST];
    do {
        be_tcp();
        ne_tx  = tle_evq_get(str_hdl.txeq, (const void**)evdata, MAX_PKT_BURST);
        ne_err = tle_evq_get(str_hdl.ereq, (const void**)evdata, MAX_PKT_BURST);
    } while (!ne_tx && !ne_err);

    if (ne_err > 0) {
        printf("Impossible to connect to the server\n");
        return;
    }

    fprintf(stderr, "\nClient connected!\n");
    sleep(1);

    struct rte_mbuf *tx_mbuf, *rx_mbuf;
    uint32_t nb_rx;
    uint16_t payload_offset = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
                                           sizeof(struct rte_tcp_hdr) + 20; // 20 bytes of options

    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {

        if (params->sleep_time) {
            sleep(params->sleep_time);
        }

        send_time = get_clock_realtime_ns();

        // Allocate a single mbuf
        tx_mbuf = rte_pktmbuf_alloc(mempool);

        // First set the mbuf len (or the adjust won't work)
        tx_mbuf->pkt_len = tx_mbuf->data_len = payload_offset + params->payload_size;

        // Fill the payload
        data          = ( struct test_data *)rte_pktmbuf_adj(tx_mbuf, payload_offset);
        data->tx_time = send_time;
        data->cnt     = counter++;
        rte_strscpy((char*)(data + 1), msg, strlen(msg));

        /* Send the packet(s) to the TLDK stack */
        np_tx = tle_tcp_stream_send(str_hdl.stream, &tx_mbuf, 1);
        if (np_tx != 1) {
            printf("Error sending packet(s): %s\n", strerror(np_tx));
            return;
        }
        be_tcp();

        pong_received = 0;
        while (!pong_received) {
            be_tcp();
            
            // Receive 1, but 8 is the minimum burst size to ensure compatibility
            nb_rx = tle_tcp_stream_recv(str_hdl.stream, &rx_mbuf, 1);

            if (nb_rx > 0) {
                response_time = get_clock_realtime_ns();
                latency       = response_time - send_time;
                pong_received = 1;

                fprintf(stdout, "%.3f\n", (float)latency / 1000.0F);
                rte_pktmbuf_free(rx_mbuf);
            }
        } 
    }

    ret = tle_tcp_stream_close(str_hdl.stream);
    if (ret != 0) {
        printf("Close: %s\n", strerror(ret));
    }
}

//--------------------------------------------------------------------------------------------------
// pong
void do_pong(struct rte_mempool *mempool, struct tldk_stream_handle str_hdl, test_config_t *params) {
    int                   ret;
    uint32_t              nb_rx, nb_req, nb_syn, nb_err, ne_err;
    uint32_t              np_tx;
    uint64_t              counter;
    struct tle_tcp_stream_cfg prm[MAX_PKT_BURST];
    struct tle_stream        *client_streams[MAX_PKT_BURST];
    char                     *data[MAX_PKT_BURST];
    struct rte_mbuf          *rx_buf;

    (void)(mempool);

    // Open the TCP connection as a server
    ret = tle_tcp_stream_listen(str_hdl.stream);
    if (ret != 0) {
        printf("Listen: %s\n", strerror(ret));
        return;
    }
    printf("TCP server waiting for connections\n");

    /* look for syn events */
    do {
        be_tcp();
        nb_syn = tle_evq_get(str_hdl.rxeq, (const void**)data, MAX_PKT_BURST);
        nb_err = tle_evq_get(str_hdl.ereq, (const void**)data, MAX_PKT_BURST);
    } while (!nb_syn && !nb_err);

    if (nb_err > 0) {
        printf("Error while waiting for incoming connections\n");
        return;
    }

    // Accept an incoming connection
    nb_req = tle_tcp_stream_accept(str_hdl.stream, client_streams, MAX_PKT_BURST);
    if (nb_req == 0) {
        printf("Accept: no client found\n");
        return;
    }    

    /* For each accepted connection, we must set the proper config */
    // Here I assume I only accept 1 connection
    struct tle_stream         *client_stream = client_streams[0];
    struct tle_tcp_stream_cfg *cfg           = &prm[0];
    // Allocate and activate the events from the same queue. "1" refers to the client stream and
    // is used to differentiate the event from syn connections
    cfg->err_ev  = tle_event_alloc(str_hdl.ereq, (void *)1);
    cfg->recv_ev = tle_event_alloc(str_hdl.rxeq, (void *)1);
    cfg->send_ev = tle_event_alloc(str_hdl.txeq, (void *)1);
    tle_event_active(cfg->send_ev, TLE_SEV_DOWN);
    tle_event_active(cfg->recv_ev, TLE_SEV_DOWN);
    tle_event_active(cfg->err_ev, TLE_SEV_DOWN);

    // Update the stream with the new configuration
    uint32_t res = tle_tcp_stream_update_cfg(client_streams, prm, nb_req);
    if (res != nb_req) {
        printf("Error updating the stream cfg\n");
        exit(1);
    }

    // TODO: It looks like this feature is not well implemented...
    // struct tle_tcp_stream_addr addr;
    // tle_tcp_stream_get_addr(stream, &addr);
    // struct sockaddr_in *client_addr = (struct sockaddr_in *)&addr.local;
    // struct sockaddr_in *server_addr = (struct sockaddr_in *)&addr.remote;
    // printf("Accepted connection from %s to %s\n", inet_ntoa(server_addr->sin_addr),
    //        inet_ntoa(client_addr->sin_addr));
    printf("Accepted connection!\n");

    counter = 0;
    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {
        
        // Check for errors
        if ((ne_err = tle_evq_get(str_hdl.ereq, (const void**)data, 1)) > 0 && ((uint64_t)data[0]) == 1) {
            printf("Connection error\n");
            tle_tcp_stream_close(client_stream);
            return;
        }

        // Receive
        be_tcp();
        nb_rx = tle_tcp_stream_recv(client_stream, &rx_buf, 1);

        if(nb_rx > 0) {              
            // Send it back
            np_tx = tle_tcp_stream_send(client_stream, &rx_buf, 1);
            if (np_tx != 1) {
                printf("Error sending packet(s): %s\n", rte_strerror(rte_errno));
                return;
            }
            counter++;
            be_tcp();
        }
    }

    // Close the stream
    ret = tle_tcp_stream_close(client_stream);
    if (ret != 0) {
        printf("Close: %s\n", strerror(ret));
    }

    ret = tle_tcp_stream_close(str_hdl.stream);
    if (ret != 0) {
        printf("Close: %s\n", strerror(ret));
    }

    be_tcp();
}

//--------------------------------------------------------------------------------------------------
int parse_arguments(int argc, char *argv[], test_config_t *config) {
    /* Argument number */
    if (argc < 2) {
        fprintf(stderr, "! Invalid number of arguments\n"
                        "! You must specify at least the running MODE\n");
        return -1;
    }
    /* Default values */
    config->role         = role_sink;
    config->payload_size = strlen(MSG) + 1;
    config->sleep_time   = 0;
    config->max_msg      = 0;
    config->burst_size   = 8;
    config->port_id      = 0;
    config->queue_id     = 0;

    /* Test role (mandatory argument) */
    if (!strcmp(argv[1], "sink")) {
        config->role = role_sink;
    } else if (!strcmp(argv[1], "source")) {
        config->role = role_source;
    } else if (!strcmp(argv[1], "ping")) {
        config->role = role_ping;
    } else if (!strcmp(argv[1], "pong")) {
        config->role = role_pong;
    } else if (!strncmp(argv[1], "-h", 2) || !strncmp(argv[1], "--help", 6)) {
        return -1; // Success, but termination required
    } else {
        fprintf(stderr, "Unrecognized argument: %s\n", argv[1]);
        return -1;
    }

    /* Parse the optional arguments */
    for (int i = 2; i < argc; ++i) {
        // Helper
        if (!strncmp(argv[i], "-h", 2) || !strncmp(argv[i], "--help", 6)) {
            return -1; // Success, but termination required
        }
        // Message payload size
        if (!strncmp(argv[i], "-s", 2) || !strncmp(argv[i], "--size", 6)) {
            char *ptr;
            ENSURE_ONE_MORE_ARGUMENT(argc, argv, i, "--size")
            config->payload_size = strtol(argv[++i], &ptr, 10);
            if (*ptr != '\0') {
                fprintf(stderr, "! Invalid value for --size option: %s\n", argv[i]);
                return -1;
            }
            if (config->payload_size <= MIN_PAYLOAD_SIZE || config->payload_size > MAX_PAYLOAD_SIZE)
            {
                fprintf(stderr, "! Invalid value for --size option: %s\n", argv[i]);
                return -1;
            }
            continue;
        }
        // Max number of messages
        if (!strncmp(argv[i], "-n", 2) || !strncmp(argv[i], "--num-msg", 9)) {
            char *ptr;
            ENSURE_ONE_MORE_ARGUMENT(argc, argv, i, "--num-msg")
            config->max_msg = strtol(argv[++i], &ptr, 10);
            if (*ptr != '\0') {
                fprintf(stderr, "! Invalid value for --num-msg option: %s\n", argv[i]);
                return -1;
            }
            continue;
        }
        // Burst size
        if (!strncmp(argv[i], "-b", 2) || !strncmp(argv[i], "--burst-size", 12)) {
            char *ptr;
            ENSURE_ONE_MORE_ARGUMENT(argc, argv, i, "--burst-size")
            config->burst_size = strtoul(argv[++i], &ptr, 10);
            if (*ptr != '\0') {
                fprintf(stderr, "! Invalid value for --burst-size option: %s\n", argv[i]);
                return -1;
            }
            if (config->burst_size > MAX_PKT_BURST) {
                fprintf(stderr, "! burst_size too high: %s max is %d\n", argv[i], MAX_PKT_BURST);
                return -1;
            }
            continue;
        }
        // Sleep time
        if (!strncmp(argv[i], "-r", 2) || !strncmp(argv[i], "--sleep-time", 12)) {
            char *ptr;
            ENSURE_ONE_MORE_ARGUMENT(argc, argv, i, "--sleep-time")
            config->sleep_time = strtol(argv[++i], &ptr, 10);
            if (*ptr != '\0') {
                fprintf(stderr, "! Invalid value for sleep-time option: %s\n", argv[i]);
                return -1;
            }
            continue;
        }
    }

    // Print out the configuration
    printf("Running with the following arguments:   \n"
           "\tRole............. : %s                \n"
           "\tPayload size..... : %d                \n"
           "\tMax messages..... : %lu               \n"
           "\tSleep time....... : %ld               \n\n",
           role_strings[config->role], config->payload_size, config->max_msg, config->sleep_time);

    return 0;
}

//--------------------------------------------------------------------------------------------------
static inline int port_init(struct rte_mempool *mempool, uint16_t mtu, test_config_t *params) {
    int valid_port = rte_eth_dev_is_valid_port(params->port_id);
    if (!valid_port)
        return -1;

    struct rte_eth_dev_info dev_info;
    int                     retval = rte_eth_dev_info_get(params->port_id, &dev_info);
    if (retval != 0) {
        fprintf(stderr, "[error] cannot get device (port %u) info: %s\n", params->port_id, strerror(-retval));
        return retval;
    }

    // Derive the actual MTU we can use based on device capabilities and user request
    uint16_t actual_mtu = RTE_MIN(mtu, dev_info.max_mtu);

    // Configure the device
    uint16_t port_id = params->port_id;
    struct rte_eth_conf port_conf;
    memset(&port_conf, 0, sizeof(port_conf));
    port_conf.rxmode.mtu = actual_mtu;
    port_conf.rxmode.offloads |= (RTE_ETH_RX_OFFLOAD_CHECKSUM | RTE_ETH_RX_OFFLOAD_SCATTER);
    port_conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;
    port_conf.txmode.offloads |= (RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_MULTI_SEGS);
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
    const uint16_t rx_rings = 1, tx_rings = 1;
    retval = rte_eth_dev_configure(port_id, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    // Set the MTU explicitly
    retval = rte_eth_dev_set_mtu(port_id, actual_mtu);
    if (retval != 0) {
        printf("Error setting up the MTU (%d)\n", retval);
        return retval;
    }

    uint16_t nb_rxd = 1024;
    uint16_t nb_txd = 1024;
    retval          = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    int socket_id = rte_eth_dev_socket_id(port_id);

    for (uint16_t q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port_id, q, nb_rxd, socket_id, NULL, mempool);
        if (retval != 0)
            return retval;
    }

    struct rte_eth_txconf txconf = dev_info.default_txconf;
    txconf.offloads              = port_conf.txmode.offloads;
    for (uint16_t q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port_id, q, nb_txd, socket_id, &txconf);
        if (retval != 0)
            return retval;
    }

    retval = rte_eth_dev_start(port_id);
    if (retval != 0) {
        return retval;
    }

    retval = rte_eth_promiscuous_enable(port_id);
    if (retval != 0)
        return retval;

    return 0;
}

//--------------------------------------------------------------------------------------------------
// MAIN
int main(int argc, char *argv[]) {
    signal(SIGINT, handle);
    printf("Welcome to the test of the raw TCP DPDK performance\n");

    /* Initialize DPDK */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "error with EAL initialization\n");
    }
    printf("Eal Init OK\n");

    /* Check test arguments */
    argc -= ret;
    test_config_t params;
    if (parse_arguments(argc, &argv[ret], &params) < 0) {
        usage(argc, argv);
        return -1;
    }

    /* Create mempool for all TX and RX data */
    uint16_t socket_id = rte_eth_dev_socket_id(params.port_id);
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create(
        "mbuf_pool", 10240, 64, 0, RTE_MBUF_DEFAULT_DATAROOM, socket_id);
    if (mbuf_pool == NULL) {
        printf("RTE_ERROR: %s\n", rte_strerror(rte_errno));
        rte_exit(EXIT_FAILURE, "cannot create the mbuf pool\n");
    }

    /* Port init */
    ret = port_init(mbuf_pool, MTU, &params);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "error with port initialization\n");
    }
    printf("Port creation OK\n");

    /* TLDK */
    // 1. Init context with local endpoint info
    init_tldk_ctx(&params);
   
    // 2. Create a TLDK stream in that context. TLDK stream == State for one TCP Connection
    struct tldk_stream_handle stream = create_tldk_stream(socket_id);

    // 3. Create the TLDK background thread, which handles the raw data packets
    // uint32_t lcore_id = 1;
    // if (rte_eal_remote_launch(backend_thread, NULL, lcore_id) != 0) {
    //     printf("Error creating thread\n");
    //     rte_exit(EXIT_FAILURE, "Error creating thread\n");
    // }    

    /*************************************************************************/

    /* Do test */
    if (params.role == role_sink) {
        do_sink(mbuf_pool, stream, &params);
    } else if (params.role == role_source) {
        do_source(mbuf_pool, stream, &params);
    } else if (params.role == role_ping) {
        do_ping(mbuf_pool, stream, &params);
    } else if (params.role == role_pong) {
        do_pong(mbuf_pool, stream, &params);
    } else {
        fprintf(stderr, "Test not supported\n");
        return -1;
    }

    /* Terminate */
    g_running = false;

    be_tcp();
    rte_eth_dev_stop(params.port_id);
    rte_eal_cleanup();
    return 0;
}