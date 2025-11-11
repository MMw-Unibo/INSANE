#define _GNU_SOURCE

#include "dpdk_common.h"
#include "protocols.h"

#include "../src/base/nsn_os_linux.c"

#include <tle_ctx.h>
#include <tle_event.h>
#include <tle_tcp.h>

// This DPDK plugin assumes we are working with NICs that use the mlx5 or i40e drivers.
// We need RSS filtering to enable the zero-copy receive, because we can associate
// different mempools with different queues, i.e., different applications. 
// However, the mlx5/i40e drivers do not allow us to have just some queues active when
// the device is started (as DPDK would allow with rx_deferred start). So we need to 
// configure and start a number of queues (MAX_DEVICE_QUEUES) which will be active
// immediately, then we stop them until it is necessary (i.e., we have an EP for them).
// If supported, we set the rte_isolate_flow() o ensure that a queue only receives packets
// matching its RSS flow rule. This has some implications:
// - we need to create a rule to receive ARP packets on queue 0 (control queue)
// - isolate() works only for bifurcated drivers: other drivers will need code to 
//     ensure that all traffic not matching the RSS ruls of other queues is received
//     on queue 0 (or dropped)

// Peer descriptor - augmented
struct tcpdpdk_peer {
    char* ip_str; // IP in string form
    u32   ip_net; // IP in network byte order
    bool  mac_set; // MAC address set or not (for ARP)
    struct rte_ether_addr mac_addr; // MAC address
};

//--------------------------------------------------------------------------------------------------
// TLDK definitions
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

//--------------------------------------------------------------------------------------------------
// Per-endpoint state
struct tcpdpdk_ep {
    u16 rx_queue_id;
    struct rte_mempool *hdr_pool; // Pool for headers, and RX payloads if zc_rx is false
    struct rte_mempool *zc_pool;  // Pool for zero-copy TX and RX
    struct rte_flow *app_flow;
    nsn_buf_t pending_rx_buf; // For non zero-copy receive
    atu32 connected_peers;
    struct tldk_stream_handle  s_svc_sockfd; // Server stream
    struct tldk_stream_handle *s_sockfd;     // Array of open streams
};

// Plugin state
static struct arp_peer* peers; // Works as ARP cache
static struct tldk_ep tldk_ctx;
static u16 n_peers;
static char* local_ip;
static uint32_t local_ip_net;
static struct rte_ether_addr local_mac_addr;
static char* dev_name;
static u16 port_id;
static u16 tx_queue_id;
static u16 mtu;
static int socket_id;
static u16 nb_rxd;
static u16 nb_txd;
static struct rte_eth_dev_info devinfo;
static nsn_ringbuf_t *free_queue_ids;
struct rte_mempool *ctrl_pool;
static temp_mem_arena_t scratch;
static struct rte_flow *rx_arp_flow;
static bool dev_stopped = true;

// Zero-copy RX switch
static bool zc_rx = false; 

// Mutex on the TLDK backend operations
static nsn_mutex_t be_lock;

//--------------------------------------------------------------------------------------------------
// Helper functions

// Callback necessary for the TLDK context.
// This function returns the tle_dest info associated with the input address
// In their example, they use a routing table for that. We do not need this, as
// we plan to use this at end hosts, but we still need to provide the tle_dest info
//
// "addr" is the destination address of the packet, IN NETWORK BYTE ORDER, set by the caller (TLDK)
static int prepare_dst_headers(void *data, const struct in_addr *addr, struct tle_dest *res) {
    (void)data;
    int i;
    struct tldk_ep *ctx = &tldk_ctx;

    // This is the device that will be used to send out the packet
    // It must be set, or it will cause the caller to fail
    res->dev = ctx->dev;

    // These are necessary for header manipulations
    res->mtu    = mtu;
    res->l2_len = RTE_ETHER_HDR_LEN;
    res->l3_len = sizeof(struct rte_ipv4_hdr);
    
    /* Ethernet header */
    struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)res->hdr;
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    rte_ether_addr_copy(&local_mac_addr, &eth_hdr->src_addr);
    for(i = 0; i < n_peers; i++) {
        if (addr->s_addr == peers[i].ip_net) {
            if(!peers[i].mac_set) {
                // TODO: should we use ARP here?
                fprintf(stderr, "[tcpdpdk] destination MAC not found for addr %s\n", peers[i].ip_str);
                return -1;
            }
            rte_ether_addr_copy(&peers[i].mac_addr, &eth_hdr->dst_addr);
        }
    }

    /* IP header */
    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    ip_hdr->version_ihl         = RTE_IPV4_VHL_DEF;
    ip_hdr->type_of_service     = 0;
    ip_hdr->fragment_offset     = 0;
    ip_hdr->time_to_live        = 64;
    ip_hdr->next_proto_id       = IPPROTO_TCP;
    ip_hdr->packet_id           = 0;
    // ip_hdr->total_length     = rte_cpu_to_be_16(pkt_len);
    // ip_hdr->src_addr         = local_ip_net;
    // ip_hdr->dst_addr         = addr->s_addr;

    // This is the mempool that will be used for fragmentation and acks
    res->head_mp = ctx->head_mp;

    // OL flags for individual mbufs
    // res->ol_flags = RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4;

    return 0;
}

// Init a TLDK context
static int init_tldk_ctx() {
    /***** TLDK: Initialize the TLDK context, then open a stream. 
     * The context consists of 4 elements:
     *  1. rte_mempool  - Header pool for fragment headers and control packets
     *  2. tle_ctx      - Context of a TLK enpoint (one per thread)!
     *  3. netbe_port   - Device port info 
     *  4. tle_dev      - Device to send packets through
     */

    /* 1. TLDK header pool will use the ctrl_pool */
    tldk_ctx.head_mp = ctrl_pool;

    /* 2. Create the TCP context */
    int32_t socket_id = rte_eth_dev_socket_id(port_id);
    if (socket_id < 0) {
        if (rte_errno == EINVAL) {
            fprintf(stderr, "[error] cannot get socket ID for port %u: %s.\n", port_id, strerror(-socket_id));
            return -EINVAL;
        } else {
            socket_id = 0; // Default to socket 0 if socket could not be determined (e.g., in VMs)
        }
    }

    struct tle_ctx_param ctx_params = {
        .socket_id         = socket_id,
        .proto             = TLE_PROTO_TCP,
        .max_streams       = MAX_STREAMS,
        .free_streams      = {.max = 0, .min = 0},
        .max_stream_rbufs  = 1024,
        .max_stream_sbufs  = 1024,
        .send_bulk_size    = 32,
        .flags             = 0,
        .hash_alg          = TLE_JHASH,
        .secret_key.u64[0] = rte_rand(),
        .secret_key.u64[1] = rte_rand(),
        .lookup4           = prepare_dst_headers, // will be called by send() to get DST info
        .lookup4_data      = NULL, // opaque data for lookup4()
    };
    tldk_ctx.ctx = tle_ctx_create(&ctx_params);
    if(tldk_ctx.ctx == NULL) {
        fprintf(stderr, "[tcpdpdk] tle_ctx_create() failed\n");
        return -1;
    }

    /* 3. Prepare the local TCP port */
    struct sockaddr_in local_ip;
    local_ip.sin_addr.s_addr = local_ip_net;
    struct netbe_port netbe_port = {
        .id         = port_id,
        .nb_lcore   = 1,    // The lcore_id will be set later in the backend thread
        .mtu        = mtu,
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
        fprintf(stderr, "[tcpdpk] tle_add_dev() failed\n");
        return -1;
    }

    return 0;
}

// Create a TLDK stream
static struct tldk_stream_handle create_tldk_stream(uint16_t socket_id, uint16_t tcp_port, struct arp_peer* peer) {

    struct tle_evq_param eprm = {
        .max_events = 1024,
        .socket_id  = socket_id,
    };

    struct tle_evq *ereq = tle_evq_create(&eprm); // ER queue
    struct tle_evq *rxeq = tle_evq_create(&eprm); // RX queue
    struct tle_evq *txeq = tle_evq_create(&eprm); // TX queue
    if (ereq == NULL || rxeq == NULL || txeq == NULL) {
        fprintf(stderr, "[tcpdpdk] error creating event queues\n");
        rte_exit(EXIT_FAILURE, "Error creating event queues\n");
    }
    
    // Allocate and initialize one event per TX, RX, ER queues.
    struct tle_event *rxev = tle_event_alloc(rxeq, NULL);
    struct tle_event *txev = tle_event_alloc(txeq, NULL);
    struct tle_event *erev = tle_event_alloc(ereq, NULL);
    tle_event_active(txev, TLE_SEV_DOWN);
    tle_event_active(rxev, TLE_SEV_DOWN);
    tle_event_active(erev, TLE_SEV_DOWN);

    // Prepare SRC and DST address for the stream
    struct sockaddr_storage src_addr_tldk, dst_addr_tldk;

    struct sockaddr_in src_addr;
    src_addr.sin_family      = AF_INET;
    src_addr.sin_port        = rte_cpu_to_be_16(tcp_port);
    src_addr.sin_addr.s_addr = local_ip_net;
    memcpy(&src_addr_tldk, &src_addr, sizeof(src_addr));

    struct sockaddr_in dst_addr;
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    if(peer) {
        dst_addr.sin_port        = rte_cpu_to_be_16(tcp_port);
        dst_addr.sin_addr.s_addr = peer->ip_net;
    }
    memcpy(&dst_addr_tldk, &dst_addr, sizeof(dst_addr));

    struct tle_tcp_stream_param stream_params = {
        .addr =
            {
                .local  = src_addr_tldk,
                .remote = dst_addr_tldk,
            },
        .cfg = // This associates the events queues to the stream
        {
            .nb_retries = 1,
            .err_ev     = erev,
            .recv_ev    = rxev,
            .send_ev    = txev,
        },

    };

    // Finally, open the stream
    struct tle_stream *stream = tle_tcp_stream_open(tldk_ctx.ctx, &stream_params);
    if (stream == NULL) {
        fprintf(stderr, "[tcpdpdk] error opening TCP stream to %s: (%d): %s\n", peer->ip_str, rte_errno, rte_strerror(rte_errno));
        return (struct tldk_stream_handle){NULL, NULL, NULL, NULL};
    }

    return (struct tldk_stream_handle){stream, ereq, rxeq, txeq};
}

// -------------------------------------------------------------------------------------------------
// TLDK backend logic
static int be_tcp(uint16_t rx_queue_id) {
    uint16_t         nb_rx, nb_valid, nb_tx, nb_arp, nb_tx_tcp, nb_tx_actual;
    struct rte_mbuf *rx_pkt[MAX_PKT_BURST];
    struct rte_mbuf *rp[MAX_PKT_BURST];
    int32_t          rc[MAX_PKT_BURST];
    struct rte_mbuf *tx_pkt[MAX_PKT_BURST];
    int              ret;

    tldk_ctx.port.lcore_id = rte_lcore_id();
    struct tle_dev *dev     = tldk_ctx.dev;

    // 1. TODO: Receive on all the active queues!
    nb_arp = 0;
    nb_rx  = rte_eth_rx_burst(tldk_ctx.port.id, rx_queue_id, rx_pkt, MAX_PKT_BURST);
    if (nb_rx) {
        // If they are TCP packets, set the l2, l3, l4 len accordingly and meet the
        // pre-conditions of tle_tcp_rx_bulk. Otherwise, drop the packet; if ARP, 
        // handle the request before discarding the packet.
        for (int i = 0; i < nb_rx; i++) {
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(rx_pkt[i], struct rte_ether_hdr *);
            // Check ethernet type
            if (rte_be_to_cpu_16(eth_hdr->ether_type) != RTE_ETHER_TYPE_IPV4) {
                if (rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_ARP) {
                    arp_hdr_t *ahdr = rte_pktmbuf_mtod_offset(rx_pkt[i], arp_hdr_t *, RTE_ETHER_HDR_LEN);
                    // Update the cache
                    arp_update_cache(ahdr, peers, n_peers);
                    // If necessary, prepare ARP reply
                    if(rte_be_to_cpu_16(ahdr->arp_opcode) == ARP_REQUEST) {
                        arp_reply_prepare(rx_pkt[i], local_ip_net, &local_mac_addr);
                        // Append the mbuf to the TX queue
                        tx_pkt[nb_arp] = rx_pkt[i];
                        nb_arp++;
                    }
                }
                continue;
            }
            // Check IP protocol
            struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
            if (ip_hdr->next_proto_id != IPPROTO_TCP) {
                fprintf(stderr, "[tcpdpdk] IP Packet type not TCP: %d\n", ip_hdr->next_proto_id);
                continue;
            }

            // Check TCP flags (prereq of tle_tcp_rx_bulk)
            if ((rx_pkt[i]->packet_type & (RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L3_IPV6)) == 0) {
                fprintf(stderr, "[tcpdpdk] packet type L3: %d (must be != 0)\n",
                       rx_pkt[i]->packet_type & (RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L3_IPV6));
                continue;
            }
            if ((rx_pkt[i]->packet_type & (RTE_PTYPE_L4_TCP)) == 0) {
                fprintf(stderr, "[tcpdpdk] packet type L4: %d (must be != 0)\n",
                       rx_pkt[i]->packet_type & (RTE_PTYPE_L4_TCP));
                continue;
            }

            //fprintf(stderr, "[tcpdpdk] received TCP packet on queue %u, nb_segs=%u, pkt_len=%u, data_len=%u\n", rx_queue_id, rx_pkt[i]->nb_segs, rx_pkt[i]->pkt_len, rx_pkt[i]->data_len);
            
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
        nsn_os_mutex_lock(&be_lock);
        nb_valid = tle_tcp_rx_bulk(dev, rx_pkt, rp, rc, nb_rx);

        // Drop packets that are not valid or not to be delivered
        for (int j = 0; j < (nb_rx - nb_valid); j++) {
            rte_pktmbuf_free(rp[j]);
        }
    } else {
        nsn_os_mutex_lock(&be_lock);
    }
    
    // 2. Progress the TCP state machine
    if (tle_tcp_process(tldk_ctx.ctx, MAX_STREAMS) < 0) {
        fprintf(stderr, "[tcpdpdk] Error processing TCP state machine\n");
    }
    
    // 3. Transmit
    nb_tx_tcp = tle_tcp_tx_bulk(dev, tx_pkt + nb_arp, MAX_PKT_BURST - nb_arp);
    nsn_os_mutex_unlock(&be_lock);

    nb_tx = nb_arp + nb_tx_tcp;
    nb_tx_actual = 0;
    while (nb_tx_actual < nb_tx) {
        nb_tx_actual += rte_eth_tx_burst(tldk_ctx.port.id, tx_queue_id, tx_pkt + nb_tx_actual, nb_tx - nb_tx_actual);
    }
    
    return 0;
}

// -------------------------------------------------------------------------------------------------
// Connection helper
static struct tldk_stream_handle try_connect_peer(struct arp_peer* peer, u16 port, u16 rx_queue_id) { 
        
    // Prepare the destination address
    struct sockaddr_in dst_addr;
    dst_addr.sin_family      = AF_INET;
    dst_addr.sin_port        = rte_cpu_to_be_16(port);
    dst_addr.sin_addr.s_addr = peer->ip_net;

    /* 1. Create the client stream ("open") */
    struct tldk_stream_handle res_str = create_tldk_stream(socket_id, port, peer);
    if(res_str.stream == NULL) {
        return res_str;
    }

    /* 2. Connect the stream to the destination */
    int ret = tle_tcp_stream_connect(res_str.stream, (struct sockaddr*)&dst_addr);
    if (ret < 0) {
        fprintf(stderr, "[tcpdpdk] connect() failed: %s (%d)\n", strerror(ret), ret);
        tle_tcp_stream_close(res_str.stream);
        be_tcp(rx_queue_id);
        res_str.stream = NULL;
        return res_str;
    }

    /* 3. Wait for the connection to be established */
    // NOTE: We check the TX Queue as it will report the completions of our TX requests!
    // int64_t timeout = 5000000; // 5ms connection timeout
    
    uint32_t  ne_tx, ne_err, np_tx;
    char     *evdata[32];
    // int64_t   start = nsn_os_get_time_ns();
    do {
        be_tcp(rx_queue_id);
        ne_tx  = tle_evq_get(res_str.txeq, (const void**)evdata, MAX_PKT_BURST);
        ne_err = tle_evq_get(res_str.ereq, (const void**)evdata, MAX_PKT_BURST);
    } while (!ne_tx && !ne_err /*&&  (nsn_os_get_time_ns() - start) < timeout*/);

    if (ne_err > 0 /*|| !ne_tx*/) {
        tle_tcp_stream_close(res_str.stream);
        be_tcp(rx_queue_id);
        res_str.stream = NULL;
        return res_str;
    }

    return res_str;
}


// -------------------------------------------------------------------------------------------------
// API functions
NSN_DATAPATH_UPDATE(tcpdpdk) {
    if (endpoint == NULL) {
        fprintf(stderr, "[tcpdpdk] invalid endpoint\n");
        return -1;
    }

    // Case 1. Delete endpoint data.
    if(endpoint->data) {
        struct tcpdpdk_ep *conn = (struct tcpdpdk_ep *)endpoint->data;

        if (!zc_rx) {
            // Return the pending buffer to the free slots
            nsn_ringbuf_enqueue_burst(endpoint->free_slots, &conn->pending_rx_buf, sizeof(conn->pending_rx_buf), 1, NULL);
        }
        
        // If the device is active, close the connection here and then just stop this queue, not the entire device.
        if(!dev_stopped) {
            int res;
            if(conn->s_svc_sockfd.stream) {
                res = tle_tcp_stream_close(conn->s_svc_sockfd.stream);
                be_tcp(conn->rx_queue_id);
                conn->s_svc_sockfd.stream = NULL;
            }
            for(u16 i = 0; i < n_peers; i++) {
                if(conn->s_sockfd[i].stream) {
                    // Flush pending data
                    while(tle_tcp_stream_tx_pending(conn->s_sockfd[i].stream)) {
                        be_tcp(conn->rx_queue_id);
                    }
                    res = tle_tcp_stream_close(conn->s_sockfd[i].stream);
                    be_tcp(conn->rx_queue_id);
                    conn->s_sockfd[i].stream = NULL;
                    atomic_fetch_sub(&conn->connected_peers, 1);
                }
            }
           
            res = rte_eth_dev_rx_queue_stop(port_id, conn->rx_queue_id);
            if (res < 0) {
                fprintf(stderr, "[tcpdpdk] failed to stop the device queue: %s\n", rte_strerror(rte_errno));
            }
        }

        // Destroy the flow
        if (conn->app_flow) {
            rte_flow_destroy(port_id, conn->app_flow, NULL);
        }

        // Destroy the tx mempools
        rte_mempool_free(conn->zc_pool);

        // Un-register memory
        void *addr = (void*)((usize)endpoint->tx_zone & 0xFFFFFFFFFFF00000);
        usize len  = align_to((endpoint->tx_zone->total_size + (((void*)endpoint->tx_zone) - addr)),
                              endpoint->page_size);
        unregister_memory_area(addr, len, endpoint->page_size, port_id);

        // Enqueue the queue_id in the free queue_ids
        nsn_ringbuf_enqueue_burst(free_queue_ids, &conn->rx_queue_id, sizeof(void*), 1, NULL);

        // Free the ep data and clean the ep state
        free(endpoint->data);
        endpoint->data = NULL;
        endpoint->data_size = 0;
    } 
    // Case 2. Create endpoint data.
    else {  
        if (nsn_ringbuf_count(free_queue_ids) == 0) {
            fprintf(stderr, "[tcpdpdk] No free queues left for the application\n");
            return -1;
        }

        // create the state of the endpoint, which will hold connection data
        endpoint->data = malloc(sizeof(struct tcpdpdk_ep));
        if (endpoint->data == NULL) {
            fprintf(stderr, "[tcpdpdk] malloc() failed\n");
            return -1;
        }
        endpoint->data_size = sizeof(struct tcpdpdk_ep);

        // Initialize the state of the endpoint
        struct tcpdpdk_ep *conn = (struct tcpdpdk_ep*)endpoint->data;
        
        conn->s_sockfd = malloc(n_peers * sizeof(struct tldk_stream_handle));
        if (!conn->s_sockfd) {
            fprintf(stderr, "malloc() failed: %s\n", strerror(errno));
            free(endpoint->data);
            return -1;
        }
        memset(conn->s_sockfd, 0, n_peers * sizeof(struct tldk_stream_handle));

        // Assign a queue to this application
        u64 queue_id;
        nsn_ringbuf_dequeue_burst(free_queue_ids, &queue_id, sizeof(void*), 1, NULL);
        conn->rx_queue_id = queue_id;

        if (setup_memory_and_mempools(endpoint, conn->rx_queue_id, port_id, socket_id, &conn->hdr_pool, &conn->zc_pool) < 0) {
            goto error_1;
        }

        /* We have two separate paths, one to enable the zero-copy receive, one for the copy-on-receive */
        int ret;
        if(zc_rx) {
            /* Configure RX split: headers and payloads in their respective mempools */
            struct rte_eth_rxconf rx_conf = devinfo.default_rxconf;
            // Configure the BUFFER_SPLIT offload behavior for the selected RX queue.
            uint8_t rx_pkt_nb_segs = 2;
            struct rte_eth_rxseg_split *rx_seg;
            union rte_eth_rxseg rx_useg[2] = {};
            // Segment 0 (header)
            rx_seg         = &rx_useg[0].split;
            rx_seg->mp     = conn->hdr_pool;
            rx_seg->offset = 0;
            // See docs in rte_ethdev.h. Must be zero if length is used (and vice versa)
            rx_seg->proto_hdr = 0;
            // Max bytes to be placed in this segment. Must be zero if proto_hdr is used (and vice versa)
            rx_seg->length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_tcp_hdr);
            // Segment 1 (payload)
            rx_seg         = &rx_useg[1].split;
            rx_seg->offset = 0;
            rx_seg->mp     = conn->zc_pool;
            rx_seg->proto_hdr = 0;
            rx_seg->length = 2048;

            // Configure the number of segments and the segments themselves
            rx_conf.rx_nseg     = rx_pkt_nb_segs;
            rx_conf.rx_seg      = rx_useg;
            rx_conf.rx_mempools = NULL;
            rx_conf.rx_nmempool = 0;
            rx_conf.rx_deferred_start = 1;
            // Setup the RX queue using the selected configuration
            if ((ret = rte_eth_rx_queue_setup(port_id, conn->rx_queue_id, nb_rxd, socket_id, &rx_conf, NULL)) != 0) {
                fprintf(stderr, "[tcpdpdk] failed configuring rx queue %u: %s\n", conn->rx_queue_id, rte_strerror(rte_errno));
                goto error_2;
            }
        } else {
            // get a descriptor to receive
            u32 np = nsn_ringbuf_dequeue_burst(endpoint->free_slots, &conn->pending_rx_buf, sizeof(conn->pending_rx_buf), 1, NULL);
            if (np == 0) {
                fprintf(stderr, "[tcpdpdk] No free slots to receive from ring %p [%u]\n", endpoint->free_slots, nsn_ringbuf_count(endpoint->free_slots));
                goto error_2;
            }

            // // Setup the RX queue using the selected configuration
            // if ((ret = rte_eth_rx_queue_setup(port_id, conn->rx_queue_id, nb_rxd, socket_id, NULL, conn->rx_hdr_pool)) != 0) {
            //     fprintf(stderr, "[tcpdpdk] failed configuring rx queue %u: %s\n", conn->rx_queue_id, rte_strerror(rte_errno));
            //     goto error_4;
            // }
        }

        // Start the queue
        ret = rte_eth_dev_rx_queue_start(port_id, conn->rx_queue_id);
        if (ret < 0) {
            fprintf(stderr, "[tcpdpdk] failed to start queue %u: %s\n", conn->rx_queue_id, strerror(-ret));
            goto error_3;
        }

        // Now create the RSS filter on that queue for this endpoint's TCP port.
        // Do this immediately after the queue is started
        struct rte_flow_error flow_error;
        conn->app_flow = configure_tcp_rss_flow(port_id, conn->rx_queue_id, local_ip, endpoint->app_id, &flow_error);
        if (conn->app_flow == NULL) {
            fprintf(stderr, "[tcpdpdk] failed to create flow: %s\n", flow_error.message ? flow_error.message : "unkown");
            goto error_4;
        }

        // try to connect to peers. If we fail, just ignore the peer.
        at_store(&conn->connected_peers, 0, mo_rlx);
        for (int p = 0; p < n_peers; p++) {
            // Try to get the ARP replies; if no MAC, skip
            if (!be_tcp(0) && !peers[p].mac_set) {
                continue;
            }
            conn->s_sockfd[p] = try_connect_peer(&peers[p], endpoint->app_id, conn->rx_queue_id);
            if(conn->s_sockfd[p].stream) {
                fprintf(stderr, "[tcpdpdk] connected to %s\n", peers[p].ip_str);
                atomic_fetch_add(&conn->connected_peers, 1);
            } else {
                fprintf(stderr, "[tcpdpdk] failed to connect to %s\n", peers[p].ip_str);
            }
        }

        // Now create the server connection (i.e., the server "socket")
        conn->s_svc_sockfd = create_tldk_stream(socket_id, endpoint->app_id, NULL);
        if(conn->s_svc_sockfd.stream == NULL) {
            goto error_5;
        }
        fprintf(stderr, "[tcpdpdk] created server socket\n");
        
        // Listen
        ret = tle_tcp_stream_listen(conn->s_svc_sockfd.stream);
        if (ret != 0) {
            fprintf(stderr, "[tcpdpdk] listen: %s\n", strerror(ret));
            goto error_6;
        }
                
        return 0;
error_6:
        tle_tcp_stream_close(conn->s_svc_sockfd.stream);
error_5:
        rte_flow_destroy(port_id, conn->app_flow, NULL);
error_4:
        rte_eth_dev_rx_queue_stop(port_id, conn->rx_queue_id);
error_3:
        if (!zc_rx) {
            nsn_ringbuf_enqueue_burst(endpoint->free_slots, &conn->pending_rx_buf, sizeof(conn->pending_rx_buf), 1, NULL); 
        }
error_2:
    if(conn->zc_pool) {
        rte_mempool_free(conn->zc_pool);
    }
error_1:
        nsn_ringbuf_enqueue_burst(free_queue_ids, &conn->rx_queue_id, sizeof(void*), 1, NULL);
        free(conn);
        return -1;
    }
    return 0;
}

NSN_DATAPATH_CONN_MANAGER(tcpdpdk) {   
    // Call the backend thread on the ARP port - protected by a lock internally;
    // This has to be done anyway
    be_tcp(0);

    if (endpoint_list == NULL) {
        fprintf(stderr, "[tcpdpdk] connection manager: invalid endpoint_list\n");
        return -1;
    }
    if (list_empty(endpoint_list)) {
        return 0;
    }
   
    u32 nb_syn, nb_err, nb_req;
    char *data[32];
    ep_initializer_t *ep_in;
    list_for_each_entry(ep_in, endpoint_list, node) {    
        nsn_endpoint_t *ep = ep_in->ep;
        struct tcpdpdk_ep *conn = (struct tcpdpdk_ep *)ep->data;

        // already connected to all peers - skip
        u32 conn_peers = at_load(&conn->connected_peers, mo_rlx);
        if (conn_peers == n_peers) {
            continue;
        }

        // Call the backend thread on this EP's port - protected by a lock internally;
        be_tcp(conn->rx_queue_id);

        // Detect incoming connections, if any
        nb_syn = tle_evq_get(conn->s_svc_sockfd.rxeq, (const void**)data, MAX_PKT_BURST);
        nb_err = tle_evq_get(conn->s_svc_sockfd.ereq, (const void**)data, MAX_PKT_BURST);
    
        if (nb_err) {
            fprintf(stderr, "[tcpdpdk] connection was closed by peer\n");
            continue;
        }

        if(!nb_syn) {
            // No connection to check
            continue;
        }

        // Accept the incoming connection requests
        struct tle_stream *client_streams[MAX_PKT_BURST];
        struct tle_tcp_stream_cfg prm[MAX_PKT_BURST];
        nb_req = tle_tcp_stream_accept(conn->s_svc_sockfd.stream, client_streams, MAX_PKT_BURST);
        if (nb_req == 0) {
            continue;
        }

        struct tle_stream *client_stream;
        struct tle_tcp_stream_cfg *cfg;
        for (u32 i = 0; i < nb_req; i++) {
            client_stream = client_streams[i];
            cfg           = &prm[i];

            // Allocate and activate the events from the same queue. "1" refers to the client stream and
            // is used to differentiate the event from syn connections
            cfg->err_ev  = tle_event_alloc(conn->s_svc_sockfd.ereq, (void *)1);
            cfg->recv_ev = tle_event_alloc(conn->s_svc_sockfd.rxeq, (void *)1);
            cfg->send_ev = tle_event_alloc(conn->s_svc_sockfd.txeq, (void *)1);
            tle_event_active(cfg->send_ev, TLE_SEV_DOWN);
            tle_event_active(cfg->recv_ev, TLE_SEV_DOWN);
            tle_event_active(cfg->err_ev, TLE_SEV_DOWN);

            // Save the new stream in the EP state. To do that, we must identify the peer.
            struct tle_tcp_stream_addr addr;
            tle_tcp_stream_get_addr(client_stream, &addr);
            struct sockaddr_in *client_addr = (struct sockaddr_in *)&addr.remote;

            for (int p = 0; p < n_peers; p++) {
                if(client_addr->sin_addr.s_addr == peers[p].ip_net && 
                   rte_be_to_cpu_16(client_addr->sin_port) == ep->app_id) 
                {
                    conn->s_sockfd[p] = (struct tldk_stream_handle){
                        .stream = client_stream,
                        .ereq   = conn->s_svc_sockfd.ereq,
                        .rxeq   = conn->s_svc_sockfd.rxeq,
                        .txeq   = conn->s_svc_sockfd.txeq,
                    };

                    atomic_fetch_add(&conn->connected_peers, 1);
                    fprintf(stderr, "[tcpdpdk] connection manager: accepted connection from %s:%u\n", peers[p].ip_str, ep->app_id);
                    break;
                }
            }
        }

        // Update the stream with the new configuration
        uint32_t res = tle_tcp_stream_update_cfg(client_streams, prm, nb_req);
        if (res != nb_req) {
            fprintf(stderr, "[tcpdpdk] error updating the stream cfg: %s\n", rte_strerror(rte_errno));
            continue;
        }
    }    

    return 0;
}

NSN_DATAPATH_INIT(tcpdpdk) {
    nsn_thread_ctx_t this_thread = nsn_thread_ctx_alloc();
    this_thread.is_main_thread   = false;
    nsn_thread_set_ctx(&this_thread);

    scratch = nsn_thread_scratch_begin(NULL, 0);

    // 1a) Initialize local state 
    n_peers = ctx->n_peers;
    peers = mem_arena_push(scratch.arena, n_peers * sizeof(struct arp_peer));
    for (int i = 0; i < n_peers; i++) {
        peers[i].ip_str = ctx->peers[i];
        peers[i].ip_net = inet_addr(peers[i].ip_str);
        peers[i].mac_set = false;
    }

    // 1b) Retrieve the local IP from the list of parameters
    string_t local_ip_str;
    local_ip_str.data = mem_arena_push(scratch.arena, MAX_PARAM_STRING_SIZE);
    local_ip_str.len = 0;
    int ret = nsn_config_get_string_from_list(&ctx->params, str_lit("ip"), &local_ip_str);
    if (ret < 0) {
        fprintf(stderr, "[tcpdpdk] nsn_config_get_string_from_list() failed: no option \"ip\" found\n");
        goto early_fail;
    }
    local_ip = to_cstr(local_ip_str);
    local_ip_net = inet_addr(local_ip);
    fprintf(stderr, "[tcpdpdk] parameter: ip: %s\n", local_ip);

    // 2a) Get the EAL parameters: first as a single string, then as parameters
    string_t eal_args;
    eal_args.data = (u8*)malloc(MAX_PARAM_STRING_SIZE);
    eal_args.len = 0;
    ret = nsn_config_get_string_from_list(&ctx->params, str_lit("eal_args"), &eal_args);
    if (ret < 0) {
        fprintf(stderr, "[tcpdpdk] nsn_config_get_string_from_list() failed: no option \"eal_args\" found\n");
        goto early_fail;
    }
    fprintf(stderr, "[tcpdpdk] parameter: eal_args: %s\n", to_cstr(eal_args));
    char* argv [MAX_PARAM_STRING_SIZE];
    int argc = 1;
    string_t delimiter = str_lit(" ");
    string_list_t eal_args_list = str_split(scratch.arena, eal_args, &delimiter, 1);
    argv[0] = mem_arena_push(scratch.arena, strlen("tcpdpdk") + 1);
    strcpy(argv[0], "tcpdpdk");
    for(string_node_t *node = eal_args_list.head; node; node = node->next) {
        argv[argc] = mem_arena_push(scratch.arena, node->string.len + 1); 
        strncpy(argv[argc], to_cstr(node->string), node->string.len);
        argc++;
    }
    // Because EAL_INIT remains initialized for the whole process, we need to ensure that each time we start/stop 
    // the plugin, we put EAL files in a different directory. We need to use an ID that is different every time
    // we call it. For the moment, use the curennt time TODO: This is not really secure...
    // The use of different file prefixes is suggested by the DPDK doc for "concurrent primary processes", but
    // there is no mention of "subsequent" primary processes that are started and stopped.
    argv[argc] = mem_arena_push(scratch.arena, strlen("--file-prefix") + 1); 
    strcpy(argv[argc], "--file-prefix");
    argc++;
    argv[argc] = mem_arena_push(scratch.arena, 32);
    sprintf(argv[argc], "nsn_%ld", nsn_os_get_time_ns() % 1000000);
    argc++;

    // 2b) Get the DPDK device name
    string_t dev_name_str;
    dev_name_str.data = mem_arena_push(scratch.arena, MAX_PARAM_STRING_SIZE);
    dev_name_str.len = 0;
    ret = nsn_config_get_string_from_list(&ctx->params, str_lit("pci_device"), &dev_name_str);
    if (ret < 0) {
        fprintf(stderr, "[tcpdpdk] nsn_config_get_string_from_list() failed: no option \"pci_device\" found\n");
        goto early_fail;
    }
    dev_name = to_cstr(dev_name_str);
    fprintf(stderr, "[tcpdpdk] parameter: dev_name: %s\n", dev_name);

    // Now, finally, initialize EAL
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        fprintf(stderr, "[tcpdpdk] rte_eal_init failed: %s\n", rte_strerror(rte_errno));
        goto early_fail;
    }

    // Select the desired device
    bool found = false;
    RTE_ETH_FOREACH_DEV(port_id) {
        ret = rte_eth_dev_info_get(port_id, &devinfo);
        if (ret < 0) {
            fprintf(stderr, "[tcpdpdk] cannot get info for port %u: %s, skipping\n", port_id,
                   rte_strerror(rte_errno));
            continue;
        }
        if(strcmp(rte_dev_name(devinfo.device), dev_name) == 0) {
            fprintf(stderr, "[tcpdpdk] found device %s on port %u\n", dev_name, port_id);
            found = true;
            break;
        }
    }
    if (!found) {
        fprintf(stderr, "[tcpdpdk] device %s not found\n", dev_name);
        goto fail;
    }

    // Check that the NIC supports all the required offloads
    if(!probe_supported_offloads(&devinfo)) {
        fprintf(stderr, "[tcpdpdk] required offloads not supported by the device\n");
        goto fail;
    }

    /* For the moment, we disable the zero-copy RX path. 
     * That is because TLDK must be changed to properly handle incoming
     * multi-segment DPDK mbufs. Once that is fixed, it will be sufficient
     * to uncomment the following line to enable the zero-copy RX path.
     */
    if(devinfo.rx_offload_capa & RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT) {
        fprintf(stderr, "[tcpdpdk] NIC supports buffer split, but zero-copy receive is disabled\n");
        // fprintf(stderr, "[tcpdpdk] NIC supports buffer split: zero-copy receive enabled\n");
        // zc_rx = true;
    }  else {
        fprintf(stderr, "[tcpdpdk] NIC does not support buffer split: zero-copy receive disabled\n");
    }

    ret = rte_eth_dev_get_mtu(port_id, &mtu);
    if(ret) {
        fprintf(stderr, "[tcpdpdk] Error while detecting device MTU: %s\n", strerror(ret));
        goto fail;
    }
    fprintf(stderr, "[tcpdpdk] Device MTU %u bytes\n", mtu);

    socket_id = rte_eth_dev_socket_id(port_id);    
    if (socket_id < 0) {
        if (rte_errno == EINVAL) {
            fprintf(stderr, "[tcpdpdk] cannot get socket ID for port %u: %s.\n", port_id, strerror(-socket_id));
            return -EINVAL;
        } else {
            socket_id = 0; // Default to socket 0 if socket could not be determined (e.g., in VMs)
        }
    } else if (socket_id != (int)rte_socket_id()) {
        fprintf(stderr, "[tcpdpdk] Warning: running on a different socket than that the NIC is attached to!\n");
        goto fail;
    }

    // Get the local MAC address
    ret = rte_eth_macaddr_get(port_id, &local_mac_addr);
    if (ret < 0) {
        fprintf(stderr, "[tcpdpdk] failed to get MAC address for port %u: %s\n", port_id,
                  rte_strerror(rte_errno));
        goto fail;
    }

    // Configure the port
    struct rte_eth_conf port_conf;
    bzero(&port_conf, sizeof(port_conf));
    // port_conf.rxmode.mtu = MTU;
    port_conf.rxmode.offloads |= (RTE_ETH_RX_OFFLOAD_CHECKSUM | RTE_ETH_RX_OFFLOAD_SCATTER);
    if (zc_rx) {
        port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT;
    }
    port_conf.txmode.mq_mode  = RTE_ETH_MQ_TX_NONE;
    port_conf.txmode.offloads |= (RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_MULTI_SEGS);
    if (devinfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
    }
    // if ((ret = rte_eth_dev_set_mtu(port_id, MTU)) != 0) {
    //     fprintf(stderr, "[tcpdpdk] setting mtu failed: %s\n", rte_strerror(rte_errno));
    //     goto fail;
    // }
    nb_rxd = 1024;
    nb_txd = 1024;
    if ((ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd)) != 0) {
        fprintf(stderr, "[tcpdpdk] error setting tx and rx descriptors: %s\n", rte_strerror(rte_errno));
        goto fail;;
    }

    // Isolate the flow - only allow traffic that is specified by the flow rules (RSS filter)
    // i.e., ARP on queue 0 and TCP to app_id port on the other queues
    struct rte_flow_error error;
    ret = rte_flow_isolate(port_id, 1, &error);
    if (ret < 0) {
         fprintf(stderr, "[tcpdpdk] NIC does not support traffic isolation: %s. Skipping...\n", error.message? error.message : rte_strerror(rte_errno));
    }
    
    // Configure the queues. We have:
    // - A single tx queue
    // - n_peers rx queues + 1 (queue 0) for control messages.
    uint16_t tx_queues = 1;
    uint16_t rx_queues = MAX_DEVICE_QUEUES;
    if ((ret = rte_eth_dev_configure(port_id, rx_queues, tx_queues, &port_conf)) != 0) {
        fprintf(stderr, "[tcpdpdk] error configuring device queues: %s\n", rte_strerror(rte_errno));
        goto fail;;
    }

    // Configure the tx queue
    nb_rxd = 1024;
    nb_txd = 1024;
    tx_queue_id = 0;
    struct rte_eth_txconf txconf = devinfo.default_txconf;
    txconf.offloads              = port_conf.txmode.offloads;
    if ((ret = rte_eth_tx_queue_setup(port_id, tx_queue_id, nb_txd, socket_id, &txconf)) != 0) {
        fprintf(stderr, "[tcpdpdk] failed configuring tx queue %u: %s\n", tx_queue_id, rte_strerror(rte_errno));
        goto fail;
    } 

    // Prepare a ring to store the "free" queue IDs
    u32 ring_size = rte_align32pow2(rx_queues);
    void *ring_memory = mem_arena_push(scratch.arena, sizeof(nsn_ringbuf_t) + (sizeof(void*) * ring_size));
    free_queue_ids = nsn_ringbuf_create(ring_memory, str_lit("free_queue_ids"), ring_size);

    // Create a mempool to receive "spare" data, i.e., data not associated to any endpoint,
    // e.g., for ARP and possibly control messages. Used also to tx control msgs.
    ctrl_pool = rte_pktmbuf_pool_create("ctrl_pool", 10239, 64, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
    if (ctrl_pool == NULL) {
        fprintf(stderr, "[tcpdpdk] failed to create mempool ctrl_pool\n");
        goto fail;
    }

    // Configure the rx queue 0 (control traffic) to start immediately
    struct rte_eth_rxconf rx_conf = devinfo.default_rxconf;
    rx_conf.share_group = 0;
    if ((ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd, socket_id, &rx_conf, ctrl_pool)) != 0) {
        fprintf(stderr, "[tcpdpdk] failed configuring rx queue %u: %s\n", 0, rte_strerror(rte_errno));
        goto fail;
    }

    // The remaining queues are confgured with "deferred start"
    // NOTE: some drivers, like mlx5, do not support deferred start, so this will have no effect,
    // and we will need to explicitly stop the queues later. 
    char pool_name[64];
    struct rte_mempool *rx_pool;
    rx_conf.rx_deferred_start = 1;
    for (uint16_t i = 1; i < rx_queues; i++) {                   
        // Create a mempool for the queue (will be retrieved later by the endpoint,
        // using its name, through DPDK). 
        // 1. WHY HERE? Clearly, doing it here wastes memory, as we
        // create the max possible number of mempool ever needed. But the rules on the
        // queue config force us to do so, as we are not able to setup queues after the
        // RTE device is started.
        // 2. WHAT FOR? Header mempool. Must have 10239 as num_mbufs or it will fail. 
        // It is used for TX and RX headers. If zero-copy RX is disabled,
        // it is used for RX payloads as well.
        bzero(pool_name, 64);
        sprintf(pool_name, "hdr_pool_%u", i);
        if ((rx_pool = rte_pktmbuf_pool_create(pool_name, 10239, 64, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id)) ==  NULL) {
            fprintf(stderr, "[tcpdpdk] failed to create mempool %s\n", pool_name);
            goto fail;
        }

        // TODO: Can we do this here also for ZC?
        if (!zc_rx) {
            // Associate the mempool to the queue and request deferred start
            if ((ret = rte_eth_rx_queue_setup(port_id, i, nb_rxd, socket_id, &rx_conf, rx_pool)) != 0) {
                fprintf(stderr, "[tcpdpdk] failed configuring rx queue %u: %s\n", i, strerror(-ret));
                goto fail;
            } 
        }

        // Prepare the descriptor for this data queue (q > 0)
        nsn_ringbuf_enqueue_burst(free_queue_ids, &i, sizeof(void*), 1, NULL);
    }

    // Start the device
    ret = -EAGAIN;
    while (ret == -EAGAIN) {
        ret = rte_eth_dev_start(port_id);
    };
    if (ret) {
        fprintf(stderr, "[tcpdpdk] impossible to start device: %s\n", strerror(-ret));
        goto fail;
    } else {
        dev_stopped = false;
    }

    // This may take up to 9s
    struct rte_eth_link link;
    memset(&link, 0, sizeof(link));
    ret = rte_eth_link_get(port_id, &link);
    if (ret < 0) {
        fprintf(stderr, "[tcpdpdk] failed link get (port %u): %s\n", port_id, strerror(-ret));
        goto fail;
    } else if (!link.link_status) {
        fprintf(stderr, "[tcpdpdk] link never came up on port %u\n", port_id);
        goto fail;
    }

    // ARP packets to be received on queue 0
    rx_arp_flow = configure_arp_rss_flow(port_id, 0, &error);    
    if (rx_arp_flow == NULL) {
        fprintf(stderr, "[tcpdpdk] failed to create ARP flow: %s\n", error.message? error.message : rte_strerror(rte_errno));
        goto fail_and_stop;
    }

    // For each peer, send an ARP request
    for (int i = 0; i < n_peers; i++) {
        arp_request(port_id, tx_queue_id, &local_mac_addr, local_ip_net, peers[i].ip_net, ctrl_pool);
    }

    // Stop the queues that are not used. This is necessary because some drivers, 
    // such as mlx5 and i40e, do not support deferred start, and all queues are 
    // started immediately (and silently). Other, more basic drivers just do not
    // support queue_stop/queue_start at all, so in these case we just go on.
    for (uint16_t i = 1; i < rx_queues; i++) {
        ret = rte_eth_dev_rx_queue_stop(port_id, i);
        if (ret < 0 && ret != -ENOTSUP) {
            fprintf(stderr, "[tcpdpdk] failed to stop queue %u: %s\n", i, strerror(-ret));
        }
    }

    // Init the TLDK context
    ret = init_tldk_ctx();
    if (ret < 0) {
        fprintf(stderr, "[tcpdpdk] init_tldk_ctx() failed\n");
        goto fail_and_stop;
    }

    // Init the TLDK backend thread mutex
    ret = nsn_os_mutex_init(&be_lock); 
    if (ret < 0) {
        fprintf(stderr, "[tcpdpdk] nsn_os_mutex_init() failed\n");
        goto fail_and_stop;
    }

    // Setup the communication channels to the peers
    // This will enable the FLOW RULES, only for the queues that are actually used
    ep_initializer_t *ep_in;
    list_for_each_entry(ep_in, endpoint_list, node) {
        ret = tcpdpdk_datapath_update(ep_in->ep);
        if (ret < 0) {
            fprintf(stderr, "[tcpdpdk] tcpdpdk_datapath_update() failed\n");
            goto fail_and_stop;
        }
        struct tcpdpdk_ep *conn = (struct tcpdpdk_ep *)ep_in->ep->data;
        be_tcp(conn->rx_queue_id);
    }

    // Try to get ARP replies early
    tcpdpdk_datapath_conn_manager(endpoint_list);

    return 0;

fail_and_stop:
    rte_eth_dev_stop(port_id);
fail:
    rte_eal_cleanup();
early_fail:    
    nsn_thread_scratch_end(scratch);
    return -1;

}

NSN_DATAPATH_TX(tcpdpdk) {
    struct rte_mbuf *tx_bufs[MAX_TX_BURST];
    struct rte_mbuf *hdr_mbuf, *data_mbuf;
    uint16_t nb_tx, nb_px;   
    usize i, valid;

    struct tcpdpdk_ep *conn = (struct tcpdpdk_ep *)endpoint->data;

    if (buf_count > MAX_TX_BURST) {
        fprintf(stderr, "[tcpdpdk] tx burst too large\n");
        return -1;
    }

    // Here, we decide to break the stream abstraction of TCP. Assuming that we only send to INSANE DPDK-TCP peers,
    // we just send the payload on the network. Because we control how packets are written on the network, we can
    // avoid unwanted forms of batching (like it happens in the kernel), so we work message-by-message. However,
    // this breaks compatibility with peers that use in-kernel TCP (INSANE-managed or not).
    // To be compatible, we should send, for each packet, the size first, and then the payload. Possibly within the
    // same Ethernet frame payload. For the moment, we don't do that.

    // For each peer that is connected, send the burst of packets 
    for(int p = 0; p < n_peers; p++) {
        if (conn->s_sockfd[p].stream == NULL) {
            continue;
        }

        valid = 0;
        for (usize i = 0; i < buf_count; i++) {
            // Prepare the payload - get the corresponding mbuf from the pool
            data_mbuf = nsn_pktmbuf_alloc(conn->zc_pool, bufs[i].index);
            data_mbuf->pkt_len = data_mbuf->data_len = ((nsn_meta_t*)(nsn_mm_zone_get_ptr(endpoint->tx_meta_zone)) + bufs[i].index)->len;
            if (nsn_unlikely(data_mbuf->data_len == 0 || data_mbuf->data_len > endpoint->io_bufs_size)) {
                fprintf(stderr, "[tcpdpdk] Invalid packet size: %u. Discarding packet...\n", data_mbuf->data_len);
                continue;
            }  
            
            // Header len
            struct rte_mbuf *tx_buf = rte_pktmbuf_alloc(conn->hdr_pool);
            if (!tx_buf) {
                fprintf(stderr, "[tcpdpdk] failed to allocate tx mbuf\n");
                continue;
            }
            tx_buf->data_len = tx_buf->pkt_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
                                                         sizeof(struct rte_tcp_hdr); // + 20; // 20 bytes of options            
            // Chain the mbufs
            rte_pktmbuf_chain(tx_buf, data_mbuf);

            // Prepare the mbuf for TLDK processing
            tx_buf->l2_len = sizeof(struct rte_ether_hdr);
            tx_buf->l3_len = sizeof(struct rte_ipv4_hdr);
            tx_buf->l4_len = sizeof(struct rte_tcp_hdr);
            
            // Move the data_off pointer to the beginning of the data, as required by TLDK
            if (!rte_pktmbuf_adj(tx_buf, tx_buf->data_len)) {
                fprintf(stderr, "[tcpdpdk] failed to move the data_off pointer\n");
            }

            tx_bufs[valid] = tx_buf;
            valid++;
        }

        /* Send ALL the packet(s) to the TLDK stack */
        uint16_t np_tx = 0;
        do {
            np_tx += tle_tcp_stream_send(conn->s_sockfd[p].stream, tx_bufs + np_tx, valid - np_tx);
            be_tcp(conn->rx_queue_id);
        } while(np_tx < valid);
    }
    return buf_count;
}

NSN_DATAPATH_RX(tcpdpdk) {

    struct tcpdpdk_ep *conn = (struct tcpdpdk_ep *)endpoint->data;
    struct rte_mbuf *rx_bufs[MAX_RX_BURST];
    assert(*buf_count <= MAX_RX_BURST);

    struct tldk_stream_handle* hdl;
    char *error_data[MAX_PKT_BURST];
    uint32_t ne_err, nb_rx;
    usize valid = 0;

    // To receive in zero-copy, we need to break the stream abstraction of TCP. INSANE DPDK-TCP operates
    // per-packet, so no metadata, such as payload size, has to be sent before the payload. This is different
    // from the kernel, where we need to send the payload size before the payload. We assume that NO BATCHING
    // is done and that 1 TCP segment received corresponds to 1 INSANE application packet.

    // Progress the backend
    be_tcp(conn->rx_queue_id);

    // In TCP we decide to receive 1 pkt per time from each peer.
    usize buf_size;
    for (int p = 0; p < n_peers; p++) {    

        // If peer not connected, skip
        if (conn->s_sockfd[p].stream == NULL) {
            continue;
        }

        hdl = &conn->s_sockfd[p];

        // Check for errors
        if ((ne_err = tle_evq_get(hdl->ereq, (const void**)error_data, 1)) > 0 && ((uint64_t)error_data[0]) == 1) {
            fprintf(stderr, "[tcpdpdk] connection closed by %s\n", peers[p].ip_str);
            hdl->stream = NULL;
            atomic_fetch_sub(&conn->connected_peers, 1);
            continue;
        }

        // Process received packets for this stream
        struct rte_mbuf *mbuf;
        nb_rx = tle_tcp_stream_recv(hdl->stream, (struct rte_mbuf**)&rx_bufs, MAX_PKT_BURST);
        for(uint16_t i = 0; i < nb_rx; i++) {
            mbuf = rx_bufs[i];
            
            if(zc_rx) {
                // This is for debug purpose! We should not receive packets with less than 2 segments
                if(mbuf->nb_segs != 2) {
                    fprintf(stderr, "[tcpdpdk] received packet with %u segments, expected 2\n", mbuf->nb_segs);
                    rte_pktmbuf_free(mbuf);
                    continue;
                }

                // Set the index (zero-copy receive)
                bufs[valid].index = *(usize*)(mbuf->next + 1); 
                usize *size = &((nsn_meta_t*)(nsn_mm_zone_get_ptr(endpoint->tx_meta_zone)) + bufs[valid].index)->len;
                *size = mbuf->next->data_len; //TODO: Is this ok?
                
                // Finalize the rx
                *buf_count  = *buf_count - 1;
                valid++;
                
                // Release the mbuf with custom free: DO NOT RE-ENQUEUE the index (the app will do that)
                // This modified function only frees DPDK-specific resources, but not the INSANE-backed mbuf (the app will do that)
                nsn_pktmbuf_free(mbuf);
            } else {
                // Get the packet payload
                char* payload = rte_pktmbuf_mtod(mbuf, char*);
                usize payload_size = mbuf->data_len;

                // Get the NSN buffer memory
                bufs[valid] = conn->pending_rx_buf;
                char *data  = (char*)(nsn_mm_zone_get_ptr(endpoint->tx_zone)) + (bufs[valid].index * endpoint->io_bufs_size);
                usize *size = &((nsn_meta_t*)(nsn_mm_zone_get_ptr(endpoint->tx_meta_zone)) + bufs[valid].index)->len;

                // Copy the packet payload to the NSN buffer memory        
                *size = payload_size;        
                memcpy(data, payload, payload_size);
                *buf_count  = *buf_count - 1;
                valid++;

                // Release the mbuf
                rte_pktmbuf_free(mbuf);
                
                // Update the pending tx descriptor
                u32 np = nsn_ringbuf_dequeue_burst(endpoint->free_slots, &conn->pending_rx_buf, sizeof(conn->pending_rx_buf), 1, NULL);
                if (np == 0) {
                    fprintf(stderr, "[tcpdpdk] No free slots for next receive! Ring: %p [count %u]\n", endpoint->free_slots, nsn_ringbuf_count(endpoint->free_slots));
                }
            }
        }
    }

    return (int)valid;
}

NSN_DATAPATH_DEINIT(tcpdpdk)
{
    nsn_unused(ctx);

    // Close all the open connections. Here, not in the update(), because of the comment below.
    // For plugin closing before this DEINIT, the connections will be closed in the update() function.
    int res;
    struct ep_initializer *ep_in;
    list_for_each_entry(ep_in, endpoint_list, node) {
        struct tcpdpdk_ep *conn = (struct tcpdpdk_ep *)ep_in->ep->data;
        if(!conn) {
            continue;
        }
        if(conn->s_svc_sockfd.stream) {
            res = tle_tcp_stream_close(conn->s_svc_sockfd.stream);
            be_tcp(conn->rx_queue_id);
            conn->s_svc_sockfd.stream = NULL;
        }
        for(u16 i = 0; i < n_peers; i++) {
            if(conn->s_sockfd[i].stream) {
                // Flush pending data
                while(tle_tcp_stream_tx_pending(conn->s_sockfd[i].stream)) {
                    be_tcp(conn->rx_queue_id);
                }
                res = tle_tcp_stream_close(conn->s_sockfd[i].stream);
                be_tcp(conn->rx_queue_id);
                conn->s_sockfd[i].stream = NULL;
                atomic_fetch_sub(&conn->connected_peers, 1);
            }
        }
    }

    // Handle the close()
    list_for_each_entry(ep_in, endpoint_list, node) {
        struct tcpdpdk_ep *conn = (struct tcpdpdk_ep *)ep_in->ep->data;
        if(!conn) {
            continue;
        }
        be_tcp(conn->rx_queue_id);
    }
    
    // Stop the device (and all queues, consequently). Must be done BEFORE destroying resources 
    // (e.g., mempools etc.) => i.e., call this BEFORE the tcpdpdk_datapath_update() below.
    res = rte_eth_dev_stop(port_id);
    if (res < 0) {
        fprintf(stderr, "[tcpdpdk] failed to stop device: %s\n", strerror(-res));
    }
    dev_stopped = true;
    
    // This may take up to 9s
    struct rte_eth_link link;
    memset(&link, 0, sizeof(link));
    res = rte_eth_link_get(port_id, &link);
    if (res < 0) {
        fprintf(stderr, "[tcpdpdk] failed link get (port %u): %s\n", port_id, strerror(-res));
    } else if (link.link_status) {
        fprintf(stderr, "[tcpdpdk] link still up on port %u\n", port_id);
    }

    list_for_each_entry(ep_in, endpoint_list, node) {
        res = tcpdpdk_datapath_update(ep_in->ep);
        if (res < 0) {
            fprintf(stderr, "[tcpdpdk] failed cleanup of endpoint %d\n", ep_in->ep->app_id);
        }
    }

    res = rte_eth_dev_close(port_id);
    if (res < 0) {
        fprintf(stderr, "[tcpdpdk] failed to close device: %s\n", strerror(-res));
    }

    res = rte_eal_cleanup();
    if (res < 0) {
        fprintf(stderr, "[tcpdpdk] failed to cleanup EAL: %s\n", strerror(-res));
    }

    // Destroy the scratch memory
    nsn_thread_scratch_end(scratch);

    return 0;
}
