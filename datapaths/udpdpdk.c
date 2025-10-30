#define _GNU_SOURCE

#include "dpdk_common.h"
#include "protocols.h"

#include "../src/common/nsn_temp.h"
#include "../src/base/nsn_os_linux.c"

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


// Per-endpoint state
struct udpdpdk_ep {
    u16 rx_queue_id;
    struct rte_mempool *hdr_pool; // Pool for headers, and RX payloads if zc_rx is false
    struct rte_mempool *zc_pool;  // Pool for zero-copy TX and RX
    struct rte_flow *app_flow;
    nsn_buf_t pending_rx_buf; // For non zero-copy receive
};

// Plugin state
static struct arp_peer* peers; // Works as ARP cache
static u16 n_peers;
static char* local_ip;
static uint32_t local_ip_net;
static struct rte_ether_addr local_mac_addr;
static char*  dev_name;
static u16    port_id;
static u16    tx_queue_id;
static int    socket_id;
static u16    nb_rxd;
static u16    nb_txd;
static struct rte_eth_dev_info devinfo;
static nsn_ringbuf_t *free_queue_ids;
struct rte_mempool *ctrl_pool;
static temp_mem_arena_t scratch;
static struct rte_flow *rx_arp_flow;
static bool dev_stopped = true;

// Zero-copy RX switch
static bool zc_rx = false;

/* Protocols */
static inline void 
prepare_headers(
    struct rte_mbuf *hdr_mbuf, size_t payload_size, 
    uint16_t udp_port, int peer_idx
) {

    struct rte_ether_hdr *ehdr;
    struct rte_ipv4_hdr *ih;
    struct rte_udp_hdr *uh;

    // Ethernet
    {
        ehdr = rte_pktmbuf_mtod(hdr_mbuf, struct rte_ether_hdr*);
        memcpy(&ehdr->src_addr, local_mac_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
        memcpy(&ehdr->dst_addr, &peers[peer_idx].mac_addr, RTE_ETHER_ADDR_LEN);
        ehdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);
    }

    // IP
    {
        ih = (struct rte_ipv4_hdr *)(ehdr + 1);
        memory_zero_struct(ih);
        ih->src_addr        = local_ip_net;
        ih->dst_addr        = peers[peer_idx].ip_net;
        ih->version         = IPV4;
        ih->ihl             = 0x05;
        ih->total_length    = htons(payload_size + IP_HDR_LEN + UDP_HDR_LEN);
        ih->time_to_live    = 64;
        ih->next_proto_id   = IP_UDP;
        ih->hdr_checksum    = rte_ipv4_cksum(ih);
    }

    // UDP
    {
        uh = (struct rte_udp_hdr *)(ih + 1);
        memory_zero_struct(uh);
        uh->dst_port    = htons(udp_port);
        uh->src_port    = htons(udp_port);
        uh->dgram_len   = htons(payload_size + UDP_HDR_LEN);
    }

    // Finally, set the data_len and pkt_len: only headers! The payload size is in another mbuf
    hdr_mbuf->data_len = hdr_mbuf->pkt_len = RTE_ETHER_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
}

/* API */
NSN_DATAPATH_UPDATE(udpdpdk)
{
    if (endpoint == NULL) {
        fprintf(stderr, "[udpdpdk] invalid endpoint\n");
        return -1;
    }

    // Case 1. Delete endpoint data.
    if(endpoint->data) {
        struct udpdpdk_ep *conn = (struct udpdpdk_ep *)endpoint->data;
        
        // Destroy the flow
        if (conn->app_flow) {
            rte_flow_destroy(port_id, conn->app_flow, NULL);
        }

        // If the device is active, just stop this queue, not the entire device
        if(!dev_stopped) {
            int res = rte_eth_dev_rx_queue_stop(port_id, conn->rx_queue_id);
            if (res < 0) {
                fprintf(stderr, "[udpdpdk] failed to stop the device queue: %s\n", rte_strerror(rte_errno));
            }
        }

        // Destroy the ZC mempool. The HDR mempool can be re-used by the next app,
        // as it is associated with the device RX queue and not to the endpoint.
        rte_mempool_free(conn->zc_pool);

        // Un-register memory
        void *addr = (void*)((usize)endpoint->tx_zone & 0xFFFFFFFFFFF00000);
        usize len  = align_to((endpoint->tx_zone->total_size + (((void*)endpoint->tx_zone) - addr)),
                              endpoint->page_size);
        unregister_memory_area(addr, len, endpoint->page_size, port_id);

        if (!zc_rx) {
            // Return the pending buffer to the free slots
            nsn_ringbuf_enqueue_burst(endpoint->free_slots, &conn->pending_rx_buf, sizeof(conn->pending_rx_buf), 1, NULL);
        }

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
            fprintf(stderr, "[udpdpdk] No free queues left for the application\n");
            return -1;
        }

        // create the state of the endpoint, which will hold connection data
        endpoint->data = malloc(sizeof(struct udpdpdk_ep));
        if (endpoint->data == NULL) {
            fprintf(stderr, "[udpdpdk] malloc() failed\n");
            return -1;
        }
        endpoint->data_size = sizeof(struct udpdpdk_ep);

        // Initialize the state of the endpoint
        struct udpdpdk_ep *conn = (struct udpdpdk_ep*)endpoint->data;

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
            rx_seg->length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr);
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
                fprintf(stderr, "[udpdpdk] failed configuring rx queue %u: %s\n", conn->rx_queue_id, rte_strerror(rte_errno));
                goto error_2;
            }
        } else {
            // get a descriptor to receive
            u32 np = nsn_ringbuf_dequeue_burst(endpoint->free_slots, &conn->pending_rx_buf, sizeof(conn->pending_rx_buf), 1, NULL);
            if (np == 0) {
                printf("[udpdpdk] No free slots to receive from ring %p [%u]\n", endpoint->free_slots, nsn_ringbuf_count(endpoint->free_slots));
                goto error_2;
            }

            // // Setup the RX queue using the selected configuration
            // if ((ret = rte_eth_rx_queue_setup(port_id, conn->rx_queue_id, nb_rxd, socket_id, NULL, conn->hdr_pool)) != 0) {
            //     fprintf(stderr, "[udpdpdk] failed configuring rx queue %u: %s\n", conn->rx_queue_id, rte_strerror(-ret));
            //     goto error_4;
            // }
        }

        // Start the queue
        ret = rte_eth_dev_rx_queue_start(port_id, conn->rx_queue_id);
        if (ret < 0 && ret != -ENOTSUP) {
            fprintf(stderr, "[udpdpdk] failed to start queue %u: %s\n", conn->rx_queue_id, strerror(-ret));
            goto error_3;
        }

        // Now create the RSS filter on that queue for this endpoint's UDP port.
        // Do this immediately after the queue is started
        struct rte_flow_error flow_error;
        conn->app_flow = configure_udp_rss_flow(port_id, conn->rx_queue_id, local_ip, endpoint->app_id, &flow_error);
        if (conn->app_flow == NULL) {
            fprintf(stderr, "[udpdpdk] failed to create flow: %s\n", flow_error.message ? flow_error.message : "unkown");
            goto error_4;
        }

        return 0;
error_4:
        rte_eth_dev_rx_queue_stop(port_id, conn->rx_queue_id);
error_3:
        if (!zc_rx) {
            nsn_ringbuf_enqueue_burst(endpoint->free_slots, &conn->pending_rx_buf, sizeof(conn->pending_rx_buf), 1, NULL); 
        }
error_2:
        rte_mempool_free(conn->zc_pool);
error_1:
        nsn_ringbuf_enqueue_burst(free_queue_ids, &conn->rx_queue_id, sizeof(void*), 1, NULL);
        free(conn);
        return -1;
    }
    return 0;
}

NSN_DATAPATH_CONN_MANAGER(udpdpdk)
{
    // Because this gets called periodically, we can put here the management of queue 0,
    // which is used for control messages (e.g., ARP).
    nsn_unused(endpoint_list);
    struct rte_mbuf      *pkts_burst[MAX_RX_BURST_ARP];
    struct rte_ether_hdr *eth_hdr;
    u16 ether_type;
    
    const u16 queue_id = 0;
    u16 rx_count  = rte_eth_rx_burst(port_id, 0, pkts_burst, MAX_RX_BURST_ARP);
    if (rx_count > 0)
        fprintf(stderr, "[%s] received %u packets\n", __func__, rx_count);
    
    for (int j = 0; j < rx_count; j++) {
        eth_hdr    = rte_pktmbuf_mtod(pkts_burst[j], struct rte_ether_hdr *);
        ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
        switch (ether_type) {
            case RTE_ETHER_TYPE_ARP: {
                fprintf(stderr, "[%s] handling an ARP packet (%d)\n", __func__, j);
                arp_receive(port_id, tx_queue_id, &local_mac_addr, local_ip_net, pkts_burst[j], peers, n_peers);
            } break;
            default: {
                fprintf(stderr, "[%s] received an unexpected packet with etype=%x (%d)\n", 
                        __func__, ether_type, j);
                rte_pktmbuf_free(pkts_burst[j]);
            } break;
        }
    }
   
    return 0;
}

NSN_DATAPATH_INIT(udpdpdk)
{
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
        fprintf(stderr, "[udpdpdk] nsn_config_get_string_from_list() failed: no option \"ip\" found\n");
        goto early_fail;
    }
    local_ip = to_cstr(local_ip_str);
    local_ip_net = inet_addr(local_ip);
    fprintf(stderr, "[udpdpdk] parameter: ip: %s\n", local_ip);

    // 2a) Get the EAL parameters: first as a single string, then as parameters
    string_t eal_args;
    eal_args.data = (u8*)malloc(MAX_PARAM_STRING_SIZE);
    eal_args.len = 0;
    ret = nsn_config_get_string_from_list(&ctx->params, str_lit("eal_args"), &eal_args);
    if (ret < 0) {
        fprintf(stderr, "[udpdpdk] nsn_config_get_string_from_list() failed: no option \"eal_args\" found\n");
        goto early_fail;
    }
    fprintf(stderr, "[udpdpdk] parameter: eal_args: %s\n", to_cstr(eal_args));
    char* argv [MAX_PARAM_STRING_SIZE];
    int argc = 1;
    string_t delimiter = str_lit(" ");
    string_list_t eal_args_list = str_split(scratch.arena, eal_args, &delimiter, 1);
    argv[0] = mem_arena_push(scratch.arena, strlen("udpdpdk") + 1);
    strcpy(argv[0], "udpdpdk");
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
        fprintf(stderr, "[udpdpdk] nsn_config_get_string_from_list() failed: no option \"pci_device\" found\n");
        goto early_fail;
    }
    dev_name = to_cstr(dev_name_str);
    fprintf(stderr, "[udpdpdk] parameter: dev_name: %s\n", dev_name);

    // Now, finally, initialize EAL
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        fprintf(stderr, "[udpdpdk] rte_eal_init failed: %s\n", rte_strerror(rte_errno));
        goto early_fail;
    }

    // Select the desired device
    bool found = false;
    RTE_ETH_FOREACH_DEV(port_id) {
        ret = rte_eth_dev_info_get(port_id, &devinfo);
        if (ret < 0) {
            fprintf(stderr, "[udpdpdk] cannot get info for port %u: %s, skipping\n", port_id,
                   rte_strerror(rte_errno));
            continue;
        }
        if(strcmp(rte_dev_name(devinfo.device), dev_name) == 0) {
            fprintf(stderr, "[udpdpdk] found device %s on port %u\n", dev_name, port_id);
            found = true;
            break;
        }
    }
    if (!found) {
        fprintf(stderr, "[udpdpdk] device %s not found\n", dev_name);
        goto fail;
    }

    // Check that the NIC supports all the required offloads
    if(!probe_supported_offloads(&devinfo)) {
        fprintf(stderr, "[udpdpdk] required offloads not supported by the device\n");
        goto fail;
    }
    
    // Check that the NIC supports the buffer split offload, to enable zero-copy receive
    if(devinfo.rx_offload_capa & RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT) {
        fprintf(stderr, "[udpdpdk] NIC supports buffer split: zero-copy receive enabled\n");
        zc_rx = true;
    } else {
        fprintf(stderr, "[udpdpdk] NIC does not support buffer split: zero-copy receive disabled\n");
    }

    socket_id = rte_eth_dev_socket_id(port_id);    
    if (socket_id < 0) {
        if (rte_errno) {
            fprintf(stderr, "[udpdpdk] cannot get socket id: %s\n", rte_strerror(rte_errno));
            goto fail;
        } else {
            socket_id = rte_socket_id();
        }
    } else if (socket_id != (int)rte_socket_id()) {
        fprintf(stderr, "[udpdpdk] Warning: running on a different socket than that the NIC is attached to!\n");
        goto fail;
    }

    // Get the local MAC address
    ret = rte_eth_macaddr_get(port_id, &local_mac_addr);
    if (ret < 0) {
        fprintf(stderr, "[udpdpdk] failed to get MAC address for port %u: %s\n", port_id,
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
    //     fprintf(stderr, "[udpdpdk] setting mtu failed: %s\n", rte_strerror(rte_errno));
    //     goto fail;
    // }
    nb_rxd = 1024;
    nb_txd = 1024;
    if ((ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd)) != 0) {
        fprintf(stderr, "[udpdpdk] error setting tx and rx descriptors: %s\n", rte_strerror(rte_errno));
        goto fail;
    }

    // Isolate the flow - only allow traffic that is specified by the flow rules (RSS filter)
    // i.e., ARP on queue 0 and UDP to app_id port on the other queues
    struct rte_flow_error error;
    ret = rte_flow_isolate(port_id, 1, &error);
    if (ret < 0) {
        fprintf(stderr, "[udpdpdk] NIC does not support traffic isolation: %s. Skipping...\n", error.message? error.message : rte_strerror(rte_errno));
    }
    
    // Configure the queues. We have:
    // - A single tx queue
    // - n_peers rx queues + 1 (queue 0) for control messages.
    uint16_t tx_queues = 1;
    uint16_t rx_queues = MAX_DEVICE_QUEUES;
    if ((ret = rte_eth_dev_configure(port_id, rx_queues, tx_queues, &port_conf)) != 0) {
        fprintf(stderr, "[udpdpdk] error configuring device queues: %s\n", rte_strerror(rte_errno));
        goto fail;;
    }

    // Configure the tx queue
    nb_rxd = 1024;
    nb_txd = 1024;
    tx_queue_id = 0;
    struct rte_eth_txconf txconf = devinfo.default_txconf;
    txconf.offloads              = port_conf.txmode.offloads;
    if ((ret = rte_eth_tx_queue_setup(port_id, tx_queue_id, nb_txd, socket_id, &txconf)) != 0) {
        fprintf(stderr, "[udpdpdk] failed configuring tx queue %u: %s\n", tx_queue_id, rte_strerror(rte_errno));
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
        fprintf(stderr, "[udpdpdk] failed to create mempool ctrl_pool\n");
        goto fail;
    }

    // Configure the rx queue 0 (control traffic) to start immediately
    struct rte_eth_rxconf rx_conf = devinfo.default_rxconf;
    rx_conf.share_group = 0;
    if ((ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd, socket_id, &rx_conf, ctrl_pool)) != 0) {
        fprintf(stderr, "[udpdpdk] failed configuring rx queue %u: %s\n", 0, rte_strerror(rte_errno));
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
            fprintf(stderr, "[udpdpdk] failed to create mempool %s\n", pool_name);
            goto fail;
        }

        // TODO: Can we do this here also for ZC?
        if (!zc_rx) {
            // Associate the mempool to the queue and request deferred start
            if ((ret = rte_eth_rx_queue_setup(port_id, i, nb_rxd, socket_id, &rx_conf, rx_pool)) != 0) {
                fprintf(stderr, "[udpdpdk] failed configuring rx queue %u: %s\n", i, strerror(-ret));
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
        fprintf(stderr, "[udpdpdk] impossible to start device: %s\n", strerror(-ret));
        goto fail;
    } else {
        dev_stopped = false;
    }

    // This may take up to 9s
    struct rte_eth_link link;
    memset(&link, 0, sizeof(link));
    ret = rte_eth_link_get(port_id, &link);
    if (ret < 0) {
        fprintf(stderr, "[udpdpdk] failed link get (port %u): %s\n", port_id, strerror(-ret));
        goto fail;
    } else if (!link.link_status) {
        fprintf(stderr, "[udpdpdk] link never came up on port %u\n", port_id);
        goto fail;
    }

    // ARP packets to be received on queue 0
    rx_arp_flow = configure_arp_rss_flow(port_id, 0, &error);    
    if (rx_arp_flow == NULL) {
        fprintf(stderr, "[udpdpdk] failed to create ARP flow: %s\n", error.message? error.message : rte_strerror(rte_errno));
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
            fprintf(stderr, "[udpdpdk] failed to stop queue %u: %s\n", i, strerror(-ret));
        }
    }

    // Setup the communication channels to the peers
    // This will enable the FLOW RULES, only for the queues that are actually used
    ep_initializer_t *ep_in;
    list_for_each_entry(ep_in, endpoint_list, node) {
        ret = udpdpdk_datapath_update(ep_in->ep);
        if (ret < 0) {
            fprintf(stderr, "[udpdpdk] udpdpdk_datapath_update() failed\n");
            goto fail_and_stop;
        }
    }

    // Try to get ARP replies early
    udpdpdk_datapath_conn_manager(endpoint_list);

    return 0;

fail_and_stop:
    rte_eth_dev_stop(port_id);
fail:
    rte_eal_cleanup();
early_fail:    
    nsn_thread_scratch_end(scratch);
    return -1;
}

NSN_DATAPATH_TX(udpdpdk)
{
    struct rte_mbuf *tx_bufs[MAX_TX_BURST];
    struct rte_mbuf *hdr_mbuf, *data_mbuf;
    uint16_t nb_tx, nb_px;   
    struct udpdpdk_ep *conn = (struct udpdpdk_ep *)endpoint->data;
    int ret;

    if (buf_count > MAX_TX_BURST) {
        fprintf(stderr, "[udpdpdk] tx burst too large\n");
        return -1;
    }

    for(int p = 0; p < n_peers; p++) {
        if (!peers[p].mac_set) {
            // This peer did not reply to the ARP request, so it is not ready to receive data
            fprintf(stderr, "[udpdpdk] peer %d not ready\n", p);
            continue;
        }        

        // Prepare the header mbuf
        ret = rte_pktmbuf_alloc_bulk(conn->hdr_pool, tx_bufs, buf_count);
        if (ret < 0) {
            fprintf(stderr, "[udpdpdk] failed to allocate header mbufs: %s\n", strerror(-ret));
            continue;
        }
        

        for (usize i = 0; i < buf_count; i++) {
            // Get the data and size from the index
            char* data = ((char*)(nsn_mm_zone_get_ptr(endpoint->tx_zone)) + (bufs[i].index * endpoint->io_bufs_size));
            usize size = ((nsn_meta_t*)(nsn_mm_zone_get_ptr(endpoint->tx_meta_zone)) + bufs[i].index)->len;

            // Prepare the header
            prepare_headers(tx_bufs[i], size, endpoint->app_id, p);
            
            // Prepare the payload - get the corresponding mbuf from the pool
            data_mbuf = nsn_pktmbuf_alloc(conn->zc_pool, bufs[i].index);
            if(data_mbuf == NULL) {
                fprintf(stderr, "[udpdpdk] failed to allocate data mbuf for index %lu\n", bufs[i].index);
            }
            data_mbuf->pkt_len = data_mbuf->data_len = size;
           
            // Chain the mbufs
            rte_pktmbuf_chain(tx_bufs[i], data_mbuf);
        }

        // Send the burst. All of it!
        nb_tx = 0;
        while (nb_tx < buf_count) {
            nb_tx += rte_eth_tx_burst(port_id, tx_queue_id, &tx_bufs[nb_tx], buf_count - nb_tx);
        }
    }
    
    return buf_count;
}

NSN_DATAPATH_RX(udpdpdk)
{
    struct udpdpdk_ep *conn = (struct udpdpdk_ep *)endpoint->data;
    struct rte_mbuf *rx_bufs[MAX_RX_BURST];
    assert(*buf_count <= MAX_RX_BURST);

    // Receive the packets
    uint16_t nb_rx = rte_eth_rx_burst(port_id, conn->rx_queue_id, rx_bufs, *buf_count);

    // Deliver only UDP packet payloads
    usize valid = 0;
    for(uint16_t i = 0; i < nb_rx; i++) 
    {
        struct rte_mbuf *mbuf = rx_bufs[i];
        struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
        struct rte_ipv4_hdr *ih = (struct rte_ipv4_hdr *)(eth_hdr + 1);
        struct rte_udp_hdr *uh = (struct rte_udp_hdr *)(ih + 1);

        // Check if the packet is UDP
        if (rte_be_to_cpu_16(eth_hdr->ether_type) != RTE_ETHER_TYPE_IPV4 || ih->next_proto_id != IP_UDP) {
            rte_pktmbuf_free(mbuf);
            continue;
        }

        // Check if the packet is for this IP
        if (ih->dst_addr != local_ip_net) {
            rte_pktmbuf_free(mbuf);
            continue;
        }
        
        // Check if the packet is for this app
        if (rte_be_to_cpu_16(uh->dst_port) != endpoint->app_id) {
            rte_pktmbuf_free(mbuf);
            continue;
        }

        // fprintf(stderr, "[udpdpdk] received packet on port %u on queue %u with %u segs, total len %u\n",
        //        port_id, conn->rx_queue_id, mbuf->nb_segs, mbuf->pkt_len);
        // struct rte_mbuf *cur = mbuf;
        // for (int k = 0; k < mbuf->nb_segs; k++) {
        //     printf(" - seg %d len %u from mempool %s\n", k + 1, cur->data_len,
        //            cur->pool->name);
        //     cur = cur->next;
        // }       

        if(zc_rx) {
            if(mbuf->nb_segs != 2) {
                fprintf(stderr, "[udpdpdk] received packet with %u segments, expected 2\n", mbuf->nb_segs);
                rte_pktmbuf_free(mbuf);
                continue;
            }

            // Set the index (zero-copy receive)
            bufs[valid].index = *(usize*)(mbuf->next + 1);

            // Set the size
            usize *size = &((nsn_meta_t*)(nsn_mm_zone_get_ptr(endpoint->tx_meta_zone)) + bufs[valid].index)->len;
            *size = rte_be_to_cpu_16(uh->dgram_len) - sizeof(struct rte_udp_hdr);
            
            // Finalize the rx
            *buf_count  = *buf_count - 1;
            valid++;

            // Release the mbuf with custom free: DO NOT RE-ENQUEUE the index (the app will do that)
            nsn_pktmbuf_free(mbuf);
        } else {
            // Get the packet payload
            char* payload = (char*)(uh + 1);
            usize payload_size = rte_be_to_cpu_16(uh->dgram_len) - sizeof(struct rte_udp_hdr); 

            // Get the NSN buffer memory
            bufs[valid] = conn->pending_rx_buf;
            char *data  = (char*)(nsn_mm_zone_get_ptr(endpoint->tx_zone)) + (bufs[valid].index * endpoint->io_bufs_size);    
            usize *size = &((nsn_meta_t*)(nsn_mm_zone_get_ptr(endpoint->tx_meta_zone)) + bufs[valid].index)->len;

            // Copy the packet payload to the NSN buffer memory        
            *size = payload_size;        
            memcpy(data, (char*)(uh + 1), payload_size);
            *buf_count  = *buf_count - 1;
            valid++;

            // Release the mbuf
            rte_pktmbuf_free(mbuf);
            
            // Update the pending tx descriptor
            u32 np = nsn_ringbuf_dequeue_burst(endpoint->free_slots, &conn->pending_rx_buf, sizeof(conn->pending_rx_buf), 1, NULL);
            if (np == 0) {
                printf("[udpdpdk] No free slots for next receive! Ring: %p [count %u]\n", endpoint->free_slots, nsn_ringbuf_count(endpoint->free_slots));
            }

        }
    }

    return (int)valid;
}

NSN_DATAPATH_DEINIT(udpdpdk)
{
    nsn_unused(ctx);

    // Stop the device (and all queues, consequently). Must be done BEFORE destroying resources 
    // (e.g., mempools etc.) => i.e., call this BEFORE the udpdpdk_datapath_update() below.
    int res = rte_eth_dev_stop(port_id);
    if (res < 0) {
        fprintf(stderr, "[udpdpdk] failed to stop device: %s\n", strerror(-res));
    }
    dev_stopped = true;

    // This may take up to 9s
    struct rte_eth_link link;
    memset(&link, 0, sizeof(link));
    res = rte_eth_link_get(port_id, &link);
    if (res < 0) {
        fprintf(stderr, "[udpdpdk] failed link get (port %u): %s\n", port_id, strerror(-res));
    } else if (link.link_status) {
        fprintf(stderr, "[udpdpdk] link still up on port %u\n", port_id);
    }

    struct ep_initializer *ep_in;
    list_for_each_entry(ep_in, endpoint_list, node) {
        res = udpdpdk_datapath_update(ep_in->ep);
        if (res < 0) {
            fprintf(stderr, "[udpdpdk] failed cleanup of endpoint %d\n", ep_in->ep->app_id);
        }
    }

    res = rte_eth_dev_close(port_id);
    if (res < 0) {
        fprintf(stderr, "[udpdpdk] failed to close device: %s\n", strerror(-res));
    }

    res = rte_eal_cleanup();
    if (res < 0) {
        fprintf(stderr, "[udpdpdk] failed to cleanup EAL: %s\n", strerror(-res));
    }

    // Destroy the scratch memory
    nsn_thread_scratch_end(scratch);

    return 0;
}