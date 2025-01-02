#include "../src/nsn_datapath.h"
#include "../src/nsn_config.c"
#include "../src/nsn_string.c"
#include "../src/nsn_memory.c"
#include "../src/nsn_ringbuf.c"
#include "../src/nsn_os_linux.c"

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_flow.h>

#include "protocols.h"

// This DPDK plugin assumes we are working with NICs that use the mlx5 driver.
// We need RSS filtering to enable the zero-copy receive, because we can associate
// different mempools with different queues, i.e., different applications. 
// However, the mlx5 driver does not allow to have just some queues active and some
// stopped (as DPDK would allow with rx_deferred starte). So we need to configure and
// start a number of queues (MAX_DEVICE_QUEUES) which will be active immediately.
// Hence, we set the rte_isolate_flow() to ensure that a queue only receives packets
// matching its RSS flow rule. This has some implications:
// - we need to create a rule to receive ARP packets on queue 0 (control queue)
// - isolate() works only for bifurcated drivers: other drivers will need code to 
//     ensure that all traffic not matching the RSS ruls of other queues is received
//     on queue 0 (or dropped)
// - we did not include rte_queue_start() logic which will be nice to have when supported


#define MAX_PARAM_STRING_SIZE 2048
#define MAX_DEVICE_QUEUES     16    // Must be at least 2
#define MAX_RX_BURST_ARP      8     // Must be at least 8
#define MAX_TX_BURST          64    // Must be at least 32

// Per-endpoint state
struct udpdpdk_ep {
    u16 rx_queue_id;
    struct rte_mempool *rx_pool;
    struct rte_mempool *tx_hdr_pool;
    struct rte_mempool *tx_data_pool;
    struct rte_flow *app_flow;
    nsn_buf_t pending_rx_buf;
};

// Peer descriptor - augmented
struct udpdpdk_peer {
    char* ip_str; // IP in string form
    u32   ip_net; // IP in network byte order
    bool  mac_set; // MAC address set or not (for ARP)
    struct rte_ether_addr mac_addr; // MAC address
};

// Local state
static struct udpdpdk_peer* peers; // Works as ARP cache
static u16 n_peers;
static char* local_ip;
static uint32_t local_ip_net;
static struct rte_ether_addr local_mac_addr;
static u16    port_id;
static u16    tx_queue_id;
static int    socket_id;
static nsn_ringbuf_t *free_queue_ids;
struct rte_mempool *ctrl_pool;
static temp_mem_arena_t scratch;
struct rte_flow *rx_arp_flow;

/* Configuration */

// Register with DPDK and with the NIC an arbitrary memory area for zero-copy send/receive
// WARNING: "addr" and "len" MUST be aligned to the "page size"
static inline int register_memory_area(void *addr, const uint64_t len, uint32_t page_size,
                                       uint16_t port_id) {
    // Pin pages in memory (necessary if we do not use hugepages)
    mlock(addr, len);

    fprintf(stderr, "[udpdpdk] registering memory area %p, len %lu, page_size %u, port_id %u\n", addr, len, page_size, port_id);

    // Prepare for the external memory registration with DPDK: compute page IOVAs
    uint32_t    n_pages = len < page_size ? 1 : len / page_size;
    rte_iova_t *iovas   = malloc(sizeof(*iovas) * n_pages);
    if (iovas == NULL) {
        fprintf(stderr, "[udpdpdk] failed to allocate iovas: %s\n", strerror(errno));
        return -1;
    }
    for (uint32_t cur_page = 0; cur_page < n_pages; cur_page++) {
        size_t     offset;
        void      *cur;
        offset = page_size * cur_page;
        cur    = RTE_PTR_ADD(addr, offset);
        /* This call goes into the kernel. Avoid it on the critical path. */
        iovas[cur_page] = rte_mem_virt2iova(cur);
    }

    // Register external memory with DPDK. Note: DPDK has a max segment list limit. You may need
    // to check if you stay within that limit. Using hugepages usually helps. From then on, we will
    // use the internal DPDK page table to get IOVAs.
    int ret = rte_extmem_register(addr, len, iovas, n_pages, page_size);
    if (ret < 0) {
        fprintf(stderr, "[udpdpdk] failed to register external memory with DPDK: %s\n",
               rte_strerror(rte_errno));
        return -1;
    }

    // Register pages for DMA with the NIC.
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(port_id, &dev_info);
    for (uint32_t cur_page = 0; cur_page < n_pages; cur_page++) {
        ret = rte_dev_dma_map(dev_info.device, addr + (cur_page * page_size), iovas[cur_page],
                              page_size);
        if (ret < 0) {
            fprintf(stderr, "[udpdpdk] failed to pin memory for DMA: %s\n", rte_strerror(rte_errno));
            return -1;
        }
    }

    // Free the iova vector
    free(iovas);
    return 0;
}

static inline int unregister_memory_area(void *addr, const uint64_t len, uint32_t page_size,
                                       uint16_t port_id) {
    // De-register pages from the NIC. This must be done BEFORE de-registering from DPDK.
    int ret;
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(port_id, &dev_info);
    uint32_t    n_pages = len < page_size ? 1 : len / page_size;
    for (uint32_t cur_page = 0; cur_page < n_pages; cur_page++) {
        size_t     offset = page_size * cur_page;
        ret = rte_dev_dma_unmap(dev_info.device, addr + offset, rte_mem_virt2iova(addr + offset), page_size);
        if (ret < 0) {
            fprintf(stderr, "[udpdpdk] failed to unpin memory for DMA: %s\n", rte_strerror(rte_errno));
        }
    }

    // De-register pages from DPDK
    ret = rte_extmem_unregister(addr, len);
    if (ret < 0) {
        fprintf(stderr, "[udpdpdk] failed to unregister external memory from DPDK: %s\n",
        rte_strerror(rte_errno));
    }

    // Unpin pages in memory
    munlock(addr, len);

    return 0;
}

static struct rte_flow * 
configure_udp_rss_flow(u16 port_id, u16 queue_id, uint16_t udp_port, struct rte_flow_error *error) {
    struct rte_flow_attr         attr;
    struct rte_flow_item         pattern[4];
    struct rte_flow_item_eth     item_eth_mask = {};
    struct rte_flow_item_eth     item_eth_spec = {};
    struct rte_flow_item_ipv4    ipv4_spec;
    struct rte_flow_item_ipv4    ipv4_mask;
    struct rte_flow_item_udp     udp_spec;
    struct rte_flow_item_udp     udp_mask;
    struct rte_flow_action       action[2];
    struct rte_flow             *flow  = NULL;
    struct rte_flow_action_queue queue = {.index = queue_id};
    int                          err;

    bzero(&attr, sizeof(attr));
    bzero(pattern, sizeof(pattern));
    bzero(action, sizeof(action));

    // rule attr
    attr.ingress = 1;

    // action sequence
    action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    action[0].conf = &queue;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    // patterns
    item_eth_spec.hdr.ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4);
    item_eth_mask.hdr.ether_type = RTE_BE16(0xFFFF);
    pattern[0].type              = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[0].mask              = &item_eth_mask;
    pattern[0].spec              = &item_eth_spec;

    bzero(&ipv4_spec, sizeof(ipv4_spec));
    ipv4_spec.hdr.next_proto_id = 0x11; // UDP only
    inet_pton(AF_INET, local_ip, &ipv4_spec.hdr.dst_addr); // Local IP only
    bzero(&ipv4_mask, sizeof(ipv4_mask));
    ipv4_mask.hdr.next_proto_id = 0xff; // UDP Mask
    // ipv4_mask.hdr.dst_addr      = 0xffffffff; // This is not supported by the Intel IGC driver
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    // pattern[1].spec = &ipv4_spec;      // This is not supported by the Intel i40e driver
    // pattern[1].mask = &ipv4_mask;      // This is not supported by the Intel i40e driver
    pattern[1].last = NULL;

    bzero(&udp_spec, sizeof(udp_spec));
    udp_spec.hdr.dst_port = RTE_BE16(udp_port); // UDP port
    bzero(&udp_mask, sizeof(udp_mask));
    udp_mask.hdr.dst_port = 0xffff;
    pattern[2].type       = RTE_FLOW_ITEM_TYPE_UDP;
    pattern[2].spec       = &udp_spec;
    pattern[2].mask       = &udp_mask;
    pattern[2].last       = NULL;

    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;

    err = rte_flow_validate(port_id, &attr, pattern, action, error);
    if (!err) {
        flow = rte_flow_create(port_id, &attr, pattern, action, error);
    }

    return flow;
}

static struct rte_flow *
configure_arp_rss_flow(u16 port_id, u16 queue_id, struct rte_flow_error *error) {
    struct rte_flow_attr         attr;
    struct rte_flow_item         pattern[2];
    struct rte_flow_item_eth     item_eth_mask = {};
    struct rte_flow_item_eth     item_eth_spec = {};
    struct rte_flow_action       action[2];
    struct rte_flow             *flow  = NULL;
    struct rte_flow_action_queue queue = {.index = queue_id};
    int                          err;

    bzero(&attr, sizeof(attr));
    bzero(pattern, sizeof(pattern));
    bzero(action, sizeof(action));

    // rule attr
    attr.ingress = 1;

    // action sequence
    action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    action[0].conf = &queue;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    // patterns
    // TODO: There is a specific enum for ARP but I was not able to use it
    item_eth_spec.hdr.ether_type = RTE_BE16(RTE_ETHER_TYPE_ARP);
    item_eth_mask.hdr.ether_type = RTE_BE16(0xFFFF);

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[0].mask = &item_eth_mask;
    pattern[0].spec = &item_eth_spec;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

    err = rte_flow_validate(port_id, &attr, pattern, action, error);
    if (!err) {
        flow = rte_flow_create(port_id, &attr, pattern, action, error);
    }

    return flow;
}

/* Protocols */
static void arp_reply(arp_ipv4_t *req_data) {

    struct rte_mbuf *rte_mbuf = rte_pktmbuf_alloc(ctrl_pool);
    if (!rte_mbuf) {
        fprintf(stderr, "[udpdpdk] failed to allocate mbuf for ARP reply: %s\n", rte_strerror(rte_errno));
        return;
    }

    // 1. Ethernet Header
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(rte_mbuf, struct rte_ether_hdr *);
    memcpy(&eth_hdr->src_addr, &local_mac_addr, RTE_ETHER_ADDR_LEN);
    memcpy(&eth_hdr->dst_addr, req_data->arp_sha, RTE_ETHER_ADDR_LEN);
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHERNET_P_ARP);

    // 2. ARP Data
    arp_hdr_t  *arp_hdr = (arp_hdr_t *)(eth_hdr + 1);
    arp_ipv4_t *data    = (arp_ipv4_t *)(&arp_hdr->arp_data);
    memcpy(data->arp_tha, req_data->arp_sha, RTE_ETHER_ADDR_LEN);
    memcpy(data->arp_sha, &local_mac_addr, RTE_ETHER_ADDR_LEN);

    data->arp_tip = req_data->arp_sip;
    data->arp_sip = local_ip_net;

    arp_hdr->arp_opcode = rte_cpu_to_be_16(ARP_REPLY);
    arp_hdr->arp_htype  = rte_cpu_to_be_16(ARP_ETHERNET);
    arp_hdr->arp_hlen   = RTE_ETHER_ADDR_LEN;
    arp_hdr->arp_ptype  = rte_cpu_to_be_16(ETHERNET_P_IP);
    arp_hdr->arp_plen   = 4;

    rte_mbuf->next     = NULL;
    rte_mbuf->nb_segs  = 1;
    rte_mbuf->pkt_len  = sizeof(arp_hdr_t) + RTE_ETHER_HDR_LEN;
    rte_mbuf->data_len = rte_mbuf->pkt_len;

    // Send the request
    uint16_t ret = 0;
    while(!ret) {
        ret = rte_eth_tx_burst(port_id, 0, &rte_mbuf, 1);
    }    
}

static void arp_receive(struct rte_mbuf *arp_mbuf) {
    arp_hdr_t *ahdr = rte_pktmbuf_mtod_offset(arp_mbuf, arp_hdr_t *, RTE_ETHER_HDR_LEN);

    // Update the ARP cache
    for(int i = 0; i < n_peers; i++) {
        if (peers[i].ip_net == ahdr->arp_data.arp_sip) {
            peers[i].mac_set = true;
            memcpy(&peers[i].mac_addr, ahdr->arp_data.arp_sha, RTE_ETHER_ADDR_LEN);

            char mac_str[32];
            rte_ether_format_addr(mac_str, 32, &peers[i].mac_addr);
            fprintf(stderr, "[udpdpdk] ARP reply from %s: %s\n", peers[i].ip_str, mac_str);

            break;
        }
    }

    if (ahdr->arp_data.arp_tip != local_ip_net) {
        // not for us - do not reply
        return;
    }

    switch (rte_be_to_cpu_16(ahdr->arp_opcode)) {
    case ARP_REQUEST:
        arp_reply(&ahdr->arp_data);
        break;
    default:
        // Replies or wrong opcodes - no action
        break;
    }
}

static int32_t arp_request(uint32_t daddr) {

    // 0. Allocate an mbuf
    struct rte_mbuf *rte_mbuf = rte_pktmbuf_alloc(ctrl_pool);
    if (!rte_mbuf) {
        fprintf(stderr, "[udpdpdk] failed to allocate mbuf for ARP request: %s\n", rte_strerror(rte_errno));
        return -rte_errno;
    }

    // 1. Ethernet Header
    struct rte_ether_addr broadcast_hw = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(rte_mbuf, struct rte_ether_hdr *);
    memcpy(&eth_hdr->src_addr, &local_mac_addr, RTE_ETHER_ADDR_LEN);
    memcpy(&eth_hdr->dst_addr, &broadcast_hw, RTE_ETHER_ADDR_LEN);
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHERNET_P_ARP);

    // 2. ARP data
    arp_hdr_t  *ahdr  = (arp_hdr_t *)(eth_hdr + 1);
    arp_ipv4_t *adata = (arp_ipv4_t *)(&ahdr->arp_data);

    memcpy(adata->arp_sha, &local_mac_addr, RTE_ETHER_ADDR_LEN);
    memcpy(adata->arp_tha, &broadcast_hw, RTE_ETHER_ADDR_LEN);
    adata->arp_sip = local_ip_net;
    adata->arp_tip = daddr;

    ahdr->arp_opcode = rte_cpu_to_be_16(ARP_REQUEST);
    ahdr->arp_htype  = rte_cpu_to_be_16(ARP_ETHERNET);
    ahdr->arp_ptype  = rte_cpu_to_be_16(ETHERNET_P_IP);
    ahdr->arp_hlen   = RTE_ETHER_ADDR_LEN;
    ahdr->arp_plen   = 4;

    // 3. Append the fragment to the transmission queue of the control DP
    rte_mbuf->next    = NULL;
    rte_mbuf->nb_segs = 1;
    rte_mbuf->pkt_len = rte_mbuf->data_len = RTE_ETHER_HDR_LEN + sizeof(arp_hdr_t);
    

    fprintf(stderr, "[udpdpdk] sending ARP request\n");
    uint16_t ret = 0;
    while(!ret) {
        ret += rte_eth_tx_burst(port_id, tx_queue_id, &rte_mbuf, 1);
    }

    return 0;
}

static inline void prepare_headers(struct rte_mbuf *hdr_mbuf, size_t payload_size, uint16_t udp_port, int peer_idx) {

    /* Ethernet */
    struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(hdr_mbuf, struct rte_ether_hdr*);
    memcpy(&ehdr->src_addr, &local_mac_addr, RTE_ETHER_ADDR_LEN);
    memcpy(&ehdr->dst_addr, &peers[peer_idx].mac_addr, RTE_ETHER_ADDR_LEN);
    ehdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    /* IP */
    struct rte_ipv4_hdr *ih = (struct rte_ipv4_hdr *)(ehdr + 1);
    ih->src_addr        = local_ip_net;
    ih->dst_addr        = peers[peer_idx].ip_net;
    ih->version         = IPV4;
    ih->ihl             = 0x05;
    ih->type_of_service = 0;
    ih->total_length    = htons(payload_size + IP_HDR_LEN + UDP_HDR_LEN);
    ih->packet_id       = 0;
    ih->fragment_offset = 0;
    ih->time_to_live    = 64;
    ih->next_proto_id   = IP_UDP;
    ih->hdr_checksum    = 0;
    // Compute the IP checksum
    ih->hdr_checksum = rte_ipv4_cksum(ih);

    /* UDP */
    struct rte_udp_hdr *uh = (struct rte_udp_hdr *)(ih + 1);
    uh->dst_port           = htons(udp_port);
    uh->src_port           = htons(udp_port);
    uh->dgram_len          = htons(payload_size + UDP_HDR_LEN);
    uh->dgram_cksum        = 0;
    // Compute the UDP checksum
    uh->dgram_cksum = rte_ipv4_udptcp_cksum(ih, uh);

    // Finally, set the data_len and pkt_len: only headers! The payload size is in another mbuf
    hdr_mbuf->data_len = hdr_mbuf->pkt_len = RTE_ETHER_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
}

// Callback function: return the NSN buffer index to the free pool. Called by the DPDK PMD.
void free_extbuf_cb(void *addr, void *opaque) {
    nsn_endpoint_t *ep = (nsn_endpoint_t *)opaque;
    // Compute the index from the buf address, relative to the start of the zone
    uint64_t index = ((char*)addr - (char*)(ep->tx_zone + 1)) / ep->io_bufs_size;
    if(nsn_ringbuf_enqueue_burst(ep->free_slots, &index, sizeof(void*), 1, NULL) < 1) {
        fprintf(stderr, "[udpsock] Failed to enqueue 1 descriptor\n");
    }
}

/* Checks if an mbuf crosses page boundary */
static inline int mbuf_crosses_page_boundary(struct rte_mbuf *m, size_t pg_sz) {
    uint64_t start = (uint64_t)m->buf_addr + m->data_off;
    uint64_t end   = start + m->data_len;
    return (start / pg_sz) != ((end - 1) / pg_sz);
}

// This function is similar to the rte_pktmbuf_ext_shinfo_init_helper. However, the "original" one
// would allocate the rte_mbuf_ext_shared_info structure at the end of the external buffer. We
// can't, because the buffer is INSANE-managed memory. So this function stores the struct in the area
// the user passes as first argument. Generally, and specifically for this case, the caller will
// pass a private area of the mbuf as first argument. DO NOT PASS a NULL callback pointer: it will
// be called by DPDK causing a segfault. Just pass a function that does nothing, if you do not need
// this feature.
static inline void rte_pktmbuf_ext_shinfo_init_helper_custom(
    struct rte_mbuf_ext_shared_info *ret_shinfo, rte_mbuf_extbuf_free_callback_t free_cb,
    void *fcb_opaque) {

    struct rte_mbuf_ext_shared_info *shinfo = ret_shinfo;
    shinfo->free_cb                         = free_cb;
    shinfo->fcb_opaque                      = fcb_opaque;
    rte_mbuf_ext_refcnt_set(shinfo, 1);
    return;
}

/* API */

NSN_DATAPATH_UPDATE(udpdpdk) {
    if (endpoint == NULL) {
        fprintf(stderr, "[udpdpdk] invalid endpoint\n");
        return -1;
    }

    // Case 1. Delete endpoint data.
    if(endpoint->data) {
        struct udpdpdk_ep *conn = (struct udpdpdk_ep *)endpoint->data;
        
        // Return the pending buffer to the free slots
        nsn_ringbuf_enqueue_burst(endpoint->free_slots, &conn->pending_rx_buf, sizeof(conn->pending_rx_buf), 1, NULL);

        // Destroy the flow
        if (conn->app_flow) {
            rte_flow_destroy(port_id, conn->app_flow, NULL);
        }

        // Stop the device queue
        int res = rte_eth_dev_rx_queue_stop(port_id, conn->rx_queue_id);
        if (res < 0) {
            fprintf(stderr, "[udpdpdk] failed to stop the device queue: %s\n", rte_strerror(rte_errno));
        }

        // Destroy the tx mempools
        rte_mempool_free(conn->tx_data_pool);
        rte_mempool_free(conn->tx_hdr_pool);

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

        // Stop the rx queue
        int ret = rte_eth_dev_rx_queue_stop(port_id, conn->rx_queue_id);
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

        // get a descriptor to receive
        u32 np = nsn_ringbuf_dequeue_burst(endpoint->free_slots, &conn->pending_rx_buf, sizeof(conn->pending_rx_buf), 1, NULL);
        if (np == 0) {
            printf("[udpsock] No free slots to receive from ring %p [%u]\n", endpoint->free_slots, nsn_ringbuf_count(endpoint->free_slots));
            goto error_1;
        }

        // RX mempool: retrieve it from the endpoint (created at queue setup)
        // TODO: we will need an indirect mempool for the zero-copy receive
        char pool_name[64];
        sprintf(pool_name, "rx_pool_%u", conn->rx_queue_id);
        conn->rx_pool = rte_mempool_lookup(pool_name);
        if (conn->rx_pool == NULL) {
            fprintf(stderr, "[udpdpdk] failed to create mempool\n");
            goto error_2;
        }

        // TODO: Create the tx direct and indirect mempool, and possibly prepare the headers (at least for the local part)

        /* TX: header mempool */
        sprintf(pool_name, "tx_hdr_pool_%u", conn->rx_queue_id);
        conn->tx_hdr_pool = rte_pktmbuf_pool_create(
            pool_name, 10239, 64, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
        if (!conn->tx_hdr_pool) {
            fprintf(stderr, "[udpdpdk]: failed to create tx hdr pool: %s\n", rte_strerror(rte_errno));
            goto error_2;
        }

        /* TX: data mempool.
            This mempool contains only descriptors, not data: data_room_size is 0.
            The descriptors will point to the INSANE nbufs, containing the data.
            This is called "indirect mempool" in DPDK. As required for "indirect" mempools,
            we need to provide a stucture with additional metadata. The DPDK code suggests to
            place this area at the end of the user data, but we cannot! So we place that struct
            in the "private area" of the mbuf, i.e., memory area right after each mbuf descriptor.
        */
        size_t private_size    = sizeof(struct rte_mbuf_ext_shared_info);
        size_t data_room_size  = 0;
        sprintf(pool_name, "tx_data_pool_%u", conn->rx_queue_id);
        conn->tx_data_pool = rte_pktmbuf_pool_create(
            pool_name, 10239, 64, private_size, data_room_size, socket_id);
        if (!conn->tx_data_pool) {
            fprintf(stderr, "[udpdpdk]: failed to create tx data pool: %s\n", rte_strerror(rte_errno));
            goto error_3;
        }

        // Register the application memory with the NIC
        // See the alignment comment in the function.
        void *addr = (void*)((usize)endpoint->tx_zone & 0xFFFFFFFFFFF00000);
        usize len = align_to((endpoint->tx_zone->total_size + (((void*)endpoint->tx_zone) - addr)),
                              endpoint->page_size);
        int ret = register_memory_area(addr, len, endpoint->page_size, port_id);
        if (ret < 0) {
            fprintf(stderr, "[udpdpdk] failed to register memory area with DPDK and NIC\n");
            goto error_4;
        }

        // Now create the RSS filter on that queue for this endpoint's UDP port
        struct rte_flow_error flow_error;
        conn->app_flow = configure_udp_rss_flow(port_id, conn->rx_queue_id, endpoint->app_id, &flow_error);
        if (conn->app_flow == NULL) {
            fprintf(stderr, "[udpdpdk] failed to create flow: %s\n", flow_error.message ? flow_error.message : "unkown");
            goto error_5;
        }

        // Start the queue
        ret = rte_eth_dev_rx_queue_start(port_id, conn->rx_queue_id);
        if (ret < 0) {
            fprintf(stderr, "[udpdpdk] failed to start queue %u: %s\n", conn->rx_queue_id, strerror(ret));
            goto error_5;
        }
    
        return 0;
error_5:
        rte_flow_destroy(port_id, conn->app_flow, NULL);
        unregister_memory_area(addr, len, endpoint->page_size, port_id);
error_4:
        rte_mempool_free(conn->tx_data_pool);
error_3:
        rte_mempool_free(conn->tx_hdr_pool);
error_2:
        nsn_ringbuf_enqueue_burst(endpoint->free_slots, &conn->pending_rx_buf, sizeof(conn->pending_rx_buf), 1, NULL); 
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
    uint16_t              ether_type;
    uint16_t              queue_id = 0;
    int j;

    // Send ARP requests for "missing" peers
    // for (int i = 0; i < n_peers; i++) {
    //     if (!peers[i].mac_set) {
    //         arp_request(peers[i].ip_net);
    //     }
    // }

    // Receive ARP replies or answer incoming ARP requests
    uint16_t rx_count = rte_eth_rx_burst(port_id, 0, pkts_burst, MAX_RX_BURST_ARP);

    for (j = 0; j < rx_count; j++) {
        eth_hdr    = rte_pktmbuf_mtod(pkts_burst[j], struct rte_ether_hdr *);
        ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
        switch (ether_type) {
            case RTE_ETHER_TYPE_ARP:
                // Receive ARP and, if necessary, reply
                arp_receive(pkts_burst[j]);
                rte_pktmbuf_free(pkts_burst[j]);
                break;
            default:
                rte_pktmbuf_free(pkts_burst[j]);
                break;
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
    peers = mem_arena_push(scratch.arena, n_peers * sizeof(struct udpdpdk_peer));
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
    char* dev_name = to_cstr(dev_name_str);
    fprintf(stderr, "[udpdpdk] parameter: dev_name: %s\n", dev_name);

    // Now, finally, initialize EAL
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        fprintf(stderr, "[udpdpdk] rte_eal_init failed: %s\n", rte_strerror(rte_errno));
        goto early_fail;
    }

    // Select the desired device
    bool                    found = false;
    struct rte_eth_dev_info devinfo;
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

    // Create a mempool to receive "spare" data, i.e., data not associated to any endpoint,
    // e.g., for ARP and possibly control messages. Used also to tx control msgs.
    ctrl_pool = rte_pktmbuf_pool_create("ctrl_pool", 10239, 64, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
    if (ctrl_pool == NULL) {
        fprintf(stderr, "[udpdpdk] failed to create mempool\n");
        goto fail;
    }

    // Configure the port
    struct rte_eth_conf port_conf;
    bzero(&port_conf, sizeof(port_conf));
    // port_conf.rxmode.mtu = MTU;
    port_conf.rxmode.offloads |= (RTE_ETH_RX_OFFLOAD_CHECKSUM | RTE_ETH_RX_OFFLOAD_SCATTER);
    port_conf.txmode.mq_mode  = RTE_ETH_MQ_TX_NONE;
    port_conf.txmode.offloads |= (RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_MULTI_SEGS);
    if (devinfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
    }
    // if ((ret = rte_eth_dev_set_mtu(port_id, MTU)) != 0) {
    //     fprintf(stderr, "[udpdpdk] setting mtu failed: %s\n", rte_strerror(rte_errno));
    //     goto fail;
    // }
    uint16_t nb_rxd = 1024;
    uint16_t nb_txd = 1024;
    if ((ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd)) != 0) {
        fprintf(stderr, "[udpdpdk] error setting tx and rx descriptors: %s\n", rte_strerror(rte_errno));
        goto fail;;
    }

    // Isolate the flow - only allow traffic that is specified by the flow rules (RSS filter)
    // i.e., ARP on queue 0 and UDP to app_id port on the other queues
    struct rte_flow_error error;
    ret = rte_flow_isolate(port_id, 1, &error);
    if (ret < 0) {
        fprintf(stderr, "[udpdpdk] failed to isolate traffic: %s\n", error.message? error.message : rte_strerror(rte_errno));
        goto fail;
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

    // Configure the rx queues: queue 0 to start immediately
    if ((ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd, socket_id, NULL, ctrl_pool)) != 0) {
        fprintf(stderr, "[udpdpdk] failed configuring rx queue %u: %s\n", 0, rte_strerror(rte_errno));
        goto fail;
    }

    // The remaining queues are confgured with "deferred start"
    // NOTE: mlx5 driver does not support deferred start, so this will have no effect.
    // But other drivers might support it, so we leave it.
    struct rte_eth_rxconf rx_conf = devinfo.default_rxconf;
    rx_conf.rx_deferred_start = 1;
    char pool_name[64];
    struct rte_mempool *rx_pool;
    for (uint16_t i = 1; i < rx_queues; i++) {
        // Create a mempool for the queue (will be retrieved later by the endpoint, using name)
        // TODO: In the final version, this mempool should ideally be an external mempool,
        // where each mbuf actually points to a slot in the shared memory of this app.
        // For the moment, we just create a local mempool and copy the data on receive.
        bzero(pool_name, 64);
        sprintf(pool_name, "rx_pool_%u", i);
        if ((rx_pool = rte_pktmbuf_pool_create(pool_name, 10239, 64, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id)) == NULL) {
            fprintf(stderr, "[udpdpdk] failed to create mempool\n");
            goto fail;
        }

        // Setup the queue using that mempool
        if ((ret = rte_eth_rx_queue_setup(port_id, i, nb_rxd, socket_id, &rx_conf, rx_pool)) != 0) {
            fprintf(stderr, "[udpdpdk] failed configuring rx queue %u: %s\n", i, rte_strerror(rte_errno));
            goto fail;
        }

        // Put the queue id in the ring
        nsn_ringbuf_enqueue_burst(free_queue_ids, &i, sizeof(void*), 1, NULL);
    }

    // Start the device
    ret = -EAGAIN;
    while (ret == -EAGAIN) {
        ret = rte_eth_dev_start(port_id);
    };
    if (ret) {
        fprintf(stderr, "[udpdpdk] impossible to start device: %s\n", rte_strerror(rte_errno));
        goto fail;
    }

    // ARP packets to be received on queue 0
    rx_arp_flow = configure_arp_rss_flow(port_id, 0, &error);    
    if (rx_arp_flow == NULL) {
        fprintf(stderr, "[udpdpdk] failed to create ARP flow: %s\n", error.message? error.message : rte_strerror(rte_errno));
        goto fail_and_stop;
    }

    // Stop the queues that are not used. This is necessary because some drivers, such as mlx5,
    // do not support deferred start, and all queues are started immediately.
    for (uint16_t i = 1; i < rx_queues; i++) {
        ret = rte_eth_dev_rx_queue_stop(port_id, i);
        if (ret < 0) {
            fprintf(stderr, "[udpdpdk] failed to stop queue %u: %s\n", i, rte_strerror(rte_errno));
        }
    }

    // For each peer, send an ARP request
    for (int i = 0; i < n_peers; i++) {
        arp_request(peers[i].ip_net);
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
        rte_pktmbuf_alloc_bulk(conn->tx_hdr_pool, tx_bufs, buf_count);

        for (usize i = 0; i < buf_count; i++) {
            // Get the data and size from the index
            char* data = (char*)(endpoint->tx_zone + 1) + (bufs[i].index * endpoint->io_bufs_size); 
            usize size = ((nsn_meta_t*)(endpoint->tx_meta_zone + 1) + bufs[i].index)->len;

            // Prepare the header
            prepare_headers(tx_bufs[i], size, endpoint->app_id, p);
            
            // Prepare the data as external buffer
            data_mbuf = rte_pktmbuf_alloc(conn->tx_data_pool);
            struct rte_mbuf_ext_shared_info *ret_shinfo =
                (struct rte_mbuf_ext_shared_info *)(data_mbuf + 1);
            rte_pktmbuf_ext_shinfo_init_helper_custom(ret_shinfo, free_extbuf_cb, endpoint);

            // Set IOVA mapping
            rte_iova_t iova;
            if (rte_eal_iova_mode() == RTE_IOVA_VA) {
                iova = (rte_iova_t)data;
            } else {
                struct rte_memseg *ms = rte_mem_virt2memseg(data, rte_mem_virt2memseg_list(data));
                iova = ms->iova + (data - (char *)ms->addr);
            }

            // Attach the memory buffer to the mbuf
            rte_pktmbuf_attach_extbuf(data_mbuf, data, iova, size, ret_shinfo);
            data_mbuf->pkt_len = data_mbuf->data_len = size;

            // For external memory, we must handle the case data crosses a page boundary
            if (nsn_unlikely(mbuf_crosses_page_boundary(data_mbuf, endpoint->page_size))) {
                // 1. Get page boundary starting from last_mbuf->buf_addr (+ data_off)
                uint64_t start         = (uint64_t)data;
                uint64_t end           = start + data_mbuf->data_len;
                uint64_t page_boundary = ((start / endpoint->page_size) + 1) * endpoint->page_size;
                // 2. Compute the length of the ext_mbuf and the second mbuf
                uint64_t second_len = end - page_boundary;
                // 3. Allocate a new mbuf for the second part
                struct rte_mbuf *second_mbuf = rte_pktmbuf_alloc(conn->tx_data_pool);
                // 4. Attach the second mbuf to the external memory in the second page, with the correct IOVA.
                rte_iova_t second_iova;
                if (rte_eal_iova_mode() == RTE_IOVA_VA) {
                    rte_iova_t second_iova = page_boundary;
                } else {
                    struct rte_memseg *ms =
                        rte_mem_virt2memseg((void*)page_boundary, rte_mem_virt2memseg_list((void*)page_boundary));
                    second_iova = ms->iova + ((void *)page_boundary - ms->addr);
                }

                struct rte_mbuf_ext_shared_info *ret_shinfo =
                    (struct rte_mbuf_ext_shared_info *)(second_mbuf + 1);
                rte_pktmbuf_ext_shinfo_init_helper_custom(ret_shinfo, free_extbuf_cb, NULL);
                rte_pktmbuf_attach_extbuf(second_mbuf, (void *)page_boundary, second_iova, second_len,
                                          ret_shinfo);
                second_mbuf->data_len = second_len;
                second_mbuf->data_off = 0;

                // 6. Chain this mbuf to the last one
                data_mbuf->next = second_mbuf;
                data_mbuf->data_len -= second_len;
            }
            
            // Put headers and data packets in chain
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

NSN_DATAPATH_RX(dpdk)
{
    nsn_unused(bufs);
    nsn_unused(endpoint);

    fprintf(stderr, "[udpdpdk] Unimplemented datapath rx\n");
    return (int)*buf_count;
}

NSN_DATAPATH_DEINIT(udpdpdk)
{
    nsn_unused(ctx);

    // Stop the device (and all queues, consequently). Must be done BEFORE destroying resources 
    // (e.g., mempools etc.) => i.e., call this BEFORE the udpdpdk_datapath_update() below.
    int res = rte_eth_dev_stop(port_id);
    if (res < 0) {
        fprintf(stderr, "[udpdpdk] failed to stop device: %s\n", rte_strerror(rte_errno));
    }

    struct ep_initializer *ep_in;
    list_for_each_entry(ep_in, endpoint_list, node) {
        res = udpdpdk_datapath_update(ep_in->ep);
        if (res < 0) {
            fprintf(stderr, "[udpdpdk] failed cleanup of endpoint %d\n", ep_in->ep->app_id);
        }
    }
    
    res = rte_eal_cleanup();
    if (res < 0) {
        fprintf(stderr, "[udpdpdk] failed to cleanup EAL: %s\n", rte_strerror(rte_errno));
    }

    // Destroy the scratch memory
    nsn_thread_scratch_end(scratch);

    return 0;
}
