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
#include <rte_malloc.h>

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
#define MAX_RX_BURST          64    // Must be at least 32

// Per-endpoint state
struct udpdpdk_ep {
    u16 rx_queue_id;
    struct rte_mempool *rx_hdr_pool;
    struct rte_mempool *rx_data_pool;
    struct rte_mempool *tx_hdr_pool;
    struct rte_mempool *tx_data_pool;
    struct rte_flow *app_flow;
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
static u16    nb_rxd;
static u16    nb_txd;
static struct rte_eth_dev_info devinfo;
static nsn_ringbuf_t *free_queue_ids;
struct rte_mempool *ctrl_pool;
static temp_mem_arena_t scratch;
static struct rte_flow *rx_arp_flow;
static bool dev_stopped = true;

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
        ret = rte_eth_tx_burst(port_id, tx_queue_id, &rte_mbuf, 1);
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
        fprintf(stderr, "[udpdpdk] ARP reply not for us\n");
        return;
    }

    switch (rte_be_to_cpu_16(ahdr->arp_opcode)) {
    case ARP_REQUEST:
        fprintf(stderr, "[udpdpdk] Reply to ARP request...\n");
        arp_reply(&ahdr->arp_data);
        break;
    default:
        fprintf(stderr, "[udpdpdk] ARP reply, or opcode not supported\n");
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
    // uh->dgram_cksum = rte_ipv4_udptcp_cksum(ih, uh);

    // Finally, set the data_len and pkt_len: only headers! The payload size is in another mbuf
    hdr_mbuf->data_len = hdr_mbuf->pkt_len = RTE_ETHER_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;
}

/** The context to initialize the mbufs with pinned external buffers. */
struct rte_pktmbuf_extmem_init_ctx {
	const struct rte_pktmbuf_extmem *ext_mem; /* descriptor array. */
	unsigned int ext_num; /* number of descriptors in array. */
	unsigned int ext; /* loop descriptor index. */
	size_t off; /* loop buffer offset. */
};

/**
 * Custom free: free the mbufs, but do NOT re-enqueue EXTERNAL mbufs
 * in the backend (i.e., here, the INSANE ring). It will be the APP
 * to do the re-enqueue, when more convenient. Regular mbufs are freed
 * by the standard DPDK function.
 */
static inline void nsn_pktmbuf_free(struct rte_mbuf *m)
{
	struct rte_mbuf *m_next, *n;

	if (m != NULL)
		__rte_mbuf_sanity_check(m, 1);

	while (m != NULL) {
		m_next = m->next;
        n = rte_pktmbuf_prefree_seg(m);
	    if (likely(n != NULL) && !RTE_MBUF_HAS_PINNED_EXTBUF(n)) {
		    rte_mbuf_raw_free(n);
        }
		m = m_next;
	}
}

/**
 * Get a mbuf from an INSANE-backed mempool, with the specific index passed as param.
 * This call will bypass the call to the DEQUEUE OPS, because we already have the index,
 * which was obtained by the application.
 */
static inline struct rte_mbuf *nsn_pktmbuf_alloc(struct rte_mempool *mp, size_t index)
{
    struct rte_mbuf** table = (struct rte_mbuf**)mp->pool_config;
    struct rte_mbuf *m = table[index];
    if (m != NULL) {
        rte_pktmbuf_reset(m);
    }
	return m;
}

/*
 * The callback routine called when reference counter in shinfo
 * for mbufs with pinned external buffer reaches zero. It means there is
 * no more reference to buffer backing mbuf and this one should be freed.
 * This routine is called for the regular (not with pinned external or
 * indirect buffer) mbufs on detaching from the mbuf with pinned external
 * buffer.
 */
static void
rte_pktmbuf_free_pinned_extmem(void *addr, void *opaque)
{
	struct rte_mbuf *m = opaque;

	RTE_SET_USED(addr);
	RTE_ASSERT(RTE_MBUF_HAS_EXTBUF(m));
	RTE_ASSERT(RTE_MBUF_HAS_PINNED_EXTBUF(m));
	RTE_ASSERT(m->shinfo->fcb_opaque == m);

	rte_mbuf_ext_refcnt_set(m->shinfo, 1);
	m->ol_flags = RTE_MBUF_F_EXTERNAL;
	if (m->next != NULL)
		m->next = NULL;
	if (m->nb_segs != 1)
		m->nb_segs = 1;

	rte_mbuf_raw_free(m);
}

/* Helper, modified starting from __rte_pktmbuf_init_extmem. It associates a DPDK mbuf
   with a chunck of external memory, in this case the NSN memory.
 */
static void nsn_pktmbuf_init_extmem(struct rte_mempool *mp,
			  void *opaque_arg,
			  void *_m,
			  __rte_unused unsigned int i)
{
	struct rte_mbuf *m = _m;
	struct rte_pktmbuf_extmem_init_ctx *ctx = opaque_arg;
	const struct rte_pktmbuf_extmem *ext_mem;
	uint32_t mbuf_size, buf_len, priv_size;
	struct rte_mbuf_ext_shared_info *shinfo;

	priv_size = rte_pktmbuf_priv_size(mp);
	mbuf_size = sizeof(struct rte_mbuf) + priv_size;
	buf_len = rte_pktmbuf_data_room_size(mp);

	RTE_ASSERT(RTE_ALIGN(priv_size, RTE_MBUF_PRIV_ALIGN) == priv_size);
	RTE_ASSERT(mp->elt_size >= mbuf_size);
	RTE_ASSERT(buf_len <= UINT16_MAX);

    // DO NOT zero the mbuf! We are using the priv_mem to hold the buf index!
	//memset(m, 0, mbuf_size);
	m->priv_size = priv_size;
	m->buf_len = (uint16_t)buf_len;

	/* set the data buffer pointers to external memory */
	ext_mem = ctx->ext_mem + ctx->ext;

	RTE_ASSERT(ctx->ext < ctx->ext_num);
	RTE_ASSERT(ctx->off + ext_mem->elt_size <= ext_mem->buf_len);

	m->buf_addr = RTE_PTR_ADD(ext_mem->buf_ptr, ctx->off);
	rte_mbuf_iova_set(m, ext_mem->buf_iova == RTE_BAD_IOVA ? RTE_BAD_IOVA :
								 (ext_mem->buf_iova + ctx->off));

    // usize index = *(usize*)(m + 1);
    // printf("MBUF %lu points to %p\n", index, m->buf_addr);

	ctx->off += ext_mem->elt_size;
	if (ctx->off + ext_mem->elt_size > ext_mem->buf_len) {
		ctx->off = 0;
		++ctx->ext;
	}
	/* keep some headroom between start of buffer and data */
	m->data_off = RTE_MIN(RTE_PKTMBUF_HEADROOM, (uint16_t)m->buf_len);

	/* init some constant fields */
	m->pool = mp;
	m->nb_segs = 1;
	m->port = RTE_MBUF_PORT_INVALID;
	m->ol_flags = RTE_MBUF_F_EXTERNAL;
	rte_mbuf_refcnt_set(m, 1);
	m->next = NULL;

	/* init external buffer shared info items */
	shinfo = RTE_PTR_ADD(m, mbuf_size);
	m->shinfo = shinfo;
	shinfo->free_cb = rte_pktmbuf_free_pinned_extmem;
	shinfo->fcb_opaque = m;
	rte_mbuf_ext_refcnt_set(shinfo, 1);
}

/* Helper, modified starting from rte_pktmbuf_pool_create_extbuf */
static struct rte_mempool* nsn_dpdk_pktmbuf_pool_create_extmem(const char *name, unsigned int n,
	unsigned int cache_size, uint16_t priv_size,
	uint16_t data_room_size, int socket_id,
	const struct rte_pktmbuf_extmem *ext_mem,
	unsigned int ext_num,
    nsn_ringbuf_t *free_slots)
{
	struct rte_mempool *mp;
	struct rte_pktmbuf_pool_private mbp_priv;
	struct rte_pktmbuf_extmem_init_ctx init_ctx;
	unsigned int elt_size;
	unsigned int i, n_elts = 0;
	int ret;

	if (RTE_ALIGN(priv_size, RTE_MBUF_PRIV_ALIGN) != priv_size) {
		RTE_LOG(ERR, MBUF, "mbuf priv_size=%u is not aligned\n",
			priv_size);
		rte_errno = EINVAL;
		return NULL;
	}
	/* Check the external memory descriptors. */
	for (i = 0; i < ext_num; i++) {
		const struct rte_pktmbuf_extmem *extm = ext_mem + i;

		if (!extm->elt_size || !extm->buf_len || !extm->buf_ptr) {
			RTE_LOG(ERR, MBUF, "invalid extmem descriptor\n");
			rte_errno = EINVAL;
			return NULL;
		}
		if (data_room_size > extm->elt_size) {
			RTE_LOG(ERR, MBUF, "ext elt_size=%u is too small\n",
				priv_size);
			rte_errno = EINVAL;
			return NULL;
		}
		n_elts += extm->buf_len / extm->elt_size;
	}
	/* Check whether enough external memory provided. */
	if (n_elts < n) {
		RTE_LOG(ERR, MBUF, "not enough extmem\n");
		rte_errno = ENOMEM;
		return NULL;
	}
	elt_size = sizeof(struct rte_mbuf) +
		   (unsigned int)priv_size +
		   sizeof(struct rte_mbuf_ext_shared_info);

	memset(&mbp_priv, 0, sizeof(mbp_priv));
	mbp_priv.mbuf_data_room_size = data_room_size;
	mbp_priv.mbuf_priv_size = priv_size;
	mbp_priv.flags = RTE_PKTMBUF_POOL_F_PINNED_EXT_BUF;

	mp = rte_mempool_create_empty(name, n, elt_size, cache_size,
		 sizeof(struct rte_pktmbuf_pool_private), socket_id, 0);
	if (mp == NULL)
		return NULL;

    /* Set our custom INSANE-based OPS to back the mempool */
	ret = rte_mempool_set_ops_byname(mp, "nsn_mp_ops", NULL);
	if (ret != 0) {
		RTE_LOG(ERR, MBUF, "error setting mempool handler\n");
		rte_mempool_free(mp);
		rte_errno = -ret;
		return NULL;
	}
	rte_pktmbuf_pool_init(mp, &mbp_priv);

    /* Set the INSANE ring as the backing ring */
    mp->pool_data = free_slots;

    /* This calls the POPULATE op, allocating mbufs */
	ret = rte_mempool_populate_default(mp);
	if (ret < 0) {
		rte_mempool_free(mp);
		rte_errno = -ret;
		return NULL;
	}

    /* Associate the mbufs with the external buffers */
	init_ctx = (struct rte_pktmbuf_extmem_init_ctx){
		.ext_mem = ext_mem,
		.ext_num = ext_num,
		.ext = 0,
		.off = 0,
	};
	rte_mempool_obj_iter(mp, nsn_pktmbuf_init_extmem, &init_ctx);

	return mp;
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

        // Register the application memory with the NIC
        // See the alignment comment in the function.
        void *addr = (void*)((usize)endpoint->tx_zone & 0xFFFFFFFFFFF00000);
        usize len = align_to((endpoint->tx_zone->total_size + (((void*)endpoint->tx_zone) - addr)),
                              endpoint->page_size);
        int ret = register_memory_area(addr, len, endpoint->page_size, port_id);
        if (ret < 0) {
            fprintf(stderr, "[udpdpdk] failed to register memory area with DPDK and NIC\n");
            goto error_1;
        }
        
        // RX: header mempool. Must have 10239 as num_mbufs or it fails
        char pool_name[64];
        bzero(pool_name, 64);
        sprintf(pool_name, "rx_hdr_pool_%u", conn->rx_queue_id);
        if ((conn->rx_hdr_pool = rte_pktmbuf_pool_create(pool_name, 10239, 64, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id)) == NULL) {
            fprintf(stderr, "[udpdpdk] failed to create mempool %s\n", pool_name);
            goto error_2;
        }

        // RX: data mempool with external memory configuration
        /* External memory configuration
            This mempool contains only descriptors, not data: data_room_size is 0.
            The descriptors will point to the INSANE nbufs, containing the data.
            This is called "indirect mempool" in DPDK.
            This mempool is actually a "special" mempool backed by the INSANE ring.

            In INSANE, the data area is not aligned to the page size, so the first page must 
            be registered with a smaller size than the page size. The rest of the pages will be
            registered with the full page size. "addr" points to the beginning of the page,
            and "data_ptr" points to the beginning of the data area on that page.
        */
        bzero(pool_name, 64);
        sprintf(pool_name, "rx_data_pool_%u", conn->rx_queue_id);
        uint32_t spare_page = (endpoint->tx_zone->size % endpoint->page_size == 0)? 0 : 1;
        uint32_t n_pages = endpoint->tx_zone->size < endpoint->page_size ? spare_page : (endpoint->tx_zone->size / endpoint->page_size) + spare_page;
        char *data_ptr = (char*)(endpoint->tx_zone + 1);
        // fprintf(stderr, "Memory for data starts at %p [npages = %u, size = %lu]\n", data_ptr, n_pages, endpoint->tx_zone->size);
        struct rte_pktmbuf_extmem *extmem_pages =
            malloc(sizeof(struct rte_pktmbuf_extmem) * n_pages);
        for (uint32_t i = 0; i < n_pages; i++) {
            void *ptr                = (i==0)? 
                                            data_ptr : 
                                            addr + i * endpoint->page_size;
            extmem_pages[i].buf_ptr  = ptr; 
            struct rte_memseg *ms    = rte_mem_virt2memseg(ptr, rte_mem_virt2memseg_list(ptr));
            extmem_pages[i].buf_iova = ms->iova + ((char *)ptr - (char *)ms->addr);
            extmem_pages[i].buf_len  = (i==0)? 
                                            endpoint->page_size - (data_ptr - (char*)addr) : 
                                            endpoint->page_size;
            extmem_pages[i].elt_size = endpoint->io_bufs_size;
        }
        size_t private_size    = sizeof(size_t);
        size_t data_room_size  = 0;
        conn->rx_data_pool = nsn_dpdk_pktmbuf_pool_create_extmem(
            pool_name, endpoint->io_bufs_count, 0, private_size, data_room_size, socket_id, extmem_pages, n_pages, endpoint->free_slots);
        if (!conn->rx_data_pool) {
            fprintf(stderr, "[udpdpdk]: failed to create tx data pool: %s\n", rte_strerror(rte_errno));
            goto error_3;
        }  
        // This is the HACK that makes the external memory work. The external mempool must be
        // created with 0 data room size. But then the driver(s) use the data room size of the mbufs
        // to know the size of the mbufs. So, afer the creation, we set the data room size of the
        // mbufs to the maximum size of the payload. Apparently this works withouth visible side
        // effects. TODO: Is there a proper way to do this?
        struct rte_pktmbuf_pool_private *mbp_priv =
            (struct rte_pktmbuf_pool_private *)rte_mempool_get_priv(conn->rx_data_pool);
        mbp_priv->mbuf_data_room_size = endpoint->io_bufs_size;

        /* Configure RX split: headers and payloads in their respective mempools */
        struct rte_eth_rxconf rx_conf = devinfo.default_rxconf;
        // Configure the BUFFER_SPLIT offload behavior for the selected RX queue.
        uint8_t rx_pkt_nb_segs = 2;
        struct rte_eth_rxseg_split *rx_seg;
        union rte_eth_rxseg rx_useg[2] = {};
        // Segment 0 (header)
        rx_seg         = &rx_useg[0].split;
        rx_seg->mp     = conn->rx_hdr_pool;
        rx_seg->offset = 0;
        // See docs in rte_ethdev.h. Must be zero if length is used (and vice versa)
        rx_seg->proto_hdr = 0;
        // Max bytes to be placed in this segment. Must be zero if proto_hdr is used (and vice versa)
        rx_seg->length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr);
        // Segment 1 (payload)
        rx_seg         = &rx_useg[1].split;
        rx_seg->offset = 0;
        rx_seg->mp     = conn->rx_data_pool;
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
            goto error_4;
        }

        // Start the queue
        ret = rte_eth_dev_rx_queue_start(port_id, conn->rx_queue_id);
        if (ret < 0) {
            fprintf(stderr, "[udpdpdk] failed to start queue %u: %s\n", conn->rx_queue_id, strerror(ret));
            goto error_4;
        }

        // Now create the RSS filter on that queue for this endpoint's UDP port.
        // Do this immediately after the queue is started
        struct rte_flow_error flow_error;
        conn->app_flow = configure_udp_rss_flow(port_id, conn->rx_queue_id, endpoint->app_id, &flow_error);
        if (conn->app_flow == NULL) {
            fprintf(stderr, "[udpdpdk] failed to create flow: %s\n", flow_error.message ? flow_error.message : "unkown");
            goto error_5;
        }

        /* TX: header mempool */
        sprintf(pool_name, "tx_hdr_pool_%u", conn->rx_queue_id);
        conn->tx_hdr_pool = rte_pktmbuf_pool_create(
            pool_name, 10239, 64, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
        if (!conn->tx_hdr_pool) {
            fprintf(stderr, "[udpdpdk]: failed to create tx hdr pool: %s\n", rte_strerror(rte_errno));
            goto error_6;
        }

        /* TX: data mempool. External memory, use the same config as before */
        private_size    = sizeof(size_t);
        data_room_size  = 0;
        sprintf(pool_name, "tx_data_pool_%u", conn->rx_queue_id);
        conn->tx_data_pool = nsn_dpdk_pktmbuf_pool_create_extmem(
            pool_name, endpoint->io_bufs_count, 0, private_size, data_room_size, socket_id, extmem_pages, n_pages, endpoint->free_slots);
        if (!conn->tx_data_pool) {
            fprintf(stderr, "[udpdpdk]: failed to create tx data pool: %s\n", rte_strerror(rte_errno));
            goto error_7;
        }      
        mbp_priv =
            (struct rte_pktmbuf_pool_private *)rte_mempool_get_priv(conn->tx_data_pool);
        mbp_priv->mbuf_data_room_size = endpoint->io_bufs_size;

        return 0;
error_7:
        rte_mempool_free(conn->tx_hdr_pool);
error_6:
        rte_flow_destroy(port_id, conn->app_flow, NULL);
error_5:
        rte_eth_dev_rx_queue_stop(port_id, conn->rx_queue_id);
error_4:
        rte_mempool_free(conn->rx_data_pool);
error_3:
        rte_mempool_free(conn->rx_hdr_pool);
error_2:
        unregister_memory_area(addr, len, endpoint->page_size, port_id);
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
    if (!(devinfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) ||
        !(devinfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS) ||
        !(devinfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) ||
        !(devinfo.rx_offload_capa & RTE_ETH_RX_OFFLOAD_CHECKSUM) ||
        !(devinfo.rx_offload_capa & RTE_ETH_RX_OFFLOAD_SCATTER) ||
        !(devinfo.rx_offload_capa & RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT))
    {
        fprintf(stderr, "[error] NIC does not support one of the required offloads\n");
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

    // Configure the port
    struct rte_eth_conf port_conf;
    bzero(&port_conf, sizeof(port_conf));
    // port_conf.rxmode.mtu = MTU;
    port_conf.rxmode.offloads |= (RTE_ETH_RX_OFFLOAD_CHECKSUM | RTE_ETH_RX_OFFLOAD_SCATTER
                                  | RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT);
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

    // Create a mempool to receive "spare" data, i.e., data not associated to any endpoint,
    // e.g., for ARP and possibly control messages. Used also to tx control msgs.
    ctrl_pool = rte_pktmbuf_pool_create("ctrl_pool", 10239, 64, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
    if (ctrl_pool == NULL) {
        fprintf(stderr, "[udpdpdk] failed to create mempool ctrl_pool\n");
        goto fail;
    }

    // Configure the rx queue 0 (control traffic) to start immediately
    // The remaining queues are confgured later, when applications start
    struct rte_eth_rxconf rx_conf = devinfo.default_rxconf;
    rx_conf.share_group = 0;
    if ((ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd, socket_id, &rx_conf, ctrl_pool)) != 0) {
        fprintf(stderr, "[udpdpdk] failed configuring rx queue %u: %s\n", 0, rte_strerror(rte_errno));
        goto fail;
    }

    // Prepare the descriptors for the data queues (q > 0)
    for(int i = 1; i < rx_queues; i++) {
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
    } else {
        dev_stopped = false;
    }

    // ARP packets to be received on queue 0
    rx_arp_flow = configure_arp_rss_flow(port_id, 0, &error);    
    if (rx_arp_flow == NULL) {
        fprintf(stderr, "[udpdpdk] failed to create ARP flow: %s\n", error.message? error.message : rte_strerror(rte_errno));
        goto fail_and_stop;
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
            
            // Prepare the payload - get the corresponding mbuf from the pool
            data_mbuf = nsn_pktmbuf_alloc(conn->tx_data_pool, bufs[i].index);
            data_mbuf->data_len = size;
           
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

// TODO: The current implementation is not zero-copy. Here we make a copy.
// We are currently studying how to make it zero-copy:
//  a) We will instruct the device to receive the payload on external memory...
//  b) ... so here we can free the header mbuf but not the whole mbuf.
NSN_DATAPATH_RX(udpdpdk)
{
    struct udpdpdk_ep *conn = (struct udpdpdk_ep *)endpoint->data;
    struct rte_mbuf *rx_bufs[MAX_RX_BURST];
    assert(*buf_count <= MAX_RX_BURST);

    // Receive the packets
    uint16_t nb_rx = rte_eth_rx_burst(port_id, conn->rx_queue_id, rx_bufs, *buf_count);

    // Deliver only UDP packet payloads
    usize valid = 0;
    for(uint16_t i = 0; i < nb_rx; i++) {
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

        if(mbuf->nb_segs != 2) {
            fprintf(stderr, "[udpdpdk] received packet with %u segments, expected 2\n", mbuf->nb_segs);
            rte_pktmbuf_free(mbuf);
            continue;
        }

        // Set the index (zero-copy receive)
        bufs[valid].index = *(usize*)(mbuf->next + 1);

        // Set the size
        usize *size = &((nsn_meta_t*)(endpoint->tx_meta_zone + 1) + bufs[valid].index)->len;
        *size = rte_be_to_cpu_16(uh->dgram_len) - sizeof(struct rte_udp_hdr);
        
        // Finalize the rx
        *buf_count  = *buf_count - 1;
        valid++;

        // Release the mbuf with custom free: DO NOT RE-ENQUEUE the index (the app will do that)
        nsn_pktmbuf_free(mbuf);
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
        fprintf(stderr, "[udpdpdk] failed to stop device: %s\n", rte_strerror(rte_errno));
    }
    dev_stopped = true;

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

/////////////////////////////////////////////////////////////////////////////////////////////////
// MEMPOOL HANDLERS and helper functions

static int check_obj_bounds(char *obj, size_t pg_sz, size_t elt_sz)
{
	if (pg_sz == 0)
		return 0;
	if (elt_sz > pg_sz)
		return 0;
	if (RTE_PTR_ALIGN(obj, pg_sz) != RTE_PTR_ALIGN(obj + elt_sz - 1, pg_sz))
		return -1;
	return 0;
}

// OPS for mempool handers
static int nsn_mp_alloc(struct rte_mempool *mp) {
    
    // Here is the trick: instead of CREATING the ring here, we pass an existing ring!
    // Actually, to enable that, we expect the user to already set the mp->pool to a ring.
    // And so here we just verify it exists!
    if(mp->pool_data == NULL) {
        // fprintf(stderr, "[udpdpdk] Mempool %s has no ring attached: deferring init...\n", mp->name);
    } else {
        nsn_ringbuf_t *ring = (nsn_ringbuf_t *)mp->pool_data;
        fprintf(stderr, "[udpdpdk] mempool %s backed by ring %s at %p\n", mp->name, ring->name, ring);
    }

    // Create the array to keep the mbufs
    mp->pool_config = rte_zmalloc_socket(mp->name, sizeof(struct rte_mbuf *) * mp->size, 0, mp->socket_id);
    return 0;
}

static void nsn_mp_free(struct rte_mempool *mp) {
    // Free the array of mbufs  
    rte_free(mp->pool_config);

    return;
} 

static int nsn_mp_enqueue(struct rte_mempool *mp, void * const *obj_table, unsigned n) {
    if (!mp->pool_data ) {
        // fprintf(stderr, "[udpdpdk] Mempool %s has no ring attached: cannot enqueue yet\n", mp->name);
        return 0;
    }
    size_t index;
    for (unsigned i = 0; i < n; i++) {
        // 1. Get the index of the element
        index = *(size_t*)((struct rte_mbuf *)obj_table[i] + 1);
        // printf("Enqueueing mbuf %p with index %lu\n", obj_table[i], index);
        // 2. Enqueue the element index in the ring
        nsn_ringbuf_enqueue_burst((nsn_ringbuf_t *)mp->pool_data, &index, sizeof(void*), n, NULL);
    }
    return n;
}

static int nsn_mp_dequeue(struct rte_mempool *mp, void **obj_table, unsigned n) {
    if (!mp->pool_data) {
        // fprintf(stderr, "[udpdpdk] Mempool %s has no ring attached: cannot dequeue yet\n", mp->name);
        return 0;
    }
    size_t index;
    unsigned i;
    struct rte_mbuf **mbuf_table = (struct rte_mbuf **)mp->pool_config;
    for (i = 0; i < n; i++) {
        // 1. Dequeue the index of the element
        if (nsn_ringbuf_dequeue_burst((nsn_ringbuf_t *)mp->pool_data, &index, sizeof(void*), 1, NULL) == 0) {
            break;
        }
        // 2. Get the element at that index
        obj_table[i] = mbuf_table[index];
        // printf("(%u) Dequeueing index %lu\n", i, index);
    }
    
    return i;
}

static unsigned
nsn_mp_get_count(const struct rte_mempool *mp)
{
    if (!mp->pool_data ) {
        fprintf(stderr, "[udpdpdk] Mempool %s has no ring attached: cannot use it yet\n", mp->name);
        return 0;
    }
	return nsn_ringbuf_count((nsn_ringbuf_t *)mp->pool_data);
}

// Copied from rte_mempool_op_populate_helper, with the exception that I put those
// objects in the array of mbufs, instead of in the ring.
static int nsn_mp_populate(struct rte_mempool *mp, unsigned int max_objs,
	      void *vaddr, rte_iova_t iova, size_t len,
	      rte_mempool_populate_obj_cb_t *obj_cb, void *obj_cb_arg) {
    
    char *va = vaddr;
	size_t total_elt_sz, pg_sz;
	size_t off;
	unsigned int i;
	void *obj;
	int ret;
    int flags = 0;

	ret = rte_mempool_get_page_size(mp, &pg_sz);
	if (ret < 0) {
		return ret;
    }
	total_elt_sz = mp->header_size + mp->elt_size + mp->trailer_size;

	if (flags & RTE_MEMPOOL_POPULATE_F_ALIGN_OBJ) {
		off = total_elt_sz - (((uintptr_t)(va - 1) % total_elt_sz) + 1);
    } else {
		off = 0;
    }

    // Find the first free slot in the ring
    uint64_t index = 0;
    nsn_ringbuf_t **mbuf_table = (nsn_ringbuf_t **)mp->pool_config;
    for (uint32_t j = 0; j < mp->size; j++) {
        if (!mbuf_table[j]) {
            index = j;
            break;
        }
    }
    if (index >= mp->size) {
        fprintf(stderr, "Required index %lu exceeds mempool %s's capacity\n", index, mp->name);
        return -EINVAL;
    }

	for (i = 0; i < max_objs; i++) {
		/* avoid objects to cross page boundaries */
		if (check_obj_bounds(va + off, pg_sz, total_elt_sz) < 0) {
			off += RTE_PTR_ALIGN_CEIL(va + off, pg_sz) - (va + off);
			if (flags & RTE_MEMPOOL_POPULATE_F_ALIGN_OBJ)
				off += total_elt_sz -
					(((uintptr_t)(va + off - 1) %
						total_elt_sz) + 1);
		}

		if (off + total_elt_sz > len) {
			break;
        }

		off += mp->header_size;
		obj = va + off;
		obj_cb(mp, obj_cb_arg, obj,
		       (iova == RTE_BAD_IOVA) ? RTE_BAD_IOVA : (iova + off));

        // Place the object in the array, and set the object's right index in priv_mem
        mbuf_table[index] = obj;
        *(size_t*)((struct rte_mbuf *)obj + 1) = index;
        ++index;
		
        off += mp->elt_size + mp->trailer_size;
	}

	return i;
}


// We can now set the OPS for the mempool. AFAIK, this has effect only on the mempools
// created with the "rte_pktmbuf_pool_create_extbuf" function and should not affect the
// "regular" mempools.
// This is achieved by adding a new mempool ops code, and using the RTE_MEMPOOL_REGISTER_OPS macro.
static const struct rte_mempool_ops nsn_mp_ops = {
	.name      = "nsn_mp_ops",
	.alloc     = nsn_mp_alloc,
	.free      = nsn_mp_free,
	.enqueue   = nsn_mp_enqueue,
	.dequeue   = nsn_mp_dequeue,
	.get_count = nsn_mp_get_count,
	.populate  = nsn_mp_populate,
};

RTE_MEMPOOL_REGISTER_OPS(nsn_mp_ops);
