#define _GNU_SOURCE

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "../src/nsn_memory.c"
#include "../src/nsn_string.c"
#include "../src/nsn_log.h"
#include "../src/nsn_ringbuf.h"
#include "../src/nsn_ringbuf.c"
#include "../src/nsn_os.h"
#include "../src/nsn_os_linux.c"
#include "../datapaths/protocols.h"

#include <rte_arp.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_flow.h>
#include <rte_malloc.h>

/* This test demonstrates the possibility to have a full zero-copy receive on INSANE memory using DPDK.
 * To achieve that, four DPDK features are leveraged and must be supported by DPDK and the NIC:
 * 1) The external memory mempool;
 * 2) Alternative rte_mempool backend: use the INSANE ring instead of the DPDK ring.
 * 2) The RSS filtering on incoming packets
 * 3) The BUFFER_SPLIT offload
 *
 * Using these three mechanisms, the following communication can be enabled:
 * 1) The receiver waits for the right packets on a specific hardware queue, using an RSS
 * filter based on the UDP port. This ensures that no "weird" data is placed in INSANE memory
 * 2) The receiver uses the BUFFER_SPLIT offload to place the headers of the incoming packets in a
 * mempool, and the payload in another. The payload mempool is actually an external mempool that
 * wraps user memory, so the NIC will DMA the payload directly into the user memory (zero-copy
 * receive). That mempool will use INSANE rings ("free_slots") instead of DPDK rings. This ensures 
 * that the user will receive memory through INSANE even if it was the NIC to dequeue the mbuf.
 **/

#define PORT                             2509
#define MAX_SINGLE_FRAG_UDP_PAYLOAD_SIZE 1434

/* Protocols */
static void arp_reply(arp_ipv4_t *req_data, struct rte_mempool* pool) {

    struct rte_mbuf *rte_mbuf = rte_pktmbuf_alloc(pool);
    if (!rte_mbuf) {
        fprintf(stderr, "[udpdpdk] failed to allocate mbuf for ARP reply: %s\n", rte_strerror(rte_errno));
        return;
    }

    // Get local MAC addr
    struct rte_ether_addr local_mac_addr;
    rte_eth_macaddr_get(0, &local_mac_addr);

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
    inet_aton("192.168.56.211", (struct in_addr*)&data->arp_sip);

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
        ret = rte_eth_tx_burst(0, 0, &rte_mbuf, 1);
    }    
}

static void arp_receive(struct rte_mbuf *arp_mbuf, struct rte_mempool* pool) {
    arp_hdr_t *ahdr = rte_pktmbuf_mtod_offset(arp_mbuf, arp_hdr_t *, RTE_ETHER_HDR_LEN);

    switch (rte_be_to_cpu_16(ahdr->arp_opcode)) {
    case ARP_REQUEST:
        arp_reply(&ahdr->arp_data, pool);
        break;
    default:
        break;
    }
}

/* Configure an RSS filter to route incoming packets for the UDP port *udp_port* on the NIC queue
 * *queue_id*
 */
static struct rte_flow *set_rss_filter(uint16_t port_id, uint16_t rx_queue_id, uint16_t udp_port,
                                       struct rte_flow_error *error) {
    // Configure the RSS filter on the NIC port
    struct rte_flow_attr   attr;
    struct rte_flow_item   pattern[4];
    struct rte_flow_action action[2];
    bzero(&attr, sizeof(attr));
    bzero(pattern, sizeof(pattern));
    bzero(action, sizeof(action));

    struct rte_flow_item_eth  item_eth_mask = {};
    struct rte_flow_item_eth  item_eth_spec = {};
    struct rte_flow_item_ipv4 ipv4_spec, ipv4_mask;
    struct rte_flow_item_udp  udp_spec, udp_mask;

    struct rte_flow_action_queue queue = {.index = rx_queue_id};

    // the filter applies to ingress traffic
    attr.ingress = 1;

    // Start RSS Filter
    // filter at ETH level: accept only IPv4 packets
    item_eth_spec.hdr.ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4);
    item_eth_mask.hdr.ether_type = RTE_BE16(0xFFFF);
    pattern[0].type              = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[0].mask              = &item_eth_mask;
    pattern[0].spec              = &item_eth_spec;
    pattern[0].last              = NULL;

    // filter at IP level: accept only UDP packets
    bzero(&ipv4_spec, sizeof(ipv4_spec));
    bzero(&ipv4_mask, sizeof(ipv4_mask));
    ipv4_spec.hdr.next_proto_id = 0x11; // UDP
    ipv4_mask.hdr.next_proto_id = 0xff; // UDP Mask
    pattern[1].type             = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[1].spec             = &ipv4_spec;
    pattern[1].mask             = &ipv4_mask;
    pattern[1].last             = NULL;

    // filter at UDP level: accept only packets with destination port PORT
    bzero(&udp_spec, sizeof(udp_spec));
    bzero(&udp_mask, sizeof(udp_mask));
    udp_spec.hdr.dst_port = RTE_BE16(udp_port);
    udp_mask.hdr.dst_port = 0xffff;
    pattern[2].type       = RTE_FLOW_ITEM_TYPE_UDP;
    pattern[2].spec       = &udp_spec;
    pattern[2].mask       = &udp_mask;
    pattern[2].last       = NULL;

    // end filter
    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;

    // Action to do with the filter for queue 0
    action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    action[0].conf = &queue;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    // Validate and apply the filter
    struct rte_flow *flow;
    if (!rte_flow_validate(port_id, &attr, pattern, action, error)) {
        flow = rte_flow_create(port_id, &attr, pattern, action, error);
    }

    return flow;
}

/* Configure a NIC port for DPDK, with M tx queues and N rx queues, and configure the RSS filter to
 * receive packets for port PORT on rx queue  (i=1,...,N-1). 2 pools for each of these queue
 * (mempools array, of size N-1) are provided and the BUFFER_SPLIT option is enabled to separate the
 * header from the payload. RX queue 0 is left to handle any other incoming packet, using the
 * default_mempool without the BUFFER_SPLIT enabled.*/
static inline int port_init(uint16_t port_id, uint16_t nb_tx_queues, uint16_t nb_rx_queues,
                            struct rte_mempool *default_mempool, struct rte_mempool **mempools, size_t max_payload_size) {
    int valid_port = rte_eth_dev_is_valid_port(port_id);
    if (!valid_port)
        return -1;

    struct rte_eth_dev_info dev_info;
    int                     retval = rte_eth_dev_info_get(port_id, &dev_info);
    if (retval != 0) {
        fprintf(stderr, "[error] cannot get device (port %u) info: %s\n", 0, strerror(-retval));
        return retval;
    }

    // Check that the NIC supports all the required offloads
    if (!(dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM) ||
        !(dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MULTI_SEGS) ||
        !(dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) ||
        !(dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_CHECKSUM) ||
        !(dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_SCATTER) ||
        !(dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT))
    {
        fprintf(stderr, "[error] NIC does not support one of the required offloads\n");
        return -1;
    }

    // Specify the number of queues to be configured
    const uint16_t tx_rings = nb_tx_queues, rx_rings = nb_rx_queues;

    // Configure the device with the BUFFER_SPLIT offload option
    struct rte_eth_conf port_conf;
    memset(&port_conf, 0, sizeof(port_conf));
    port_conf.rxmode.offloads |= (RTE_ETH_RX_OFFLOAD_CHECKSUM | RTE_ETH_RX_OFFLOAD_SCATTER |
                                  RTE_ETH_RX_OFFLOAD_BUFFER_SPLIT);
    port_conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;
    port_conf.txmode.offloads |= (RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_MULTI_SEGS);
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
    retval = rte_eth_dev_configure(port_id, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    uint16_t nb_rxd = 1024;
    uint16_t nb_txd = 1024;
    retval          = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    int socket_id = rte_eth_dev_socket_id(port_id);

    // TX queue (tx_rings = nb_tx_queues)
    struct rte_eth_txconf txconf = dev_info.default_txconf;
    txconf.offloads              = port_conf.txmode.offloads;
    for (uint16_t q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port_id, q, nb_txd, socket_id, &txconf);
        if (retval != 0)
            return retval;
    }

    // RX queues (tx_rings = nb_rx_queues). The queue 0 is left for packets that do not match the
    // RSS filter that will be set on the others based on the UDP port, i.e., any other non-UDP
    // packet and any UDP packet for another port.
    retval = rte_eth_rx_queue_setup(port_id, 0, nb_rxd, socket_id, NULL, default_mempool);
    if (retval != 0) {
        return retval;
    }

    // If more than one queue, set configure the BUFFER_SPLIT offload behavior on them.
    struct rte_eth_rxconf       rx_conf        = dev_info.default_rxconf;
    uint8_t                     rx_pkt_nb_segs = 2;
    struct rte_eth_rxseg_split *rx_seg;
    for (uint16_t q = 1; q < rx_rings; q++) {
        union rte_eth_rxseg rx_useg[2] = {};

        // Segment 0 (header)
        rx_seg         = &rx_useg[0].split;
        rx_seg->mp     = mempools[2 * (q - 1)];
        rx_seg->offset = 0; // TODO: Understand how to use it. Is this correct?
        // See docs in rte_ethdev.h. Must be zero if length is used (and vice versa)
        rx_seg->proto_hdr = 0;
        // Max bytes to be placed in this segment. Must be zero if proto_hdr is used (and vice
        // versa)
        rx_seg->length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr);

        // Segment 1 (payload)
        rx_seg         = &rx_useg[1].split;
        rx_seg->offset = 0;
        rx_seg->mp     = mempools[2 * (q - 1) + 1];
        // See docs in rte_ethdev.h. Must be zero if length is used (and vice versa)
        rx_seg->proto_hdr = 0;
        // Max bytes to be placed in this segment. Must be zero if proto_hdr is used (and vice
        // versa)
        rx_seg->length = max_payload_size;

        // Configure the number of segments and the segments themselves
        rx_conf.rx_nseg     = rx_pkt_nb_segs;
        rx_conf.rx_seg      = rx_useg;
        rx_conf.rx_mempools = NULL;
        rx_conf.rx_nmempool = 0;

        printf("Setting up queue %u\n", q);
        // Configure the queue
        retval = rte_eth_rx_queue_setup(port_id, q, nb_rxd, socket_id, &rx_conf, NULL);
        if (retval != 0) {
            return retval;
        }
    }

    retval = rte_eth_dev_start(port_id);
    if (retval != 0) {
        return retval;
    }

    // Set the RSS filter on the receive queues from 1 to N. This must be done after the device is
    // started. Here we filter only on the UDP port.
    struct rte_flow_error flow_error;
    for (uint16_t q = 1; q < rx_rings; q++) {
        if (set_rss_filter(port_id, q, PORT + q, &flow_error) == NULL) {
            printf("RSS filter generation failed on port: %u for queue: %u, error: %s.\n", port_id,
                   q, flow_error.message ? flow_error.message : "unkown");
        }
    }

    retval = rte_eth_promiscuous_enable(port_id);
    if (retval != 0)
        return retval;

    return 0;
}

// Register with DPDK and with the NIC an arbitrary memory area for zero-copy send/receive
static inline int register_memory_area(void *addr, const uint64_t len, uint32_t page_size,
                                       uint16_t port_id) {
    // Pin pages in memory (necessary if we do not use hugepages)
    mlock(addr, len);

    // Prepare for the external memory registration with DPDK: compute page IOVAs
    uint32_t    n_pages = len < page_size ? 1 : len / page_size;
    rte_iova_t *iovas   = malloc(sizeof(*iovas) * n_pages);
    for (uint32_t cur_page = 0; cur_page < n_pages; cur_page++) {
        rte_iova_t iova;
        size_t     offset;
        void      *cur;
        offset = page_size * cur_page;
        cur    = RTE_PTR_ADD(addr, offset);
        /* touch the page before getting its IOVA */
        bzero((void *)cur, page_size);
        /* This call goes into the kernel. Avoid it on the critical path. */
        iova            = rte_mem_virt2iova(cur);
        iovas[cur_page] = iova;
    }
    if (iovas == NULL) {
        printf("%s():%i: Failed to compute iovas\n", __func__, __LINE__);
        return -1;
    }

    // Register external memory with DPDK. Note: DPDK has a max segment list limit. You may need
    // to check if you stay within that limit. Using hugepages usually helps. From then on, we will
    // use the internal DPDK page table to get IOVAs.
    int ret = rte_extmem_register(addr, len, iovas, n_pages, page_size);
    if (ret < 0) {
        printf("%s():%i: Failed to register external memory with DPDK: %s\n", __func__, __LINE__,
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
            printf("%s():%i: Failed to pin memory for DMA\n", __func__, __LINE__);
            return -1;
        }
    }

    // Free the iova vector
    free(iovas);

    return 0;
}


static int pagesz_flags(uint64_t page_sz) {
    /* as per mmap() manpage, all page sizes are log2 of page size
     * shifted by MAP_HUGE_SHIFT (26)
     */
    return (rte_log2_u64(page_sz) << 26);
}

static void *alloc_mem(size_t memsz, size_t pgsz, bool huge) {
    void *addr;
    int   flags;

    /* allocate anonymous hugepages */
    flags = MAP_ANONYMOUS | MAP_PRIVATE;
    if (huge) {
        flags |= MAP_HUGETLB | pagesz_flags(pgsz);
    }
    addr = mmap(NULL, memsz, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (addr == MAP_FAILED) {
        return NULL;
    }
    return addr;
}


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

/** The context to initialize the mbufs with pinned external buffers. */
struct rte_pktmbuf_extmem_init_ctx {
	const struct rte_pktmbuf_extmem *ext_mem; /* descriptor array. */
	unsigned int ext_num; /* number of descriptors in array. */
	unsigned int ext; /* loop descriptor index. */
	size_t off; /* loop buffer offset. */
};


static int
check_obj_bounds(char *obj, size_t pg_sz, size_t elt_sz)
{
	if (pg_sz == 0)
		return 0;
	if (elt_sz > pg_sz)
		return 0;
	if (RTE_PTR_ALIGN(obj, pg_sz) != RTE_PTR_ALIGN(obj + elt_sz - 1, pg_sz))
		return -1;
	return 0;
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

int main(int argc, char *argv[]) {
    int ret;

    /* Initialize DPDK */
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "error with EAL initialization\n");
    }
    printf("Eal Init OK\n");

    /* Get device (here, select the first to appear) */
    int                     err;
    uint16_t                port_id;
    struct rte_eth_dev_info devinfo;
    RTE_ETH_FOREACH_DEV(port_id) {
        err = rte_eth_dev_info_get(port_id, &devinfo);
        if (err < 0) {
            printf("Cannot get information of port_id:%d, error:%s. skipping...\n", port_id,
                   rte_strerror(rte_errno));
            continue;
        }
        printf("Selecting device with port_id: %d\n", port_id);
        break;
    }

    // Now, the behavior and the configuration differ for the cases of the sender and the
    // receiver

    /* RX/0: Allocate a mempool for the generic receive */
    struct rte_mempool *rx_mempool = rte_pktmbuf_pool_create(
        "rx_mbuf_pool", 10240, 64, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (rx_mempool == NULL) {
        printf("RTE_ERROR: %s\n", rte_strerror(rte_errno));
        rte_exit(EXIT_FAILURE, "cannot create the rx mbuf pool\n");
    }
    printf("RX-0 mempool creation OK\n");

    /* RX/1: Allocate a (direct) mempool for the headers of packets on queue 1 */
    struct rte_mempool *hdr_mempool = rte_pktmbuf_pool_create(
        "header_mempool", 10240, 64, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (hdr_mempool == NULL) {
        printf("RTE_ERROR: %s\n", rte_strerror(rte_errno));
        rte_exit(EXIT_FAILURE, "cannot create the direct mbuf pool\n");
    }
    printf("RX-1 hdr_mempool creation OK\n");

    // Allocate regular memory, using hugepages for performance.
    uint64_t data_buffer_len  = 2147483648;
    uint64_t buf_size         = 1500;
    uint32_t num_bufs         = 1024;
    uint32_t page_size        = RTE_PGSIZE_2M;
    char    *data_buffer_orig = (char *)alloc_mem(data_buffer_len, page_size, true);
    if (data_buffer_orig == NULL) {
        printf("%s():%i: Failed to create data memory area\n", __func__, __LINE__);
        perror("Error is: ");
        return -1;
    }   

    // Register the memory area with DPDK and with the NIC for zero-copy receive
    ret = register_memory_area(data_buffer_orig, data_buffer_len, page_size, port_id);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Failed to register memory area\n");
    }


    // Use the memory in this way: first buf_size * 1024 bytes are for the DATA;
    // Then, aligned, the next 1024 * 8 bytes + ring headers are for the INSANE ring.
    char* memory_slots = data_buffer_orig;
    char* memory_ring  = memory_slots + (buf_size * 1024);

    printf("Memory area for data starting at %p\n", memory_slots);

    // Create INSANE rings on that memory
    nsn_ringbuf_t *free_slots = nsn_ringbuf_create(memory_ring, str_lit("rxring"), num_bufs);
    if (!free_slots) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return -1;
    }

    // Now fill in the ring with the slots
    for (uint64_t i = 0; i < num_bufs; i++) {
        nsn_ringbuf_enqueue_burst(free_slots, &i, sizeof(void*), 1, NULL);
    }

    /* RX/1: Allocate an (indirect) mempool for the payload of packets on queue 1. Create
     * the mempool on the external memory and pre-populate it with mbufs. This is necessary
     * because the the DRIVER will allocate mbufs on it, and it obviously does not know our
     * extmem. Creating a pool with this function, in particular, pre-populates the mbufs
     * with pointers to the right area or our memory, and sets the flag
     * RTE_PKTMBUF_POOL_F_PINNED_EXT_BUF which prevents this association to be removed on
     * packet free. To work properly, this function needs a description of the external
     * memory via the rte_pktmbuf_extmem structure. WARNING: This assumes a continguous area
     * in physical memory. If this is not the case (very likely, especially if we do not use
     * hugepages), we need a different descriptor for each memory page, in order to properly
     * set the IOVA mapping. In any case, it does NOT allow memory buffers that cross page
     * boundaries. This might create holes... A way to overcome this would be to create a
     * custom function based on the default one that inserts cross-page mbufs and returns a
     * chain of two in case of page crossing? Or something similar, in a way that is
     * transparent to the driver. An equivalent of what we do in LF-DPDK for the
     * sender-side. Here, not necessary for the moment.*/
    uint32_t n_pages = data_buffer_len < page_size ? 1 : data_buffer_len / page_size;
    struct rte_pktmbuf_extmem *extmem_pages =
        malloc(sizeof(struct rte_pktmbuf_extmem) * n_pages);
    for (uint32_t i = 0; i < n_pages; i++) {
        void *ptr                = data_buffer_orig + i * page_size;
        extmem_pages[i].buf_ptr  = ptr;
        struct rte_memseg *ms    = rte_mem_virt2memseg(ptr, rte_mem_virt2memseg_list(ptr));
        extmem_pages[i].buf_iova = ms->iova + ((char *)ptr - (char *)ms->addr);
        extmem_pages[i].buf_len  = page_size;
        extmem_pages[i].elt_size = buf_size;
    }
    size_t              private_size   = sizeof(void*); // The nsn index. TODO: We probably need to add free_cb struct here! Add it later!
    uint32_t            cache_size     = 0; // TODO: How does it work with the NSN backend?
    size_t              data_room_size = 0;
    struct rte_mempool *payload_mempool =
        nsn_dpdk_pktmbuf_pool_create_extmem("payload_mempool", num_bufs, cache_size, private_size,
                                       data_room_size, rte_eth_dev_socket_id(port_id), extmem_pages, n_pages, free_slots);
    if (payload_mempool == NULL) {
        rte_exit(EXIT_FAILURE, "cannot create the payload_mempool\n");
    }
    free(extmem_pages);

    // This is the HACK that makes the external memory work. The external mempool must be
    // created with 0 data room size. But then the driver(s) use the data room size of the mbufs
    // to know the size of the mbufs. So, afer the creation, we set the data room size of the
    // mbufs to the maximum size of the payload. Apparently this works withouth visible side
    // effects. TODO: Is there a proper way to do this?
    struct rte_pktmbuf_pool_private *mbp_priv =
        (struct rte_pktmbuf_pool_private *)rte_mempool_get_priv(payload_mempool);
    mbp_priv->mbuf_data_room_size = buf_size;

    printf("RX-1 payload_mempool creation OK\n");

    // Finally we can init the port
    struct rte_mempool *pools[2] = {hdr_mempool, payload_mempool};
    ret                          = port_init(port_id, 1, 2, rx_mempool, pools, buf_size);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "error with port initialization\n");
    }
    printf("Port creation OK\n");

    fprintf(stderr, "\nCore %u receiving packets. [Ctrl+C to quit]\n", rte_lcore_id());

    uint16_t              nb_rx      = 0;
    uint16_t              burst_size = 8;
    struct rte_mbuf      *pkts_burst[burst_size];
    struct rte_ether_hdr *eth_hdr;
    uint16_t              ether_type;

    /* Start receive loop */
    for (;;) {
        for (uint16_t q = 0; q < 2; q++) {
            
            // Receive
            nb_rx = rte_eth_rx_burst(port_id, q, pkts_burst, burst_size);
            
            // Queue 0: handle ARP; 
            for (int j = 0; q == 0 && j < nb_rx; j++) {
                eth_hdr    = rte_pktmbuf_mtod(pkts_burst[j], struct rte_ether_hdr *);
                ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
                switch (ether_type) {
                    case RTE_ETHER_TYPE_ARP:
                        // Receive ARP and, if necessary, reply
                        fprintf(stderr, "[queue 0] Reply to ARP request...\n");
                        arp_receive(pkts_burst[j], rx_mempool);
                        break;
                    default:
                        break;
                }
            }
            // Queue 0: free packets
            if (q == 0) {
                rte_pktmbuf_free_bulk(pkts_burst, nb_rx);
            }

            // Queue 1: handle data
            for (int j = 0; q == 1 && j < nb_rx; j++) {
                printf("[queue 1] Received packet on port %u on queue %u with %u segs, total len %u\n",
                       port_id, q, pkts_burst[j]->nb_segs, pkts_burst[j]->pkt_len);
                struct rte_mbuf *cur = pkts_burst[j];
                for (int k = 0; k < pkts_burst[j]->nb_segs; k++) {
                    printf(" - seg %d len %u from mempool %s\n", k + 1, cur->data_len,
                           cur->pool->name);
                    cur = cur->next;
                }
                
                usize index = *(size_t*)(pkts_burst[j]->next + 1);
                // Re-enqueue the payload mbuf index in the ring
                printf("Re-enqueueing index %lu\n", index);
                nsn_ringbuf_enqueue_burst(free_slots, &index, sizeof(void*), 1, NULL);
                // Free the packets with CUSTOM free (which does NOT re-enqueue the external mbuf)
                nsn_pktmbuf_free(pkts_burst[j]);
            }
        }
    }
}

// OPS for mempool handers
static int nsn_mp_alloc(struct rte_mempool *mp) {
    
    // Here is the trick: instead of CREATING the ring here, we pass an existing ring!
    // Actually, to enable that, we expect the user to already set the mp->pool to a ring.
    // And so here we just verify it exists!
    if(mp->pool_data == NULL) {
        fprintf(stderr, "INSANE MP HANDLER: mempool %s has no ring attached\n", mp->name);
        return -EINVAL;
    }
    nsn_ringbuf_t *ring = (nsn_ringbuf_t *)mp->pool_data;
    fprintf(stderr, "mempool %s backed by ring %s at %p\n", mp->name, ring->name, ring);

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
    size_t index;
    for (unsigned i = 0; i < n; i++) {
        // 1. Get the index of the element
        index = *(size_t*)((struct rte_mbuf *)obj_table[i] + 1);
        printf("Enqueueing mbuf %p with index %lu\n", obj_table[i], index);
        // 2. Enqueue the element index in the ring
        nsn_ringbuf_enqueue_burst((nsn_ringbuf_t *)mp->pool_data, &index, sizeof(void*), n, NULL);
    }
    return n;
}

static int nsn_mp_dequeue(struct rte_mempool *mp, void **obj_table, unsigned n) {
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



