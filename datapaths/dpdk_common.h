#ifndef DPDK_COMMON_H
#define DPDK_COMMON_H

#include <strings.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_flow.h>
#include <rte_malloc.h>

#include "../src/nsn_datapath.h"
#include "../src/base/nsn_thread_ctx.h"
#include "../src/base/nsn_string.c"
#include "../src/base/nsn_memory.c"

#include "../src/common/nsn_temp.h"
#include "../src/common/nsn_config.c"
#include "../src/common/nsn_ringbuf.c"

// --------------------------------------------------------------------------------------------
// Memory configuration
// Register with DPDK and with the NIC an arbitrary memory area for zero-copy send/receive
// WARNING: "addr" and "len" MUST be aligned to the "page size"
int register_memory_area(void *addr, const uint64_t len, uint32_t page_size,
                                       uint16_t port_id) {
    // Pin pages in memory (necessary if we do not use hugepages)
    mlock(addr, len);

    fprintf(stderr, "[udpdpdk] registering memory area %p, len %lu, page_size %u, port_id %u\n", addr, len, page_size, port_id);

    // Prepare for the external memory registration with DPDK: compute page IOVAs
    uint32_t    n_pages = len < page_size ? 1 : len / page_size;
    rte_iova_t *iovas   = (rte_iova_t*)malloc(sizeof(*iovas) * n_pages);
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

int unregister_memory_area(void *addr, const uint64_t len, uint32_t page_size,
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

// --------------------------------------------------------------------------------------------
// RSS Flow Configuration
struct rte_flow * 
configure_udp_rss_flow(u16 port_id, u16 queue_id, 
                       char* local_ip_str, uint16_t udp_port, 
                       struct rte_flow_error *error) 
{
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
    inet_pton(AF_INET, local_ip_str, &ipv4_spec.hdr.dst_addr); // Local IP only
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

struct rte_flow *
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

// --------------------------------------------------------------------------------------------
// The context to initialize the mbufs with pinned external buffers.
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

#endif // DPDK_COMMON_H