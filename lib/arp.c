#include "arp.h"

#include <arpa/inet.h>

#include "mem_manager.h"

#include "insane/buffer.h"

static NSN_LIST_HEAD(s_arp_cache);

static u8 broadcast_hw[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

//--------------------------------------------------------------------------------------------------
u8 *arp_get_hwaddr(u32 saddr) {
    list_head_t       *item;
    arp_cache_entry_t *entry;

    list_for_each(item, &s_arp_cache) {
        entry = list_entry(item, arp_cache_entry_t, list);
        if (entry->state == ARP_RESOLVED && entry->sip == saddr) {
            u8 *copy = entry->src_mac;

            return copy;
        }
    }

    return NULL;
}

//--------------------------------------------------------------------------------------------------
static i32 _arp_update_translation_table(arp_hdr_t *hdr) {
    list_head_t       *item;
    arp_cache_entry_t *entry;

    list_for_each(item, &s_arp_cache) {
        entry = list_entry(item, arp_cache_entry_t, list);

        if (entry->hwtype == hdr->arp_htype && entry->sip == hdr->arp_data.arp_sip) {
            memcpy(entry->src_mac, hdr->arp_data.arp_sha, ETHERNET_ADDRESS_LEN);

            return ARP_TRASL_TABLE_UPDATE_OK;
        }
    }

    return ARP_TRASL_TABLE_UPDATE_NO_ENTRY;
}

//--------------------------------------------------------------------------------------------------
static arp_cache_entry_t *__arp_cache_entry__alloc(arp_hdr_t *hdr) {
    arp_cache_entry_t *entry = (arp_cache_entry_t *)malloc(sizeof(arp_cache_entry_t));

    entry->state  = ARP_RESOLVED;
    entry->hwtype = hdr->arp_htype;
    entry->sip    = hdr->arp_data.arp_sip;
    memcpy(entry->src_mac, hdr->arp_data.arp_sha, ETHERNET_ADDRESS_LEN);

    list__init(&entry->list);
    return entry;
}

//--------------------------------------------------------------------------------------------------
static i32 _arp_insert_translation_table(arp_hdr_t *hdr) {
    arp_cache_entry_t *entry = __arp_cache_entry__alloc(hdr);

    list__add_tail(&entry->list, &s_arp_cache);

    return ARP_TRASL_TABLE_INSERT_OK;
}

//--------------------------------------------------------------------------------------------------
static void _do_arp_reply(nsn_runtime_t *nsn, arp_ipv4_t *req_data) {
    nsn_buffer_t buf = mem_manager__acquire(&nsn->mem_manager, mempool_dpdk);

    struct rte_mbuf *rte_mbuf = nsn->mem_manager.dpdk_ctx->tx_mbuf[buf.index];
    nsn_pktmeta_t   *meta     = &nsn->mem_manager.tx_info[mempool_dpdk].tx_meta[buf.index];

    u8 *pkt_data = rte_pktmbuf_mtod(rte_mbuf, u8 *);

    eth_hdr_t *eth_hdr = (eth_hdr_t *)pkt_data;
    memcpy(eth_hdr->src_mac, nsn->dev->hw_addr, ETHERNET_ADDRESS_LEN);
    memcpy(eth_hdr->dst_mac, req_data->arp_sha, ETHERNET_ADDRESS_LEN);

    eth_hdr->ether_type = (uint16_t)htons(ETHERNET_P_ARP);

    LOG_TRACE("ether_type: %i", eth_hdr->ether_type);

    ETHERNET_DEBUG("arp reply eth", eth_hdr);

    arp_hdr_t  *arp_hdr = (arp_hdr_t *)(pkt_data + ETHERNET_HEADER_LEN);
    arp_ipv4_t *data    = (arp_ipv4_t *)(&arp_hdr->arp_data);

    memcpy(data->arp_tha, req_data->arp_sha, ETHERNET_ADDRESS_LEN);
    memcpy(data->arp_sha, nsn->dev->hw_addr, ETHERNET_ADDRESS_LEN);

    data->arp_tip = req_data->arp_sip;
    data->arp_sip = nsn->dev->addr;

    arp_hdr->arp_opcode = htons(ARP_REPLY);
    arp_hdr->arp_htype  = htons(ARP_ETHERNET);
    arp_hdr->arp_hlen   = ETHERNET_ADDRESS_LEN;
    arp_hdr->arp_ptype  = htons(ETHERNET_P_IP);
    arp_hdr->arp_plen   = 4;

    rte_mbuf->next     = NULL;
    rte_mbuf->nb_segs  = 1;
    rte_mbuf->pkt_len  = sizeof(arp_hdr_t) + ETHERNET_HEADER_LEN;
    rte_mbuf->data_len = rte_mbuf->pkt_len;

    ARP_DEBUG("rep", arp_hdr);

    ARPDATA_DEBUG("rep", data);

    meta->proto = nsn_proto_arp;

    mem_manager__submit(&nsn->mem_manager, &buf, mempool_dpdk);
}

//--------------------------------------------------------------------------------------------------
void arp_receive(nsn_runtime_t *nsn, u8 *pkt_data) {
    arp_hdr_t *ahdr = (arp_hdr_t *)(pkt_data + ETHERNET_HEADER_LEN);

    if (nsn->dev->addr != ahdr->arp_data.arp_tip) {
        LOG_DEBUG("ARP: was not for us - %d is not %d", nsn->dev->addr, ahdr->arp_data.arp_tip);
        return;
    }

    i32 merge = _arp_update_translation_table(ahdr);
    if (merge == ARP_TRASL_TABLE_UPDATE_NO_ENTRY &&
        _arp_insert_translation_table(ahdr) == ARP_TRASL_TABLE_INSERT_FAILED)
    {
        LOG_ERROR("No free space in ARP translation table");
        return;
    }

    u16 opcode = ntohs(ahdr->arp_opcode);
    switch (opcode) {
    case ARP_REQUEST:
        _do_arp_reply(nsn, &ahdr->arp_data);
        break;
    case ARP_REPLY:
        LOG_INFO("unknown ARP_REPLY");

        // TODO(garbu): maybe move this in a better place.
        break;
    default:
        LOG_WARN("ARP: Opcode not supported: %04x!", opcode);
        break;
    }

    if (nsn->dst_dev->addr == ahdr->arp_data.arp_sip) {
        LOG_INFO("dst_dev ARP_REPLY");
        memcpy(nsn->dst_dev->hw_addr, ahdr->arp_data.arp_sha, ETHERNET_ADDRESS_LEN);
    }
}

//--------------------------------------------------------------------------------------------------
i32 arp_request(nsn_runtime_t *nsnrt, u32 saddr, u32 daddr) {
    LOG_INFO("ARP Request");
    netdev_t *dev = nsnrt->dev;

    nsn_buffer_t buf = mem_manager__acquire(&nsnrt->mem_manager, mempool_dpdk);

    struct rte_mbuf *rte_mbuf = nsnrt->mem_manager.dpdk_ctx->tx_mbuf[buf.index];
    nsn_pktmeta_t   *meta     = &nsnrt->mem_manager.tx_info[mempool_dpdk].tx_meta[buf.index];

    u8 *pkt_data = rte_pktmbuf_mtod(rte_mbuf, uint8_t *);

    eth_hdr_t *eth_hdr = (eth_hdr_t *)pkt_data;
    memcpy(eth_hdr->src_mac, nsnrt->dev->hw_addr, ETHERNET_ADDRESS_LEN);
    memcpy(eth_hdr->dst_mac, broadcast_hw, ETHERNET_ADDRESS_LEN);

    eth_hdr->ether_type = (uint16_t)htons(ETHERNET_P_ARP);

    arp_hdr_t  *ahdr  = (arp_hdr_t *)(pkt_data + ETHERNET_HEADER_LEN);
    arp_ipv4_t *adata = (arp_ipv4_t *)(&ahdr->arp_data);

    memcpy(adata->arp_sha, dev->hw_addr, dev->addr_len);
    memcpy(adata->arp_tha, broadcast_hw, dev->addr_len);
    adata->arp_sip = saddr;
    adata->arp_tip = daddr;

    ahdr->arp_opcode = htons(ARP_REQUEST);
    ahdr->arp_htype  = htons(ARP_ETHERNET);
    ahdr->arp_ptype  = htons(ETHERNET_P_IP);
    ahdr->arp_hlen   = dev->addr_len;
    ahdr->arp_plen   = 4;

    meta->proto = nsn_proto_arp;

    mem_manager__submit(&nsnrt->mem_manager, &buf, mempool_dpdk);

    return 0;
}
