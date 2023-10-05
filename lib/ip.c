#include "ip.h"

#include "common.h"
#include "route.h"
#include "udp.h"

//--------------------------------------------------------------------------------------------------
static void ip_init_packet(ip_hdr_t *ih) {
    ih->src_addr = ntohl(ih->src_addr);
    ih->dst_addr = ntohl(ih->dst_addr);
    ih->len      = ntohs(ih->len);
    ih->id       = ntohs(ih->id);
}

//--------------------------------------------------------------------------------------------------
static u16 ip_checksum(ip_hdr_t *ih, size_t len) {
    const void *buf = ih;
    uint32_t    sum = 0;

    /* extend strict-aliasing rules */
    typedef uint16_t __attribute__((__may_alias__)) u16_p;
    const u16_p *u16_buf = (const u16_p *)buf;
    const u16_p *end     = u16_buf + len / sizeof(*u16_buf);

    for (; u16_buf != end; ++u16_buf)
        sum += *u16_buf;

    /* if length is odd, keeping it byte order independent */
    if (nsn_likely(len % 2)) {
        uint16_t left           = 0;
        *(unsigned char *)&left = *(const unsigned char *)end;
        sum += left;
    }

    sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);
    sum = ((sum & 0xffff0000) >> 16) + (sum & 0xffff);

    uint16_t cksum = (uint16_t)sum;

    return (uint16_t)~cksum;
}

//--------------------------------------------------------------------------------------------------
u8 *ip_receive(nsn_runtime_t *nsnrt, u8 *pkt_data) {
    ip_hdr_t *ih = ip_hdr(pkt_data);

    if (ih->version != IPV4) {
        LOG_ERROR("Datagram version was not IPv4 (0x%02x)", ih->version);
        goto exit;
    }

    if (ih->ihl < 5) {
        LOG_ERROR("IPv4 header length must be at least 5");
        goto exit;
    }

    if (ih->ttl == 0) {
        /**
         * TODO(garbu): Send ICMP error
         */
        LOG_ERROR("Received IPv4 packet with expired TTL");
        goto exit;
    }

    if (ip_checksum(ih, ih->ihl * 4) != 0) {
        LOG_TRACE("Dropping IP packet with wrong checksum");
        goto exit;
    }

    /**
     * TODO(garbu): Check fragmentation, possibly reassemble
     */

    ip_init_packet(ih);

    IP_DEBUG("in", ih);

    // NOTE(lr): If you add support for a packet, remember to remove the
    // free_buf if the memory will be managed by the application
    switch (ih->proto) {
    case ICMPV4:
        // icmpv4_incoming(ns, pkt_data);
        LOG_WARN("Received ICMP packet. ICMP not supported yet!");
        // TODO(garbu)L handle this in a specific queue.
        break;

    case IP_UDP:
        return udp_receive(nsnrt, pkt_data);

    case IP_TCP:
        // tcp_in(pkt_data);
        LOG_WARN("Received TCP packet. TCP not supported yet!");
        break;

    default:
        LOG_WARN("Unknown IP header proto");
        break;
    }

exit:
    return NULL;
}

//--------------------------------------------------------------------------------------------------
u8 *ip_output(nsn_runtime_t *nsnrt, u8 *pkt_data, nsn_pktmeta_t *meta, u32 *src_addr,
              u32 *dst_addr) {
    eth_hdr_t *eh  = (eth_hdr_t *)pkt_data;
    eh->ether_type = htons(ETHERNET_P_IP);

    // route_entry_t *rtentry = route_lookup(dst_addr);
    // if !(rtentry) {
    //     return -1;
    // }

    memcpy(eh->dst_mac, nsnrt->dst_dev->hw_addr, nsnrt->dst_dev->addr_len);
    memcpy(eh->src_mac, nsnrt->dev->hw_addr, nsnrt->dev->addr_len);

    ETHERNET_DEBUG("out", eh);

    ip_hdr_t *ih = (ip_hdr_t *)(((u8 *)eh) + ETHERNET_HEADER_LEN);

    // FIXME(garbu): choose correct representation for addresses.
    *src_addr = ntohl(nsnrt->dev->addr);
    *dst_addr = ntohl(nsnrt->dst_dev->addr);

    ih->version     = IPV4;
    ih->ihl         = 0x05;
    ih->tos         = 0;
    ih->len         = IP_HEADER_LEN + UDP_HEADER_LEN + meta->payload_len;
    ih->id          = ih->id;
    ih->frag_offset = 0x0000;
    ih->ttl         = 64;
    ih->proto       = IP_UDP;
    ih->src_addr    = *src_addr;
    ih->dst_addr    = *dst_addr;
    ih->csum        = 0x0000;

    IP_DEBUG("out", ih);

    ih->len         = htons(ih->len);
    ih->id          = htons(ih->id);
    ih->dst_addr    = htonl(ih->dst_addr);
    ih->src_addr    = htonl(ih->src_addr);
    ih->frag_offset = htons(ih->frag_offset);
    ih->csum        = ip_checksum(ih, ih->ihl * 4);

    return ((u8 *)ih) + IP_HEADER_LEN;
}