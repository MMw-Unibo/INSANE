#include "udp.h"

#include "insane_priv.h"
#include "ip.h"
#include "queue.h"

#include "insane/logger.h"

#include <rte_ip.h>

//--------------------------------------------------------------------------------------------------
inline static u16 udp_v4_csum(u32 saddr, u32 daddr, u16 len, u8 *data) {
    u32 sum = 0;

    size_t length = len;
    while (len > 1) {
        sum += *data++;
        if (sum & 0x80000000)
            sum += (sum & 0xFFFF) + (sum >> 16);

        len -= 2;
    }

    if (len > 0)
        sum += ((*data) & htons(0xFF00));
    // if (len & 1)
    //     sum += *((u8*)data);

    sum += (saddr >> 16) & 0xFFFF;
    sum += (saddr)&0xFFFF;

    sum += (daddr >> 16) & 0xFFFF;
    sum += (daddr)&0xFFFF;

    sum += htons(IP_UDP);
    sum += htons(length);

    // pad the bytes and add

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum > 16);

    return ~sum;
}

//--------------------------------------------------------------------------------------------------
u8 *udp_receive(nsn_runtime_t *nsnrt, u8 *pkt_data) {
    udp_hdr_t *uh = udp_hdr(pkt_data);

    // TODO(lr) All the boring controls etc

    u16 destport = ntohs(uh->udp_dport);
    LOG_INFO("UDP message received for port %d", destport);
    if (destport != nsnrt->daemon_udp_port)
        return NULL;

    return ((u8 *)uh + UDP_HEADER_LEN);
}

//--------------------------------------------------------------------------------------------------
i32 udp_send(nsn_runtime_t *nsnrt, u8 *pkt_data, nsn_pktmeta_t *meta) {
    u32 src_addr, dst_addr;

    ip_hdr_t  *ih = ip_hdr(pkt_data);
    udp_hdr_t *uh = (udp_hdr_t *)ip_output(nsnrt, pkt_data, meta, &src_addr, &dst_addr);

    uh->udp_dport = htons(nsnrt->daemon_udp_port);
    uh->udp_sport = htons(nsnrt->daemon_udp_port);
    uh->udp_len   = htons(UDP_HEADER_LEN + meta->payload_len);
    uh->udp_csum  = 0;

    uh->udp_csum = rte_ipv4_udptcp_cksum((struct rte_ipv4_hdr *)ih, (void *)uh);

    return 0;
}
