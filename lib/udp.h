#ifndef INSANE_UDP_H
#define INSANE_UDP_H

#include "common.h"
#include "ethernet.h"
#include "ip.h"
#include "runtime.h"

#define UDP_HEADER_LEN sizeof(udp_hdr_t)

//--------------------------------------------------------------------------------------------------
// UDP Header
//--------------------------------------------------------------------------------------------------
typedef struct udp_hdr {
    u16 udp_sport;
    u16 udp_dport;
    u16 udp_len;
    u16 udp_csum;
} udp_hdr_t;

//--------------------------------------------------------------------------------------------------

u8 *udp_receive(nsn_runtime_t *nsnrt, u8 *pkt_data);

i32 udp_send(nsn_runtime_t *nsnrt, u8 *pkt_data, nsn_pktmeta_t *meta);

//--------------------------------------------------------------------------------------------------

static inline udp_hdr_t *udp_hdr(const u8 *pkt_data) {
    return (udp_hdr_t *)(pkt_data + ETHERNET_HEADER_LEN + IP_HEADER_LEN);
}

#endif // INSANE_UDP_H