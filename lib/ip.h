#ifndef INSANE_IP_H
#define INSANE_IP_H

#include <arpa/inet.h>

#include "common.h"
#include "ethernet.h"
#include "list.h"
#include "runtime.h"

#define ICMPV4 1
#define IPV4   4
#define IP_TCP 6
#define IP_UDP 17

#define IP_HEADER_LEN sizeof(struct ip_hdr)
#define ip_len(ip)    (ip->len - (ip->ihl * 4))

#ifdef DEBUG_IP
#define IP_DEBUG(msg, hdr)                                                                         \
    do {                                                                                           \
        LOG_DEBUG("ip " msg " (ihl: %hhu, version: %hhu, tos: %huu, "                              \
                  "len: %hu, id: %hu, frag_offset: %hu, ttl: %hhu, "                               \
                  "proto: %hhu, csum: %hx, "                                                       \
                  "src_addr: %hhu.%hhu.%hhu.%hhu, "                                                \
                  "dst_addr: %hhu.%hhu.%hhu.%hhu) ",                                               \
                  (hdr)->ihl, (hdr)->version, (hdr)->tos, (hdr)->len, (hdr)->id,                   \
                  (hdr)->frag_offset, (hdr)->ttl, (hdr)->proto, (hdr)->csum,                       \
                  (hdr)->src_addr >> 24, (hdr)->src_addr >> 16, (hdr)->src_addr >> 8,              \
                  (hdr)->src_addr >> 0, (hdr)->dst_addr >> 24, (hdr)->dst_addr >> 16,              \
                  (hdr)->dst_addr >> 8, (hdr)->dst_addr >> 0);                                     \
    } while (0)
#else
#define IP_DEBUG(msg, hdr)
#endif

//--------------------------------------------------------------------------------------------------
// IP HEADER
//--------------------------------------------------------------------------------------------------
typedef struct ip_hdr {
    /* TODO(garbu): Should we support BIG ENDIAN? */
    // u8  version:4;
    // u8  ihl:4;

    u8  ihl : 4; /* Intenet Header Length    */
    u8  version : 4;
    u8  tos; /* Type of service          */
    u16 len;
    u16 id;
    u16 frag_offset;
    u8  ttl;
    u8  proto;
    u16 csum;
    u32 src_addr;
    u32 dst_addr;
    u8  data[];
} __nsn_packed ip_hdr_t;

//--------------------------------------------------------------------------------------------------
u8 *ip_receive(nsn_runtime_t *nsnrt, u8 *pkt_data);

u8 *ip_output(nsn_runtime_t *nsnrt, u8 *pkt_data, nsn_pktmeta_t *meta, u32 *src_addr,
              u32 *dst_addr);

//--------------------------------------------------------------------------------------------------
static inline ip_hdr_t *ip_hdr(const u8 *pkt_data) {
    return (ip_hdr_t *)(pkt_data + ETHERNET_HEADER_LEN);
}

//--------------------------------------------------------------------------------------------------
static inline i32 ip_parse(char *addr, u32 *dst) {
    if (inet_pton(AF_INET, addr, dst) != 1)
        return -1;

    return 0;
}

#endif // INSANE_IP_H
