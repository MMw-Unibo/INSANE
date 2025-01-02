#ifndef PROTOCOLS_H
#define PROTOCOLS_H

#include <rte_ether.h>

#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* Size of headers */
#define IP_HDR_LEN    sizeof(struct rte_ipv4_hdr)
#define UDP_HDR_LEN   sizeof(struct rte_udp_hdr)

/* Ethernet */
#define ETHERNET_P_IP    0x0800 /* Internet Protocol packet	    */
#define ETHERNET_P_ARP   0x0806 /* Address Resolution packet	*/

#define ETHERNET_ADDRESS_PRT_FMT "%02X:%02X:%02X:%02X:%02X:%02X"
#define ETHERNET_BROADCAST_ADDR   {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
#define ETHERNET_ADDRESS_BYTES(mac_addrs)                                                          \
    (mac_addrs)[0], (mac_addrs)[1], (mac_addrs)[2], (mac_addrs)[3], (mac_addrs)[4], (mac_addrs)[5]

/* ARP */
#define ARP_REQUEST    0x0001
#define ARP_REPLY      0x0002
#define ARP_HEADER_LEN sizeof(struct arp_hdr)
#define ARP_ETHERNET   0x0001
#define ARP_IPV4       0x0800
#define ARP_CACHE_LEN  32
#define ARP_FREE       0
#define ARP_WAITING    1
#define ARP_RESOLVED   2

typedef struct arp_ipv4 {
    uint8_t  arp_sha[RTE_ETHER_ADDR_LEN];
    uint32_t arp_sip;
    uint8_t  arp_tha[RTE_ETHER_ADDR_LEN];
    uint32_t arp_tip;
} __attribute__((packed)) arp_ipv4_t;

typedef struct arp_hdr {
    uint16_t arp_htype;
    uint16_t arp_ptype;
    uint8_t  arp_hlen;
    uint8_t  arp_plen;
    uint16_t arp_opcode;

    arp_ipv4_t arp_data;
} __attribute__((packed)) arp_hdr_t;

/* IPv4 */
#define ICMPV4     1
#define IPV4       4
#define IP_TCP     6
#define IP_UDP     17
#define ip_len(ip) (ip->len - (ip->ihl * 4))

/* UDP */
#define MAX_UDP_PAYLOAD_SIZE 1434

#endif // PROTOCOLS_H
