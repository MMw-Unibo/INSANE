#ifndef INSANE_ETHERNET_H
#define INSANE_ETHERNET_H

#include "common.h"
#include "insane/logger.h"

#define ETHERNET_ADDRESS_LEN 6
#define ETHERNET_HEADER_LEN  14

#define ETHERNET_P_LOOP  0x0060 /* Ethernet Loopback packet	    */
#define ETHERNET_P_TSN   0x22F0 /* TSN (IEEE 1722) packet	    */
#define ETHERNET_P_IP    0x0800 /* Internet Protocol packet	    */
#define ETHERNET_P_ARP   0x0806 /* Address Resolution packet	*/
#define ETHERNET_P_8021Q 0x8100 /* 802.1Q VLAN Extended Header  */
#define ETHERNET_P_IPV6  0x86DD /* IPv6 over bluebook		    */

#define ETHERNET_ADDRESS_PRT_FMT "%02X:%02X:%02X:%02X:%02X:%02X"

#define ETHERNET_ADDRESS_BYTES(mac_addrs)                                                          \
    (mac_addrs)[0], (mac_addrs)[1], (mac_addrs)[2], (mac_addrs)[3], (mac_addrs)[4], (mac_addrs)[5]

#ifdef DEBUG_ETH
#define ETHERNET_DEBUG(msg, ehdr)                                                                  \
    do {                                                                                           \
        LOG_DEBUG("eth " msg " ("                                                                  \
                  "dst_mac: " ETHERNET_ADDRESS_PRT_FMT ", "                                        \
                  "src_mac: " ETHERNET_ADDRESS_PRT_FMT ", "                                        \
                  "ether_type: %.4hx",                                                             \
                  ETHERNET_ADDRESS_BYTES(ehdr->dst_mac), ETHERNET_ADDRESS_BYTES(ehdr->src_mac),    \
                  (ehdr)->ether_type);                                                             \
    } while (0)
#else
#define ETHERNET_DEBUG(msg, ehdr)
#endif

//--------------------------------------------------------------------------------------------------
// Ethernet Header
//--------------------------------------------------------------------------------------------------
typedef struct eth_hdr {
    uint8_t  dst_mac[ETHERNET_ADDRESS_LEN];
    uint8_t  src_mac[ETHERNET_ADDRESS_LEN];
    uint16_t ether_type;
} __nsn_packed eth_hdr_t;

#endif // INSANE_ETHERNET_H
