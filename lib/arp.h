#ifndef INSANE_ARP_H
#define INSANE_ARP_H

#include "common.h"
#include "ethernet.h"
#include "list.h"
#include "runtime.h"

#define ARP_REQUEST 0x0001
#define ARP_REPLY   0x0002

//--------------------------------------------------------------------------------------------------
// ARP Header
//--------------------------------------------------------------------------------------------------
#define ARP_HEADER_LEN sizeof(struct arp_hdr)

#define ARP_ETHERNET 0x0001
#define ARP_IPV4     0x0800

#define ARP_CACHE_LEN 32
#define ARP_FREE      0
#define ARP_WAITING   1
#define ARP_RESOLVED  2

#ifdef DEBUG_ARP
#define ARP_DEBUG(msg, hdr)                                                                        \
    do {                                                                                           \
        LOG_DEBUG("arp " msg " (hwtype: %hu, protype: %.4hx, hwsize: %d, "                         \
                  "prosize: %d, opcode: %.4hx)",                                                   \
                  (hdr)->arp_htype, (hdr)->arp_ptype, (hdr)->arp_hlen, (hdr)->arp_plen,            \
                  (hdr)->arp_opcode);                                                              \
    } while (0)

#define ARPDATA_DEBUG(msg, data)                                                                   \
    do {                                                                                           \
        LOG_DEBUG("arp data " msg " (src_mac: " ETHERNET_ADDRESS_PRT_FMT ", "                      \
                  "sip: %hhu.%hhu.%hhu.%hhu, dst_mac: " ETHERNET_ADDRESS_PRT_FMT ", "              \
                  "dip: %hhu.%hhu.%hhu.%hhu, ",                                                    \
                  (data)->arp_sha[0], (data)->arp_sha[1], (data)->arp_sha[2], (data)->arp_sha[3],  \
                  (data)->arp_sha[4], (data)->arp_sha[5], (data)->arp_sip >> 24,                   \
                  (data)->arp_sip >> 16, (data)->arp_sip >> 8, (data)->arp_sip,                    \
                  (data)->arp_tha[0], (data)->arp_tha[1], (data)->arp_tha[2], (data)->arp_tha[3],  \
                  (data)->arp_tha[4], (data)->arp_tha[5], (data)->arp_tip >> 24,                   \
                  (data)->arp_tip >> 16, (data)->arp_tip >> 8, (data)->arp_tip);                   \
    } while (0)

/* #define ARPCACHE_DEBUG(msg, entry)                                             \
 *     do {                                                                       \
 *         LOG_DEBUG("arp cache " msg " (hwtype: %hu, sip: %hhu.%hhu.%hhu.%hhu, " \
 *                   "src_mac: %02x:%02x:%02x:%02x:%02x:%02x, ",                  \
 *                   (entry)->hwtype,                                             \
 *                   (entry)->sip >> 24,  (entry)->sip >> 16,  (entry)->sip >> 8, \
 *                   (entry)->sip,                                                \
 *                   (entry)->src_mac[0], (entry)->src_mac[1],                    \
 *                   (entry)->src_mac[2], (entry)->src_mac[3],                    \
 *                   (entry)->src_mac[4], (entry)->src_mac[5],                    \
 *                   (entry)->state);                                             \
 *       } while(0)
 */
#else
#define ARP_DEBUG(msg, hdr)
#define ARPDATA_DEBUG(msg, data)
#define ARPCACHE_DEBUG(msg, entry)
#endif

typedef struct arp_ipv4 {
    u8  arp_sha[ETHERNET_ADDRESS_LEN];
    u32 arp_sip;
    u8  arp_tha[ETHERNET_ADDRESS_LEN];
    u32 arp_tip;
} __nsn_packed arp_ipv4_t;

//--------------------------------------------------------------------------------------------------

typedef struct arp_hdr {
    u16 arp_htype;
    u16 arp_ptype;
    u8  arp_hlen;
    u8  arp_plen;
    u16 arp_opcode;

    arp_ipv4_t arp_data;
} __nsn_packed arp_hdr_t;

//--------------------------------------------------------------------------------------------------

u8 *arp_get_hwaddr(u32 saddr);

void arp_receive(nsn_runtime_t *nsnrt, u8 *pkt_data);

i32 arp_request(nsn_runtime_t *nsnrt, u32 saddr, u32 daddr);

//--------------------------------------------------------------------------------------------------
// ARP Table Entry
//--------------------------------------------------------------------------------------------------
#define ARP_TRASL_TABLE_INSERT_FAILED   0
#define ARP_TRASL_TABLE_INSERT_OK       1
#define ARP_TRASL_TABLE_UPDATE_NO_ENTRY 0
#define ARP_TRASL_TABLE_UPDATE_OK       1

typedef struct arp_cache_entry {
    list_head_t list;

    u16 hwtype;
    u32 sip;
    u8  src_mac[ETHERNET_ADDRESS_LEN];
    u32 state;
} arp_cache_entry_t;

#endif // INSANE_ARP_H
