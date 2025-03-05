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

struct arp_peer {
    char* ip_str; // IP in string form
    u32   ip_net; // IP in network byte order
    bool  mac_set; // MAC address set or not (for ARP)
    struct rte_ether_addr mac_addr; // MAC address
};

/* IPv4 */
#define ICMPV4     1
#define IPV4       4
#define IP_TCP     6
#define IP_UDP     17
#define ip_len(ip) (ip->len - (ip->ihl * 4))

/* UDP */
#define MAX_UDP_PAYLOAD_SIZE 1434

/** 
 * @brief Prepare the ARP reply in-place.
 * 
 * @param arp_pkt     ARP packet to be replied  
 * @param local_ipv4  Local IP addr in network byte order
 */
void 
arp_reply_prepare(
    struct rte_mbuf* arp_pkt, uint32_t local_ipv4,
    struct rte_ether_addr *local_mac_addr
){
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(arp_pkt, struct rte_ether_hdr *);
    struct arp_hdr *arp_hdr       = (struct arp_hdr*)(eth_hdr + 1);
    struct arp_ipv4 *req_data     = &arp_hdr->arp_data;

    struct rte_ether_addr remote_mac_addr;
    memcpy(&remote_mac_addr, &eth_hdr->src_addr, RTE_ETHER_ADDR_LEN);
    
    // 1. Ethernet Header
    memcpy(&eth_hdr->src_addr, local_mac_addr, RTE_ETHER_ADDR_LEN);
    memcpy(&eth_hdr->dst_addr, &remote_mac_addr, RTE_ETHER_ADDR_LEN);
    eth_hdr->ether_type = rte_cpu_to_be_16(ETHERNET_P_ARP);

    // 2. ARP Data
    memcpy(req_data->arp_sha, local_mac_addr->addr_bytes, RTE_ETHER_ADDR_LEN);
    memcpy(req_data->arp_tha, remote_mac_addr.addr_bytes, RTE_ETHER_ADDR_LEN);
    req_data->arp_tip = req_data->arp_sip;
    req_data->arp_sip = local_ipv4;

    arp_hdr->arp_opcode = rte_cpu_to_be_16(ARP_REPLY);
    arp_hdr->arp_htype  = rte_cpu_to_be_16(ARP_ETHERNET);
    arp_hdr->arp_hlen   = RTE_ETHER_ADDR_LEN;
    arp_hdr->arp_ptype  = rte_cpu_to_be_16(ETHERNET_P_IP);
    arp_hdr->arp_plen   = 4;

    arp_pkt->next     = NULL;
    arp_pkt->nb_segs  = 1;
    arp_pkt->pkt_len  = sizeof(arp_hdr_t) + RTE_ETHER_HDR_LEN;
    arp_pkt->data_len = arp_pkt->pkt_len;
}

/** Reply to an ARP request, sending the ARP reply to the network.
* @param port_id: port ID of the device
* @param tx_queue_id: TX queue ID of the device
* @param local_mac_addr: local MAC addr
* @param local_ip_net: local IP addr in network byte order
* @param arp_pkt: ARP packet to be replied
*/
void 
arp_reply(
    uint16_t port_id, uint16_t tx_queue_id, 
    struct rte_ether_addr* local_mac_addr, uint32_t local_ip_net, 
    struct rte_mbuf* arp_pkt
) {
    arp_reply_prepare(arp_pkt, local_ip_net, local_mac_addr);

    uint16_t ret = 0;
    while(!ret) {
        ret = rte_eth_tx_burst(port_id, tx_queue_id, &arp_pkt, 1);
    }    
}

void 
arp_update_cache(struct arp_hdr *arp_hdr, struct arp_peer *peers, int n_peers)
{
    // Update the ARP cache
    for (int i = 0; i < n_peers; i++) {
        if (peers[i].ip_net == arp_hdr->arp_data.arp_sip) {
            memcpy(&peers[i].mac_addr, &arp_hdr->arp_data.arp_sha, RTE_ETHER_ADDR_LEN);
            peers[i].mac_set = true;            
            break;
        }
    }
}

void
arp_receive(
    uint16_t port_id, uint16_t tx_queue_id, 
    struct rte_ether_addr *local_mac_addr, uint32_t local_ip_net, 
    struct rte_mbuf *arp_mbuf, struct arp_peer *peers, int n_peers
) {   
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(arp_mbuf, struct rte_ether_hdr *);
    struct arp_hdr *arp_hdr       = (struct arp_hdr*)(eth_hdr + 1);

    char mac_str[32];
    struct rte_ether_addr mac_addr;
    memcpy(mac_addr.addr_bytes, arp_hdr->arp_data.arp_sha, RTE_ETHER_ADDR_LEN);
    rte_ether_format_addr(mac_str, sizeof(mac_str), &mac_addr);
    char peer_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &arp_hdr->arp_data.arp_sip, peer_ip, INET_ADDRSTRLEN);

    fprintf(stderr, "[arp] received an ARP packet from %s with MAC %s\n", peer_ip, mac_str);

    arp_update_cache(arp_hdr, peers, n_peers);

    // Check if the ARP packet is for this IP
    if (arp_hdr->arp_data.arp_tip != local_ip_net)
        return;

    switch (rte_be_to_cpu_16(arp_hdr->arp_opcode)) {
        case ARP_REQUEST: 
            arp_reply(port_id, tx_queue_id, local_mac_addr, local_ip_net, arp_mbuf);
            break;
        default:
            // Replies or wrong opcodes - no action
            break;
    }
}

// l_ipv4_net: local IP in network byte order
// d_ipv4_net: destination IP in network byte order
int32_t 
arp_request(
    uint16_t port_id, uint16_t tx_queue_id,
    struct rte_ether_addr *local_haddr, uint32_t local_ipv4, 
    uint32_t peer_ipv4, struct rte_mempool *arp_pool
) {
    struct rte_mbuf *rte_mbuf = rte_pktmbuf_alloc(arp_pool);
    if (!rte_mbuf) {
        fprintf(stderr, "[arp] failed to allocate mbuf for ARP request: %s\n", 
                rte_strerror(rte_errno));
        return -rte_errno;
    }

    struct rte_ether_hdr *eth_hdr;
    struct rte_ether_addr broadcast_hw = {
        .addr_bytes = ETHERNET_BROADCAST_ADDR,
    };

    // Ethernet
    {
        eth_hdr = rte_pktmbuf_mtod(rte_mbuf, struct rte_ether_hdr *);
        eth_hdr->ether_type = rte_cpu_to_be_16(ETHERNET_P_ARP);
        memcpy(&eth_hdr->src_addr, local_haddr, RTE_ETHER_ADDR_LEN);
        memcpy(&eth_hdr->dst_addr, &broadcast_hw, RTE_ETHER_ADDR_LEN);
    }

    // ARP data
    {
        arp_hdr_t *ahdr = (arp_hdr_t *)(eth_hdr + 1);
        ahdr->arp_opcode = rte_cpu_to_be_16(ARP_REQUEST);
        ahdr->arp_htype  = rte_cpu_to_be_16(ARP_ETHERNET);
        ahdr->arp_ptype  = rte_cpu_to_be_16(ETHERNET_P_IP);
        ahdr->arp_hlen   = RTE_ETHER_ADDR_LEN;
        ahdr->arp_plen   = 4;
        
        arp_ipv4_t *adata = (arp_ipv4_t *)(&ahdr->arp_data);
        adata->arp_sip = local_ipv4;
        adata->arp_tip = peer_ipv4;
        memcpy(adata->arp_sha, local_haddr->addr_bytes, RTE_ETHER_ADDR_LEN);
        memcpy(adata->arp_tha, broadcast_hw.addr_bytes, RTE_ETHER_ADDR_LEN);
    }

    // Append the fragment to the transmission queue of the control DP
    {
        rte_mbuf->next    = NULL;
        rte_mbuf->nb_segs = 1;
        rte_mbuf->pkt_len = rte_mbuf->data_len = RTE_ETHER_HDR_LEN + sizeof(arp_hdr_t);
    }

    char local_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &local_ipv4, local_ip, INET_ADDRSTRLEN);
    char peer_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &peer_ipv4, peer_ip, INET_ADDRSTRLEN);
    char local_mac[32];
    rte_ether_format_addr(local_mac, sizeof(local_mac), local_haddr);

    fprintf(stderr, "[arp] sending ARP request: local IP %s, local MAC %s, peer IP %s\n", 
            local_ip, local_mac, peer_ip);
        
    uint16_t ret = 0;
    while(!ret) {
        ret += rte_eth_tx_burst(port_id, tx_queue_id, &rte_mbuf, 1);
    }

    return 0;
}

#endif // PROTOCOLS_H
