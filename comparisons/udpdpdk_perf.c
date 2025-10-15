#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_ip_frag.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_udp.h>

// REDME: This test assumes that we pass the -a argument to the DPDK EAL,
// which selects the device to be used. If not passed, the test will select
// the device available on port_id = 0.

// A simple macro used to check if there are enough command line args
#define ENSURE_ONE_MORE_ARGUMENT(argc, argv, i, argName)                                           \
    if (i + 1 >= argc) {                                                                           \
        usage(argc, argv);                                                                         \
        fprintf(stderr, "! Error: missing value for %s argument\n", argName);                      \
        return false;                                                                              \
    }

#define MSG              "hello, DPDK!"
#define MTU              1500
#define MAX_PAYLOAD_SIZE 1472
#define MIN_PAYLOAD_SIZE 16

#define INSANE_PORT    9999
#define IP_DEFAULT_TTL 64
#define PAYLOAD_OFFSET RTE_ETHER_HDR_LEN + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr)

#define IP_SRC  RTE_IPV4(192, 168, 56, 211)
#define IP_DST  RTE_IPV4(192, 168, 56, 212)
#define MAC_SRC "b8:ce:f6:4d:ef:1c"
#define MAC_DST "b8:ce:f6:4d:ef:2e"

typedef enum role {
    role_sink,
    role_source,
    role_ping,
    role_pong,
} role_t;

static char *role_strings[] = {"SINK", "SOURCE", "PING", "PONG"};

typedef struct test_config {
    role_t   role;
    uint32_t payload_size;
    uint64_t sleep_time;
    uint64_t max_msg;
    uint16_t burst_size;
    uint16_t port_id;
    uint16_t queue_id;
} test_config_t;

struct test_data {
    uint64_t cnt;
    uint64_t tx_time;
};

volatile bool g_running  = true;
volatile bool queue_stop = false;

// --------------------------------------------------------------------------------------------------
// ARP
#define ETHERNET_P_IP    0x0800 /* Internet Protocol packet	    */
#define ETHERNET_P_ARP   0x0806 /* Address Resolution packet	*/
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
    char     *ip_str; // IP in string form
    uint32_t  ip_net; // IP in network byte order
    bool      mac_set; // MAC address set or not (for ARP)
    struct rte_ether_addr mac_addr; // MAC address
};

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
static int32_t arp_request(
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
        .addr_bytes = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
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

enum arp_entry {
    LOCAL,
    REMOTE,
};
static struct arp_peer arp_cache[2];

//--------------------------------------------------------------------------------------------------
void handle(int signum) {
    (void)(signum);
    fprintf(stderr, "Received CTRL+C. Exiting!\n");
    g_running  = false;
    queue_stop = true;
}

//--------------------------------------------------------------------------------------------------
void usage(int argc, char *argv[]) {
    (void)(argc);
    printf("Usage: %s [EAL-ARGS] -- [MODE] [OPTIONS]    \n"
           "MODE: source|sink|ping|pong                 \n"
           "OPTIONS:                                    \n"
           "-h: display this message and exit           \n"
           "-s: message payload size in bytes           \n"
           "-n: max messages to send (0 = no limit)     \n"
           "-b: burst size for send and receive         \n"
           "-r: configure sleep time (s) in send        \n",
           argv[0]);
}

//--------------------------------------------------------------------------------------------------
static inline uint64_t get_clock_realtime_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

//--------------------------------------------------------------------------------------------------
static void setup_pkt_udp_ip_headers(struct rte_ipv4_hdr *ip_hdr, struct rte_udp_hdr *udp_hdr,
                                     uint16_t pkt_data_len, uint32_t src_ip, uint32_t dst_ip) {
    uint16_t *ptr16;
    uint32_t  ip_cksum;
    uint16_t  pkt_len;

    /*
     * Initialize UDP header.
     */
    pkt_len              = (uint16_t)(pkt_data_len + sizeof(struct rte_udp_hdr));
    udp_hdr->src_port    = rte_cpu_to_be_16(INSANE_PORT);
    udp_hdr->dst_port    = rte_cpu_to_be_16(INSANE_PORT);
    udp_hdr->dgram_len   = rte_cpu_to_be_16(pkt_len);
    udp_hdr->dgram_cksum = 0; /* No UDP checksum. */

    /*
     * Initialize IP header.
     */
    pkt_len                 = (uint16_t)(pkt_len + sizeof(struct rte_ipv4_hdr));
    ip_hdr->version_ihl     = RTE_IPV4_VHL_DEF;
    ip_hdr->type_of_service = 0;
    ip_hdr->fragment_offset = 0;
    ip_hdr->time_to_live    = IP_DEFAULT_TTL;
    ip_hdr->next_proto_id   = IPPROTO_UDP;
    ip_hdr->packet_id       = 0;
    ip_hdr->total_length    = rte_cpu_to_be_16(pkt_len);
    ip_hdr->src_addr        = rte_cpu_to_be_32(src_ip);
    ip_hdr->dst_addr        = rte_cpu_to_be_32(dst_ip);

    /*
     * Compute IP header checksum.
     */
    ptr16    = (unaligned_uint16_t *)ip_hdr;
    ip_cksum = 0;
    ip_cksum += ptr16[0];
    ip_cksum += ptr16[1];
    ip_cksum += ptr16[2];
    ip_cksum += ptr16[3];
    ip_cksum += ptr16[4];
    ip_cksum += ptr16[6];
    ip_cksum += ptr16[7];
    ip_cksum += ptr16[8];
    ip_cksum += ptr16[9];

    /*
     * Reduce 32 bit checksum to 16 bits and complement it.
     */
    ip_cksum = ((ip_cksum & 0xFFFF0000) >> 16) + (ip_cksum & 0x0000FFFF);
    if (ip_cksum > 65535)
        ip_cksum -= 65535;
    ip_cksum = (~ip_cksum) & 0x0000FFFF;
    if (ip_cksum == 0)
        ip_cksum = 0xFFFF;
    ip_hdr->hdr_checksum = (uint16_t)ip_cksum;
}

static inline bool pkt_prepare(struct rte_mbuf *pkt, test_config_t *args) {
    rte_pktmbuf_reset_headroom(pkt);
    pkt->data_len = args->payload_size + PAYLOAD_OFFSET;
    pkt->pkt_len  = pkt->data_len;
    pkt->l2_len   = sizeof(struct rte_ether_hdr);
    pkt->l3_len   = sizeof(struct rte_ipv4_hdr);
    pkt->nb_segs = 1;
    pkt->next    = NULL;

    /* Ethernet, IP, UDP headers*/
    struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
    struct rte_ipv4_hdr  *ip_hdr  = (struct rte_ipv4_hdr *)(eth_hdr + 1);
    struct rte_udp_hdr   *udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
    memcpy(&eth_hdr->src_addr, &arp_cache[LOCAL].mac_addr, RTE_ETHER_ADDR_LEN);
    memcpy(&eth_hdr->dst_addr, &arp_cache[REMOTE].mac_addr, RTE_ETHER_ADDR_LEN);
    eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    setup_pkt_udp_ip_headers(ip_hdr, udp_hdr, args->payload_size, IP_SRC, IP_DST);
    return true;
}

//--------------------------------------------------------------------------------------------------
// source
void do_source(struct rte_mempool *mempool, test_config_t *params) {
    uint64_t          counter = 0;
    struct test_data *data;
    int               ret;
    uint64_t          to_send, actual_burst;

    // ARP request and reply
    struct rte_mbuf *mbufs[params->burst_size];
    arp_request(
        params->port_id, params->queue_id,
        &arp_cache[LOCAL].mac_addr, arp_cache[LOCAL].ip_net,
        arp_cache[REMOTE].ip_net, mempool);   
        
    while(arp_cache[REMOTE].mac_set == false && g_running) {
        uint16_t nb_rx = rte_eth_rx_burst(params->port_id, params->queue_id, mbufs, params->burst_size);
        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);
            if (rte_be_to_cpu_16(eth_hdr->ether_type) != RTE_ETHER_TYPE_IPV4) {
                if (rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_ARP) {
                    arp_receive(params->port_id, params->queue_id,
                        &arp_cache[LOCAL].mac_addr, arp_cache[LOCAL].ip_net, mbufs[i], arp_cache, 2);
                }
                continue;
            }
        }
    }
    
    // Pre-allocate the mbufs, populate them, and prepare headers
    struct rte_mbuf *mbuf[params->burst_size];
    uint64_t tx_time;
    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {

        if (params->sleep_time) {
            sleep(params->sleep_time);
        }

        to_send      = params->max_msg - counter;
        actual_burst = (to_send >= params->burst_size) ? params->burst_size : to_send;
        tx_time = get_clock_realtime_ns();

        // Allocate a burst of mbufs, prepare them (UDP/IP headers), and fill payload
        for (uint16_t i = 0; i < actual_burst; i++) {
            mbuf[i] = rte_pktmbuf_alloc(mempool);
            pkt_prepare(mbuf[i], params);
            data          = rte_pktmbuf_mtod_offset(mbuf[i], struct test_data *, PAYLOAD_OFFSET);
            data->tx_time = tx_time;
            data->cnt     = counter++;
            rte_strscpy((char*)(data + 1), MSG, strlen(MSG));
            // fprintf(stderr, "(%ld) len: %u (%u) time: %ld\n", counter, mbuf[i]->pkt_len, mbuf[i]->data_len, tx_time);
        }

        ret = 0;
        while((uint64_t)ret < actual_burst) {
            ret += rte_eth_tx_burst(params->port_id, params->queue_id, mbuf + ret, actual_burst - ret);
        }
        // fprintf(stderr, "Sent %d packets\n", ret);
    }
}

//--------------------------------------------------------------------------------------------------
// sink
void do_sink(struct rte_mempool *mempool, test_config_t *params) {

    (void)(mempool);
    struct rte_mbuf *mbufs[params->burst_size];

    uint64_t first_time = 0, last_time = 0;
    uint16_t nb_rx   = 0;
    uint64_t counter = 0;
    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {

        nb_rx = rte_eth_rx_burst(params->port_id, params->queue_id, mbufs, params->burst_size);

        for (uint16_t i = 0; i < nb_rx; i++) {

            // If ARP request, reply
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);
            if (rte_be_to_cpu_16(eth_hdr->ether_type) != RTE_ETHER_TYPE_IPV4) {
                if (rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_ARP) {
                    arp_receive(params->port_id, params->queue_id,
                        &arp_cache[LOCAL].mac_addr, arp_cache[LOCAL].ip_net, mbufs[i], arp_cache, 2);
                }
                continue;
            }
                
            // Filter relevant packets: UDP port must be INSANE_PORT
            struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
            struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(ip_hdr + 1);
            if (ip_hdr->next_proto_id == IPPROTO_UDP &&
                rte_be_to_cpu_16(udp_hdr->dst_port) == INSANE_PORT) {
                if (counter == 0) {
                    first_time = get_clock_realtime_ns();
                }

                counter++;
                // struct test_data *data = (struct test_data *)buf.data;
                // fprintf(stderr, "(%ld) received: %ld, %s)\n", counter, data->cnt, data->msg);
            }
            rte_pktmbuf_free(mbufs[i]);
        }
    }
    last_time = get_clock_realtime_ns();

    /* Compute results */
    uint64_t elapsed_time_ns = last_time - first_time;
    double   mbps =
        ((counter * params->payload_size * 8) * ((double)1e3)) / ((double)elapsed_time_ns);
    double throughput = ((counter) * ((double)1e3)) / ((double)elapsed_time_ns);

    /* Print results */
    // fprintf(stdout,
    //         "[ TEST RESULT ]                 \n"
    //         "Received messages:   %lu        \n"
    //         "Elapsed time:        %.3f ms    \n"
    //         "Measured throughput: %.3f Mmsg/s\n"
    //         "Measured banwdidth:  %.3f Mbps  \n\n",
    //         counter, (double)elapsed_time_ns / ((double)1e6), throughput, mbps);
    fprintf(stdout, "%lu,%u,%.3f,%.3f,%.3f\n", counter, params->payload_size,
            (double)elapsed_time_ns / ((double)1e6), throughput, mbps);
}

//--------------------------------------------------------------------------------------------------
// ping
void do_ping(struct rte_mempool *mempool, test_config_t *params) {
    // char                *msg     = MSG;
    uint64_t             counter = 0;
    // struct test_data    *data;
    uint64_t             send_time, response_time, latency;
    uint16_t             ret;
    uint8_t              pong_received;
    struct rte_mbuf     *rx_mbuf[params->burst_size];
    struct rte_ipv4_hdr *ih;
    struct rte_udp_hdr  *uh;

    // ARP request and reply
    struct rte_mbuf *mbufs[params->burst_size];
    arp_request(
        params->port_id, params->queue_id,
        &arp_cache[LOCAL].mac_addr, arp_cache[LOCAL].ip_net,
        arp_cache[REMOTE].ip_net, mempool);   
        
    while(arp_cache[REMOTE].mac_set == false && g_running) {
        uint16_t nb_rx = rte_eth_rx_burst(params->port_id, params->queue_id, mbufs, params->burst_size);
        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);
            if (rte_be_to_cpu_16(eth_hdr->ether_type) != RTE_ETHER_TYPE_IPV4) {
                if (rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_ARP) {
                    arp_receive(params->port_id, params->queue_id,
                        &arp_cache[LOCAL].mac_addr, arp_cache[LOCAL].ip_net, mbufs[i], arp_cache, 2);
                }
                continue;
            }
        }
    }

    // Pre-allocate one mbuf, populate it, and prepare headers
    struct rte_mbuf *tx_mbuf;

    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {

        if (params->sleep_time) {
            sleep(params->sleep_time);
        }

        send_time = get_clock_realtime_ns();

        // Allocate a single mbuf
        tx_mbuf = rte_pktmbuf_alloc(mempool);

        // Prepare the packet header
        pkt_prepare(tx_mbuf, params);

        // Fill the payload
        // data          = rte_pktmbuf_mtod_offset(tx_mbuf, struct test_data *, PAYLOAD_OFFSET);
        // data->tx_time = send_time;
        // data->cnt     = counter;
        // rte_strscpy((char*)(data + 1), msg, strlen(msg));
        counter++;

        // Send the packet
        ret = rte_eth_tx_burst(params->port_id, params->queue_id, &tx_mbuf, 1);
        // fprintf(stderr, "(%ld) len: %u time: %ld\n", counter, tx_mbuf->pkt_len, send_time);

        pong_received = 0;
        while (!pong_received) {
            // Receive 1, but 8 is the minimum burst size to ensure compatibility
            ret = rte_eth_rx_burst(params->port_id, params->queue_id, rx_mbuf, 8);                   
            for (uint16_t j = 0; j < ret; j++) {

                // If ARP request, reply
                struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(rx_mbuf[j], struct rte_ether_hdr *);
                if (rte_be_to_cpu_16(eth_hdr->ether_type) != RTE_ETHER_TYPE_IPV4) {
                    if (rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_ARP) {
                        arp_receive(params->port_id, params->queue_id,
                            &arp_cache[LOCAL].mac_addr, arp_cache[LOCAL].ip_net, rx_mbuf[j], arp_cache, 2);
                    }
                    continue;
                }

                ih = (struct rte_ipv4_hdr *)(eth_hdr + 1);
                uh = (struct rte_udp_hdr *)(ih + 1);
                if (ih->next_proto_id == IPPROTO_UDP &&
                    rte_be_to_cpu_16(uh->dst_port) == INSANE_PORT)
                {

                    response_time = get_clock_realtime_ns();
                    latency       = response_time - send_time;
                    pong_received = 1;

                    fprintf(stdout, "%.3f\n", (float)latency / 1000.0F);
                }
                rte_pktmbuf_free(rx_mbuf[j]);
            }
        } 
    }
}

//--------------------------------------------------------------------------------------------------
// pong
void do_pong(struct rte_mempool *mempool, test_config_t *params) {
    struct rte_ether_addr remote_mac_addr;
    struct rte_ipv4_hdr  *ih;
    rte_be32_t            ia;
    struct rte_udp_hdr   *uh;
    uint64_t              counter = 0;
    uint16_t              nb_rx = 0;
    (void)(mempool);

    struct rte_mbuf *mbuf[8];
    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {

        nb_rx = rte_eth_rx_burst(params->port_id, params->queue_id, mbuf, 8);

        for (uint16_t j = 0; j < nb_rx; j++) {
            // If ARP request, reply
            struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(mbuf[j], struct rte_ether_hdr *);
            if (rte_be_to_cpu_16(eth_hdr->ether_type) != RTE_ETHER_TYPE_IPV4) {
                if (rte_be_to_cpu_16(eth_hdr->ether_type) == RTE_ETHER_TYPE_ARP) {
                    arp_receive(params->port_id, params->queue_id,
                        &arp_cache[LOCAL].mac_addr, arp_cache[LOCAL].ip_net, mbuf[j], arp_cache, 2);
                }
                continue;
            }

            ih = (struct rte_ipv4_hdr *)(eth_hdr + 1);
            uh = (struct rte_udp_hdr *)(ih + 1);
            // fprintf(stderr, "Received packet to port %u\n", rte_be_to_cpu_16(uh->dst_port));

            if (ih->next_proto_id == IPPROTO_UDP && rte_be_to_cpu_16(uh->dst_port) == INSANE_PORT) {

                // Switch MAC addresses in place
                memcpy(&remote_mac_addr, &eth_hdr->src_addr, RTE_ETHER_ADDR_LEN);    
                memcpy(&eth_hdr->src_addr, &eth_hdr->dst_addr, RTE_ETHER_ADDR_LEN);
                memcpy(&eth_hdr->dst_addr, &remote_mac_addr, RTE_ETHER_ADDR_LEN);
                eth_hdr->ether_type = rte_cpu_to_be_16(ETHERNET_P_IP);

                ia               = ih->src_addr;
                ih->src_addr     = ih->dst_addr;
                ih->dst_addr     = ia;
                ih->time_to_live = IP_DEFAULT_TTL;
                ih->hdr_checksum = 0;
                ih->hdr_checksum = rte_ipv4_cksum(ih);

                uh->dgram_cksum = 0;
                // uh->dgram_cksum = rte_ipv4_udptcp_cksum(ih, uh);

                // fprintf(stderr, 
                //     "Forwarding sample %lu of len %u on port %u queue %u\n",
                //     (rte_pktmbuf_mtod_offset(mbuf[j], struct test_data *, PAYLOAD_OFFSET))->cnt, mbuf[j]->pkt_len,
                //     params->port_id, params->queue_id);

                // Send packet back
                uint16_t ret = 0;
                while (!ret) {
                    ret = rte_eth_tx_burst(params->port_id, params->queue_id, &mbuf[j], 1);
                }
                ++counter;
            } else {
                // Discard non-relevant packet
                rte_pktmbuf_free(mbuf[j]);
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
int parse_arguments(int argc, char *argv[], test_config_t *config) {
    /* Argument number */
    if (argc < 2) {
        fprintf(stderr, "! Invalid number of arguments\n"
                        "! You must specify at least the running MODE\n");
        return -1;
    }
    /* Default values */
    config->role         = role_sink;
    config->payload_size = strlen(MSG) + 1;
    config->sleep_time   = 0;
    config->max_msg      = 0;
    config->burst_size   = 8;
    config->port_id      = 0;
    config->queue_id     = 0;

    /* Test role (mandatory argument) */
    if (!strcmp(argv[1], "sink")) {
        config->role = role_sink;
    } else if (!strcmp(argv[1], "source")) {
        config->role = role_source;
    } else if (!strcmp(argv[1], "ping")) {
        config->role = role_ping;
    } else if (!strcmp(argv[1], "pong")) {
        config->role = role_pong;
    } else if (!strncmp(argv[1], "-h", 2) || !strncmp(argv[1], "--help", 6)) {
        return -1; // Success, but termination required
    } else {
        fprintf(stderr, "Unrecognized argument: %s\n", argv[1]);
        return -1;
    }

    /* Parse the optional arguments */
    for (int i = 2; i < argc; ++i) {
        // Helper
        if (!strncmp(argv[i], "-h", 2) || !strncmp(argv[i], "--help", 6)) {
            return -1; // Success, but termination required
        }
        // Message payload size
        if (!strncmp(argv[i], "-s", 2) || !strncmp(argv[i], "--size", 6)) {
            char *ptr;
            ENSURE_ONE_MORE_ARGUMENT(argc, argv, i, "--size")
            config->payload_size = strtol(argv[++i], &ptr, 10);
            if (*ptr != '\0') {
                fprintf(stderr, "! Invalid value for --size option: %s\n", argv[i]);
                return -1;
            }
            if (config->payload_size <= MIN_PAYLOAD_SIZE || config->payload_size > MAX_PAYLOAD_SIZE)
            {
                fprintf(stderr, "! Invalid value for --size option: %s\n", argv[i]);
                return -1;
            }
            continue;
        }
        // Max number of messages
        if (!strncmp(argv[i], "-n", 2) || !strncmp(argv[i], "--num-msg", 9)) {
            char *ptr;
            ENSURE_ONE_MORE_ARGUMENT(argc, argv, i, "--num-msg")
            config->max_msg = strtol(argv[++i], &ptr, 10);
            if (*ptr != '\0') {
                fprintf(stderr, "! Invalid value for --num-msg option: %s\n", argv[i]);
                return -1;
            }
            continue;
        }
        // Burst size
        if (!strncmp(argv[i], "-b", 2) || !strncmp(argv[i], "--burst-size", 12)) {
            char *ptr;
            ENSURE_ONE_MORE_ARGUMENT(argc, argv, i, "--burst-size")
            config->burst_size = strtoul(argv[++i], &ptr, 10);
            if (*ptr != '\0') {
                fprintf(stderr, "! Invalid value for --burst-size option: %s\n", argv[i]);
                return -1;
            }
            if (config->burst_size <= 0) {
                fprintf(stderr, "! burst_size: %s\n", argv[i]);
                return -1;
            }
            continue;
        }
        // Sleep time
        if (!strncmp(argv[i], "-r", 2) || !strncmp(argv[i], "--sleep-time", 12)) {
            char *ptr;
            ENSURE_ONE_MORE_ARGUMENT(argc, argv, i, "--sleep-time")
            config->sleep_time = strtol(argv[++i], &ptr, 10);
            if (*ptr != '\0') {
                fprintf(stderr, "! Invalid value for sleep-time option: %s\n", argv[i]);
                return -1;
            }
            continue;
        }
    }

    // Print out the configuration
    printf("Running with the following arguments:   \n"
           "\tRole............. : %s                \n"
           "\tPayload size..... : %d                \n"
           "\tMax messages..... : %lu               \n"
           "\tSleep time....... : %ld               \n\n",
           role_strings[config->role], config->payload_size, config->max_msg, config->sleep_time);

    return 0;
}

//--------------------------------------------------------------------------------------------------
static inline int port_init(struct rte_mempool *mempool, uint16_t mtu, test_config_t *params) {
    
    // Select the first device on list - please use -a to only pass one device
    struct rte_eth_dev_info dev_info;
    int ret;
    RTE_ETH_FOREACH_DEV(params->port_id) {
        ret = rte_eth_dev_info_get(params->port_id, &dev_info);
        if (ret < 0) {
            fprintf(stderr, "[error] cannot get info for port %u: %s, skipping\n", params->port_id,
                   rte_strerror(rte_errno));
            continue;
        }
        fprintf(stderr, "found device on port %u\n", params->port_id);
        break;
    }  
       
    int valid_port = rte_eth_dev_is_valid_port(params->port_id);
    if (!valid_port)
        return -1;

    int retval = rte_eth_dev_info_get(params->port_id, &dev_info);
    if (retval != 0) {
        fprintf(stderr, "[error] cannot get device (port %u) info: %s\n", params->port_id, strerror(-retval));
        return retval;
    }

    // Derive the actual MTU we can use based on device capabilities and user request
    uint16_t actual_mtu = RTE_MIN(mtu, dev_info.max_mtu);

    // Configure the device
    uint16_t port_id = params->port_id;
    struct rte_eth_conf port_conf;
    memset(&port_conf, 0, sizeof(port_conf));
    port_conf.rxmode.mtu = actual_mtu;
    port_conf.rxmode.offloads |= (RTE_ETH_RX_OFFLOAD_CHECKSUM | RTE_ETH_RX_OFFLOAD_SCATTER);
    port_conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;
    port_conf.txmode.offloads |= (RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_MULTI_SEGS);
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
    const uint16_t rx_rings = 1, tx_rings = 1;
    retval = rte_eth_dev_configure(port_id, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    // Set the MTU explicitly
    retval = rte_eth_dev_set_mtu(port_id, actual_mtu);
    if (retval != 0) {
        printf("Error setting up the MTU (%d)\n", retval);
        return retval;
    }

    uint16_t nb_rxd = 1024;
    uint16_t nb_txd = 1024;
    retval          = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    int socket_id = rte_eth_dev_socket_id(port_id);
    if (socket_id < 0) {
        if (rte_errno == EINVAL) {
            fprintf(stderr, "[error] cannot get socket ID for port %u: %s. .\n", port_id, strerror(-socket_id));
            return -EINVAL;
        } else {
            socket_id = 0; // Default to socket 0 if socket could not be determined (e.g., in VMs)
        }
    }

    for (uint16_t q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(port_id, q, nb_rxd, socket_id, NULL, mempool);
        if (retval != 0)
            return retval;
    }

    struct rte_eth_txconf txconf = dev_info.default_txconf;
    txconf.offloads              = port_conf.txmode.offloads;
    for (uint16_t q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port_id, q, nb_txd, socket_id, &txconf);
        if (retval != 0)
            return retval;
    }

    retval = rte_eth_dev_start(port_id);
    if (retval != 0) {
        return retval;
    }

    // retval = rte_eth_promiscuous_enable(port_id);
    // if (retval != 0)
    //     return retval;

    return 0;
}

//--------------------------------------------------------------------------------------------------
// MAIN
int main(int argc, char *argv[]) {
    signal(SIGINT, handle);
    printf("Welcome to the test of the raw DPDK performance\n");

    /* Initialize DPDK */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "error with EAL initialization\n");
    }
    printf("Eal Init OK\n");

    /* Check test arguments */
    argc -= ret;
    test_config_t params;
    if (parse_arguments(argc, &argv[ret], &params) < 0) {
        usage(argc, argv);
        return -1;
    }

    /* Create mempool */
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create(
        "mbuf_pool", 10240, 64, 0, RTE_MBUF_DEFAULT_DATAROOM, rte_socket_id());
    if (mbuf_pool == NULL) {
        printf("RTE_ERROR: %s\n", rte_strerror(rte_errno));
        rte_exit(EXIT_FAILURE, "cannot create the mbuf pool\n");
    }

    /* Port init */
    ret = port_init(mbuf_pool, MTU, &params);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "error with port initialization\n");
    }
    printf("Port creation OK\n");


    /* ARP */
    arp_cache[LOCAL].ip_net = htonl(IP_SRC);
    arp_cache[LOCAL].ip_str = malloc(16);
    inet_ntop(AF_INET, &arp_cache[LOCAL].ip_net, arp_cache[LOCAL].ip_str, 16);
    rte_eth_macaddr_get(params.port_id, &arp_cache[LOCAL].mac_addr);
    arp_cache[LOCAL].mac_set = true;

    arp_cache[REMOTE].ip_net = htonl(IP_DST);
    arp_cache[REMOTE].ip_str = malloc(16);
    inet_ntop(AF_INET, &arp_cache[REMOTE].ip_net, arp_cache[REMOTE].ip_str, 16);
    arp_cache[REMOTE].mac_set = false;

    /* Do test */
    if (params.role == role_sink) {
        do_sink(mbuf_pool, &params);
    } else if (params.role == role_source) {
        do_source(mbuf_pool, &params);
    } else if (params.role == role_ping) {
        do_ping(mbuf_pool, &params);
    } else if (params.role == role_pong) {
        do_pong(mbuf_pool, &params);
    } else {
        fprintf(stderr, "Test not supported\n");
        return -1;
    }

    /* Terminate */
    rte_eth_dev_stop(params.port_id);
    rte_eal_cleanup();
    return 0;
}
