#include <stdio.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip_frag.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include "ethernet.h"
#include "ip.h"

#define IPV4_HDR_FO_ALIGN (1 << RTE_IPV4_HDR_FO_SHIFT)
#define IPV4_HDR_DF_MASK  (1 << RTE_IPV4_HDR_DF_SHIFT)
#define IPV4_HDR_MF_MASK  (1 << RTE_IPV4_HDR_MF_SHIFT)

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET 8
#define DEF_FLOW_TTL    MS_PER_S
#define DEF_FLOW_NUM    0x1000

/* Should be power of two. */
#define IP_FRAG_TBL_BUCKET_ENTRIES 128
#define MAX_FRAG_NUM               128
#define BUF_SIZE                   65407
#define MBUF_DATA_SIZE             (RTE_PKTMBUF_HEADROOM + BUF_SIZE)
#define NB_MBUF                    1024
#define MEMPOOL_CACHE_SIZE         64

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024

struct rx_queue {
    struct rte_ip_frag_tbl *frag_tbl;
    struct rte_mempool     *pool;
    uint16_t                portid;
};

struct lcore_queue_conf {
    uint16_t                     n_rx_queue;
    struct rx_queue              rx_queue_list[1];
    struct rte_ip_frag_death_row death_row;
} __rte_cache_aligned;

typedef enum role { sender, receiver } role_t;

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

static inline int port_init(struct rte_mempool *mempool, uint16_t mtu) {
    int valid_port = rte_eth_dev_is_valid_port(0);
    if (!valid_port)
        return -1;

    struct rte_eth_dev_info dev_info;
    int                     retval = rte_eth_dev_info_get(0, &dev_info);
    if (retval != 0) {
        fprintf(stderr, "[error] cannot get device (port %u) info: %s\n", 0, strerror(-retval));
        return retval;
    }

    uint16_t            port_id = 0;
    struct rte_eth_conf port_conf;
    memset(&port_conf, 0, sizeof(port_conf));

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    const uint16_t rx_rings = 1, tx_rings = 1;
    retval = rte_eth_dev_configure(port_id, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    uint16_t nb_rxd = 1024;
    uint16_t nb_txd = 1024;
    retval          = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;

    int socket_id = rte_eth_dev_socket_id(port_id);

    // Set MTU
    rte_eth_dev_set_mtu(port_id, mtu);

    // struct rte_eth_rxconf rxq_config = dev_info.default_rxconf;
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
    if (retval != 0)
        return retval;

    struct rte_ether_addr ether_addr;
    rte_eth_macaddr_get(port_id, &ether_addr);

    retval = rte_eth_promiscuous_enable(port_id);
    if (retval != 0)
        return retval;

    return 0;
}

static void prepare_packet(struct rte_mbuf *tx_buf, int payload_size, int num_iteration) {
    u32   src_addr;
    u32   dst_addr;
    char *ptr = rte_pktmbuf_mtod(tx_buf, char *);

    /* Ethernet */
    eth_hdr_t *ehdr = (eth_hdr_t *)ptr;
    // clang-format off
    ehdr->src_mac[0] = 0x00; ehdr->src_mac[1] = 0x00; ehdr->src_mac[2] = 0x00;
    ehdr->src_mac[3] = 0x00; ehdr->src_mac[4] = 0x00; ehdr->src_mac[5] = 0x00;
    ehdr->dst_mac[0] = 0xff; ehdr->dst_mac[1] = 0xff; ehdr->dst_mac[2] = 0xff;
    ehdr->dst_mac[3] = 0xff; ehdr->dst_mac[4] = 0xff; ehdr->dst_mac[5] = 0xff;
    ehdr->ether_type = RTE_ETHER_TYPE_IPV4;
    // clang-format on

    /* IP */
    ip_hdr_t *ih = (ip_hdr_t *)(ehdr + 1);
    ip_parse("10.0.0.211", &src_addr);
    ip_parse("10.0.0.212", &dst_addr);
    ih->version     = IPV4;
    ih->ihl         = 0x05;
    ih->tos         = 0;
    ih->len         = IP_HEADER_LEN + payload_size + 1;
    ih->id          = ih->id;
    ih->frag_offset = 0x0000;
    ih->ttl         = 64;
    ih->proto       = IP_UDP;
    ih->csum        = 0x0000;

    ih->src_addr = ntohl(src_addr);
    ih->dst_addr = ntohl(dst_addr);
    ih->len      = htons(ih->len);
    ih->id       = htons(ih->id);
    ih->dst_addr = htonl(ih->dst_addr);
    ih->src_addr = htonl(ih->src_addr);
    ih->csum     = ip_checksum(ih, ih->ihl * 4);

    /* Write payload content */
    char *payload = (char *)(ih + 1);
    memset(payload, 'a' + (num_iteration % 26), payload_size);
    payload[payload_size] = '\0';

    tx_buf->data_len = tx_buf->pkt_len = ETHERNET_HEADER_LEN + IP_HEADER_LEN + payload_size + 1;
}

// Same return semantic as the rte_ipv4_frag_reassemble_packet
static inline struct rte_mbuf *reassemble(struct rte_mbuf *m, struct lcore_queue_conf *qconf,
                                          uint64_t tms) {

    eth_hdr_t *eth_hdr;
    ip_hdr_t  *ip_hdr;

    struct rte_ip_frag_tbl       *tbl;
    struct rte_ip_frag_death_row *dr;
    struct rx_queue              *rxq;

    eth_hdr = rte_pktmbuf_mtod(m, eth_hdr_t *);

    if (eth_hdr->ether_type == ETHERNET_P_IP) {
        ip_hdr = (ip_hdr_t *)(eth_hdr + 1);
        if (ip_hdr->version != IPV4) {
            printf("Unsupported IP version\n");
            return NULL;
        }

        dr  = &qconf->death_row;
        rxq = &qconf->rx_queue_list[0];

        /* if it is a fragmented packet, then try to reassemble. */
        if (rte_ipv4_frag_pkt_is_fragmented((struct rte_ipv4_hdr *)ip_hdr)) {
            struct rte_mbuf *mo;

            tbl = rxq->frag_tbl;

            /* prepare mbuf: setup l2_len/l3_len. */
            m->l2_len = sizeof(*eth_hdr);
            m->l3_len = sizeof(*ip_hdr);

            /* process this fragment. */
            mo = rte_ipv4_frag_reassemble_packet(tbl, dr, m, tms, (struct rte_ipv4_hdr *)ip_hdr);
            if (mo == NULL) {
                /* no packet to return. */
                // printf("null\n");
                return NULL;
            }
            /* we have our packet reassembled. */
            if (mo != m) {
                m       = mo;
                eth_hdr = rte_pktmbuf_mtod(m, eth_hdr_t *);
                ip_hdr  = (ip_hdr_t *)(eth_hdr + 1);
            }
        }
        return m;
    }
    return NULL;
}

static inline void print_content(struct rte_mbuf *m) {
    eth_hdr_t *ehdr    = rte_pktmbuf_mtod(m, eth_hdr_t *);
    ip_hdr_t  *ih_recv = (ip_hdr_t *)(ehdr + 1);
    char      *payload = (char *)(ih_recv + 1);
    do {
        printf("Payload starts at: %p\n", payload);
        // for (uint16_t i = 0; i < m->data_len; i++) {
        //     printf("%c", payload[i]);
        // }
        m = m->next;
        if (m != NULL) {
            payload = rte_pktmbuf_mtod(m, char *);
        }
    } while (m != NULL);
}

static int setup_queue_tbl(struct rx_queue *rxq, uint32_t lcore, uint32_t queue,
                           uint16_t port_mtu) {
    int      socket;
    uint32_t nb_mbuf;
    uint64_t frag_cycles;
    char     buf[RTE_MEMPOOL_NAMESIZE];
    socket = rte_lcore_to_socket_id(lcore);
    if (socket == SOCKET_ID_ANY)
        socket = 0;

    uint32_t max_flow_num = (uint32_t)0x100;
    uint32_t max_flow_ttl = DEF_FLOW_TTL;
    uint32_t max_entries  = IP_FRAG_TBL_BUCKET_ENTRIES;
    uint16_t nb_rxd       = RTE_TEST_RX_DESC_DEFAULT;
    uint16_t nb_txd       = RTE_TEST_TX_DESC_DEFAULT;

    /* Each table entry holds information about packet fragmentation. 8< */
    frag_cycles = (rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S * max_flow_ttl;
    frag_cycles *= 100;

    if ((rxq->frag_tbl = rte_ip_frag_table_create(max_flow_num, IP_FRAG_TBL_BUCKET_ENTRIES,
                                                  max_entries, frag_cycles, socket)) == NULL)
    {
        printf("ip_frag_tbl_create(%u) on lcore: %u for queue: %u failed\n", max_flow_num, lcore,
               queue);
        return -1;
    }
    /* >8 End of holding packet fragmentation. */

    /*
     * At any given moment up to <max_flow_num * (MAX_FRAG_NUM)>
     * mbufs could be stored int the fragment table.
     * Plus, each TX queue can hold up to <max_flow_num> packets.
     */

    /* mbufs stored int the fragment table. 8< */
    nb_mbuf = RTE_MAX(max_flow_num, 2UL * MAX_PKT_BURST) * MAX_FRAG_NUM;
    nb_mbuf *= (port_mtu + RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN + BUF_SIZE - 1) / BUF_SIZE;
    nb_mbuf *= 2; /* ipv4 and ipv6 */
    nb_mbuf += nb_rxd + nb_txd;

    nb_mbuf = RTE_MAX(nb_mbuf, (uint32_t)NB_MBUF);

    snprintf(buf, sizeof(buf), "mbuf_pool_%u_%u", lcore, queue);

    rxq->pool =
        rte_pktmbuf_pool_create(buf, nb_mbuf, MEMPOOL_CACHE_SIZE, 0, MBUF_DATA_SIZE, socket);
    if (rxq->pool == NULL) {
        printf("rte_pktmbuf_pool_create(%s) failed\n", buf);
        return -1;
    }
    /* >8 End of mbufs stored int the fragmentation table. */

    return 0;
}

int main(int argc, char *argv[]) {

    /* Initialize DPDK */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "error with EAL initialization\n");
    }
    printf("Eal Init OK\n");

    /* Read arguments from cmd and check */
    argc -= ret;
    role_t role;
    if (argc != 2) {
        printf("Usage_1 (argc=%d): %s <-s|-r>\n", argc, argv[ret]);
        exit(1);
    }
    if (!strncmp(argv[ret + 1], "-s", 2)) {
        role = sender;
    } else if (!strncmp(argv[ret + 1], "-r", 2)) {
        role = receiver;
    } else {
        printf("Usage_2: %s <-s|-r>\n", argv[ret]);
        exit(1);
    }

    /* Allocate the mempool for the source data */
    uint16_t            max_mbuf_size = /* RTE_MBUF_DEFAULT_BUF_SIZE */ 65535;
    struct rte_mempool *mbuf_pool =
        rte_pktmbuf_pool_create("mbuf_pool", 10240, 64, 0, max_mbuf_size, rte_socket_id());
    if (mbuf_pool == NULL) {
        printf("RTE_ERROR: %s\n", rte_strerror(rte_errno));
        rte_exit(EXIT_FAILURE, "cannot create the mbuf pool\n");
    }
    printf("Mempool creation OK\n");

    /* Allocate the mempool for the direct mbufs */
    struct rte_mempool *direct_mbuf_pool = rte_pktmbuf_pool_create(
        "direct_mbuf_pool", 10240, 64, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (direct_mbuf_pool == NULL) {
        printf("RTE_ERROR: %s\n", rte_strerror(rte_errno));
        rte_exit(EXIT_FAILURE, "cannot create the direct mbuf pool\n");
    }
    printf("Direct mempool creation OK\n");

    /* Allocate the mempool for the indirect mbufs */
    struct rte_mempool *indirect_mbuf_pool = rte_pktmbuf_pool_create(
        "indirect_mbuf_pool", 10240, 64, 0, /*RTE_MBUF_DEFAULT_BUF_SIZE*/ 0, rte_socket_id());
    if (indirect_mbuf_pool == NULL) {
        printf("RTE_ERROR: %s\n", rte_strerror(rte_errno));
        rte_exit(EXIT_FAILURE, "cannot create the indirect mbuf pool\n");
    }
    printf("Indirect mempool creation OK\n");

    /* Port init */
    uint16_t mtu = 1518;
    ret          = port_init(mbuf_pool, mtu);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "error with port initialization\n");
    }
    printf("Port creation OK\n");

    /* Lcore check */
    if (rte_lcore_count() > 1)
        fprintf(stderr, "\nWARNING: Too many lcores enabled. Only 1 used.\n");

    if (role == receiver) {
        fprintf(stderr, "\nCore %u receiving packets. [Ctrl+C to quit]\n", rte_lcore_id());

        int              j;
        uint16_t         nb_rx      = 0;
        uint16_t         burst_size = 32;
        uint64_t         cur_tsc;
        struct rte_mbuf *pkts_burst[burst_size];

        struct lcore_queue_conf lcore_queue_conf;
        lcore_queue_conf.n_rx_queue = 1;
        setup_queue_tbl(&lcore_queue_conf.rx_queue_list[0], 0, 0, mtu); // pool and tbl
        lcore_queue_conf.rx_queue_list[0].portid = 0;

        /* Start receive loop */
        struct rte_mbuf *reassembled;
        for (;;) {
            cur_tsc = rte_rdtsc();

            nb_rx = rte_eth_rx_burst(0, 0, pkts_burst, burst_size);

            /* Prefetch first packets */
            for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; j++) {
                rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j], void *));
            }

            /* Process already prefetched packets */
            for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++) {
                rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j + PREFETCH_OFFSET], void *));
                reassembled = reassemble(pkts_burst[j], &lcore_queue_conf, cur_tsc);
                if (reassembled != NULL) {
                    printf("Reassembled packet of total len %d and content:\n",
                           reassembled->pkt_len);
                    print_content(reassembled);
                    printf("\n");
                }
            }

            /* Process remaining prefetched packets */
            for (; j < nb_rx; j++) {
                reassembled = reassemble(pkts_burst[j], &lcore_queue_conf, cur_tsc);
                if (reassembled != NULL) {
                    printf("Reassembled packet of total len %d and content:\n",
                           reassembled->pkt_len);
                    print_content(reassembled);
                    printf("\n");
                }
            }

            // rte_ip_frag_free_death_row(&lcore_queue_conf.death_row, PREFETCH_OFFSET);
        }
        {
            // for (j = 0; j < nb_rx; j++) {
            //     eth_hdr_t *ehdr = rte_pktmbuf_mtod(pkts_burst[j], eth_hdr_t *);

            //     /* Check the received IP header */
            //     ip_hdr_t *ih_recv = (ip_hdr_t *)(ehdr + 1);
            //     ih_recv->len         = ntohs(ih_recv->len);
            //     ih_recv->id          = ntohs(ih_recv->id);
            //     ih_recv->dst_addr    = ntohl(ih_recv->dst_addr);
            //     ih_recv->src_addr    = ntohl(ih_recv->src_addr);
            //     ih_recv->frag_offset = ntohs(ih_recv->frag_offset);
            //     IP_DEBUG("", ih_recv);

            //     /* Print the received content */
            //     char *payload = (char *)(ih_recv + 1);
            //     printf("Received packet or fragment of lenght %d and content:\n%s\n",
            //            pkts_burst[j]->pkt_len, payload);
            //     rte_pktmbuf_free(pkts_burst[j]);
            // }
        }

    } else if (role == sender) {
        fprintf(stderr, "\nCore %u ready to send packets. [Ctrl+D to quit]\n", rte_lcore_id());

        char     buf[64];
        int      payload_size;
        int      i     = 0;
        int      error = 0;
        uint16_t nb_tx = 0;

        /* Mbuf for send operations */
        struct rte_mbuf *tx_buf;

        /* Mbufs for the fragmentation */
        struct rte_mbuf *pkts_out[64];
        int              used_mbufs = 0;

        /* Start send loop */
        printf("Insert an amount of bytes to send out: ");
        while (fgets((char *restrict)&buf, 64, stdin) != NULL) {
            payload_size = atoi((const char *)&buf);

            /* Allocate 1 packet space and get pointer to payload */
            tx_buf = rte_pktmbuf_alloc(mbuf_pool);
            if (tx_buf == NULL) {
                printf("Packet buffer allocation failed\n");
            }

            prepare_packet(tx_buf, payload_size, i);

            // Case 1: fragmentation
            if (tx_buf->pkt_len > mtu) {
                rte_pktmbuf_adj(tx_buf, (uint16_t)sizeof(eth_hdr_t));
                if ((used_mbufs = rte_ipv4_fragment_packet(tx_buf, (struct rte_mbuf **)pkts_out, 64,
                                                           RTE_ETHER_MTU, direct_mbuf_pool,
                                                           indirect_mbuf_pool)) < 0)
                {
                    printf("Error number: %d\n", used_mbufs);
                    rte_exit(EXIT_FAILURE, "error during the fragmentation process\n");
                }

                /* Print the sizes of the sent fragments */
                printf("Successfully fragmented the segment in %d fragments of sizes: [ ",
                       used_mbufs);
                for (int j = 0; j < used_mbufs; j++) {
                    printf("%d ", pkts_out[j]->pkt_len);
                }
                printf("]\n");

                /* Add the Ethernet header to each fragment */
                struct rte_mbuf *m;
                for (int j = 0; j < used_mbufs; j++) {
                    m = pkts_out[j];

                    eth_hdr_t *hdr_frag =
                        (eth_hdr_t *)rte_pktmbuf_prepend(m, (uint16_t)sizeof(eth_hdr_t));

                    if (!hdr_frag) {
                        printf("Error: no headroom in mbuf!\n");
                        error = 1;
                        break;
                    }

                    // clang-format off
                    hdr_frag->src_mac[0] = 0x00; hdr_frag->src_mac[1] = 0x00; hdr_frag->src_mac[2] = 0x00;
                    hdr_frag->src_mac[3] = 0x00; hdr_frag->src_mac[4] = 0x00; hdr_frag->src_mac[5] = 0x00;
                    hdr_frag->dst_mac[0] = 0xff; hdr_frag->dst_mac[1] = 0xff; hdr_frag->dst_mac[2] = 0xff;
                    hdr_frag->dst_mac[3] = 0xff; hdr_frag->dst_mac[4] = 0xff; hdr_frag->dst_mac[5] = 0xff;
                    hdr_frag->ether_type = ETHERNET_P_IP;
                    // clang-format on

                    m->ol_flags = RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4;
                    m->l2_len   = sizeof(eth_hdr_t);

                    // ip_hdr_t *ih        = (ip_hdr_t *)(hdr_frag + 1);
                    // ip_hdr_t  ih_recv   = {0};
                    // ih_recv.len         = ntohs(ih->len);
                    // ih_recv.id          = ntohs(ih->id);
                    // ih_recv.dst_addr    = ntohl(ih->dst_addr);
                    // ih_recv.src_addr    = ntohl(ih->src_addr);
                    // ih_recv.frag_offset = ntohs(ih->frag_offset);
                    // IP_DEBUG("", &ih_recv);

                    // uint8_t *dio = (uint8_t *)(hdr_frag);
                    // printf("HEADERS\n");
                    // for (size_t i = 0; i < ETHERNET_HEADER_LEN + IP_HEADER_LEN; i += 2) {
                    //     printf("%02X%02X ", dio[i], dio[i + 1]);
                    // }
                    // printf("\n\n");

                    // ip_hdr_t *ih        = (ip_hdr_t *)(hdr_frag + 1);
                    // ip_hdr_t  ih_recv   = *ih;
                    // ih_recv.len         = ntohs(ih->len);
                    // ih_recv.id          = ntohs(ih->id);
                    // ih_recv.dst_addr    = ntohl(ih->dst_addr);
                    // ih_recv.src_addr    = ntohl(ih->src_addr);
                    // ih_recv.frag_offset = ntohs(ih->frag_offset);
                    // ih_recv.csum        = ntohs(ih->csum);
                    // IP_DEBUG("IP header", &ih_recv);

                    // char *content =
                    //     rte_pktmbuf_mtod(tx_buf, char *) + ETHERNET_HEADER_LEN + IP_HEADER_LEN;
                    // content[m->pkt_len] = '\0';
                    printf("Fragment with length %d\n", m->pkt_len);
                }
                if (error) {
                    error = 0;
                    printf("Insert an amount of bytes to send out: ");
                    continue;
                }

                /* Send all the fragments in a burst */
                nb_tx = rte_eth_tx_burst(0, 0, (struct rte_mbuf **)pkts_out, used_mbufs);
                printf("Successfully sent %d fragments\n", used_mbufs);
            } else { // Case 2: no fragmentation
                tx_buf->next    = NULL;
                tx_buf->nb_segs = 1;

                // Send an mbuf of size dim
                nb_tx = rte_eth_tx_burst(0, 0, &tx_buf, 1);
                printf("Sent %u packet of size %d\n", nb_tx, payload_size);
            }
            /* Free the mbuf */
            printf("Insert an amount of bytes to send out: ");
            rte_pktmbuf_free(tx_buf);
            i++;
        }
    }
}