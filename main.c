// INSANEv 0.1

#define _GNU_SOURCE
#include <pthread.h>

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include "arp.h"
#include "cmsg.h"
#include "common.h"
#include "insane_priv.h"
#include "ip.h"
#include "mem_manager.h"
#include "udp.h"

#include "runtime.h"

#include <insane/buffer.h>

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS       8191
#define MBUF_CACHE_SIZE 250
#define RX_BURST_SIZE   MAX_PKT_BURST_RX
#define TX_BURST_SIZE   64

#define ETHERNET_P_LOOP  0x0060 /* Ethernet Loopback packet	*/
#define ETHERNET_P_TSN   0x22F0 /* TSN (IEEE 1722) packet	*/
#define ETHERNET_P_IP    0x0800 /* Internet Protocol packet	*/
#define ETHERNET_P_ARP   0x0806 /* Address Resolution packet	*/
#define ETHERNET_P_8021Q 0x8100 /* 802.1Q VLAN Extended Header  */
#define ETHERNET_P_IPV6  0x86DD /* IPv6 over bluebook		*/

#define INSANE_PORT 9999

volatile bool queue_stop = false;
volatile bool g_running  = true;
static bool   trace_time = false;

// TODO(garbu): put statistics in a better place.
static i64 g_pkts_counter_rx = 0;

void handle(int signum) {
    LOG_DEBUG("Received CTRL+C. Exiting!");
    g_running  = false;
    queue_stop = true;
}

static inline int port_init(nsn_runtime_t *nsnrt, struct rte_mempool *mempool, char *l_ip_dpdk,
                            char *d_ip_dpdk, u32 mtu) {
    int valid_port = rte_eth_dev_is_valid_port(nsnrt->port_id);
    if (!valid_port)
        return -1;

    struct rte_eth_dev_info dev_info;
    int                     retval = rte_eth_dev_info_get(nsnrt->port_id, &dev_info);
    if (retval != 0) {
        fprintf(stderr, "[error] cannot get device (port %u) info: %s\n", nsnrt->port_id,
                strerror(-retval));
        return retval;
    }
    uint16_t actual_mtu = RTE_MIN(mtu, dev_info.max_mtu);

    struct rte_eth_conf port_conf;
    memset(&port_conf, 0, sizeof(port_conf));
    port_conf.rxmode.mtu = actual_mtu;
    port_conf.rxmode.offloads |= (RTE_ETH_RX_OFFLOAD_CHECKSUM | RTE_ETH_RX_OFFLOAD_SCATTER);
    port_conf.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;
    port_conf.txmode.offloads |= (RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_MULTI_SEGS);
    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
    }

    const uint16_t rx_rings = 1, tx_rings = 1;
    retval = rte_eth_dev_configure(nsnrt->port_id, rx_rings, tx_rings, &port_conf);
    if (retval != 0) {
        return retval;
    }

    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    retval          = rte_eth_dev_adjust_nb_rx_tx_desc(nsnrt->port_id, &nb_rxd, &nb_txd);
    if (retval != 0) {
        return retval;
    }

    int socket_id = rte_eth_dev_socket_id(nsnrt->port_id);

    // struct rte_eth_rxconf rxq_config = dev_info.default_rxconf;
    for (uint16_t q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(nsnrt->port_id, q, nb_rxd, socket_id, NULL, mempool);
        if (retval != 0) {
            return retval;
        }
    }

    struct rte_eth_txconf txconf = dev_info.default_txconf;
    txconf.offloads              = port_conf.txmode.offloads;
    for (uint16_t q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(nsnrt->port_id, q, nb_txd, socket_id, &txconf);
        if (retval != 0) {
            return retval;
        }
    }

    retval = rte_eth_dev_start(nsnrt->port_id);
    if (retval != 0) {
        return retval;
    }

    struct rte_ether_addr ether_addr;
    rte_eth_macaddr_get(nsnrt->port_id, &ether_addr);

    // TODO(garbu): these devices are used only for testing.

    nsnrt->dev = netdev__init(l_ip_dpdk, "00:00:00:00:00:00", actual_mtu);
    if (!nsnrt->dev) {
        LOG_WARN("cannot init source device");
        return -1;
    }

    nsnrt->dst_dev = netdev__init(d_ip_dpdk, "00:00:00:00:00:00", actual_mtu);
    if (!nsnrt->dst_dev) {
        LOG_WARN("cannot init dest device: ip = %s\tmac = %s", d_ip_dpdk);
        return -1;
    }

    LOG_DEBUG("MAC = " RTE_ETHER_ADDR_PRT_FMT, RTE_ETHER_ADDR_BYTES(&ether_addr));

    memcpy(&(nsnrt->dev->hw_addr), &ether_addr, ETHERNET_ADDRESS_LEN);

    retval = rte_eth_promiscuous_enable(nsnrt->port_id);
    if (retval != 0) {
        return retval;
    }

    return 0;
}
typedef struct arguments {
    char   l_ip_dpdk[16];
    char   d_ip_dpdk[16];
    char   l_ip_sk[16];
    char   d_ip_sk[16];
    u32    mtu;
    int    argc;
    char **argv;
} arguments_t;

static i64 g_pkts_counter_tx = 0;

static u32 flush_tx_queue_batch(nsn_runtime_t *nsnrt) { // DPDK only!!
    nsn_buffer_t bufs[TX_BURST_SIZE];
    memset(bufs, 0, sizeof(bufs));

    nsn_memmanager_t *mm = &nsnrt->mem_manager;

    i64 tmp_index[TX_BURST_SIZE];
    memset(tmp_index, 0, sizeof(tmp_index));
    u32 available;
    u32 n_bufs = rte_ring_dequeue_burst(mm->tx_info[mempool_dpdk].tx_prod, (void **)tmp_index,
                                        TX_BURST_SIZE, &available);
    if (n_bufs == 0) { // No packet available
        return n_bufs;
    }

    // i64 start = get_clock_realtime_ns();

    struct rte_mbuf *rte_mbufs[TX_BURST_SIZE];
    memset(rte_mbufs, 0, sizeof(rte_mbufs));
    for (u32 i = 0; i < n_bufs; i++) {
        bufs[i].index = tmp_index[i];
        bufs[i].data  = (u8 *)mm->dpdk_ctx->tx_mbuf[bufs[i].index];

        rte_mbufs[i]       = (struct rte_mbuf *)bufs[i].data;
        nsn_pktmeta_t meta = mm->tx_info[mempool_dpdk].tx_meta[bufs[i].index];
        u8           *data = rte_pktmbuf_mtod(rte_mbufs[i], u8 *);

        switch (meta.proto) {
        case nsn_proto_ipv4_udp:
            udp_send(nsnrt, data, &meta);
            rte_mbufs[i]->pkt_len =
                meta.payload_len + ETHERNET_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN;
            break;
        case nsn_proto_arp:
            rte_mbufs[i]->pkt_len = ETHERNET_HEADER_LEN + ARP_HEADER_LEN;
            break;
        }

        rte_mbufs[i]->next     = NULL;
        rte_mbufs[i]->data_len = rte_mbufs[i]->pkt_len;
        rte_mbufs[i]->nb_segs  = 1;
    }

    // i64 end = get_clock_realtime_ns();
    // if (trace_time)
    //     printf("elapsed time: %ld\n", end - start);

    i32 ret = rte_eth_tx_burst(nsnrt->port_id, nsnrt->queue_id, rte_mbufs, n_bufs);

    g_pkts_counter_tx += ret;

    LOG_TRACE("flush_tx_queue - tx burst = %d\ttotal = %ld", ret, g_pkts_counter_tx);

    /* NOTE(lr): Re-alloc the pktmbuf that were sent? */

    /* Set packet-ready flag to -1*/
    while (rte_ring_enqueue_bulk(mm->tx_info[mempool_dpdk].tx_cons, (void *)tmp_index, n_bufs,
                                 &available) != n_bufs)
    {
        SPIN_LOOP_PAUSE();
    }

    return n_bufs;
}

static void flush_tx_queue(nsn_runtime_t *nsnrt) {
    nsn_buffer_t buf;
    i32          ret = mem_manager__consume(&nsnrt->mem_manager, false, &buf, mempool_dpdk);
    if (ret < 0) {
        return;
    }

    // i64 start = get_clock_realtime_ns();

    // TODO(lr): This has to become a separate packet processing routine
    struct rte_mbuf *rte_mbuf = nsnrt->mem_manager.dpdk_ctx->tx_mbuf[buf.index];
    nsn_pktmeta_t    meta     = nsnrt->mem_manager.tx_info[mempool_dpdk].tx_meta[buf.index];
    u8              *data     = rte_pktmbuf_mtod(rte_mbuf, u8 *);
    switch (meta.proto) {
    case nsn_proto_ipv4_udp:
        udp_send(nsnrt, data, &meta);
        rte_mbuf->pkt_len = meta.payload_len + ETHERNET_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN;
        break;
    case nsn_proto_arp:
        rte_mbuf->pkt_len = ETHERNET_HEADER_LEN + ARP_HEADER_LEN;
        break;
    }

    rte_mbuf->next     = NULL;
    rte_mbuf->data_len = rte_mbuf->pkt_len;
    rte_mbuf->nb_segs  = 1;

    // i64 end = get_clock_realtime_ns();
    // if (trace_time)
    //     printf("elapsed time: %ld\n", end - start);

    ret = rte_eth_tx_burst(nsnrt->port_id, nsnrt->queue_id, &rte_mbuf, 1);

    g_pkts_counter_tx += ret;

    LOG_TRACE("flush_tx_queue - tx burst = %d\ttotal = %ld", ret, g_pkts_counter_tx);

    /* NOTE(lr): Re-alloc the pktmbuf that were sent? */

    /* Set packet-ready flag to -1*/
    mem_manager__release(&nsnrt->mem_manager, &buf, mempool_dpdk);
}

static void lcore_main(nsn_runtime_t *nsnrt) {
    if (rte_eth_dev_socket_id(nsnrt->port_id) >= 0 &&
        rte_eth_dev_socket_id(nsnrt->port_id) != (int)rte_socket_id())
    {
        fprintf(stderr,
                "WARNING: port %u is on remote NUMA node "
                "to polling thread.\n"
                "\tPerformance will not be optimal.\n",
                nsnrt->port_id);
    }

    fprintf(stderr, "\nCore %u forwarding packets. [Ctrl+C to quit]\n", rte_lcore_id());

    nsn_ioctx_dpdk_t *ctx = nsnrt->mem_manager.dpdk_ctx;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    u64  now_time  = now.tv_sec * 1000000000 + now.tv_nsec;
    u64  last_time = now_time;
    bool free_pkt  = false;

    while (g_running) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        now_time = now.tv_sec * 1000000000 + now.tv_nsec;

        if (now_time - last_time >= 1000000000) {
            last_time  = now_time;
            trace_time = true;
        }

        u32 nb_bufs_freed = 0;
        for (i32 s = 0; s < nsnrt->mem_manager.n_sinks; s++) {
            if (nsnrt->mem_manager.rx_queues[s].mptype == mempool_dpdk) {
                i32 idx       = -1;
                u32 available = 0;
                i64 tmp_index[8];
                do {

                    u32 nb_bufs = rte_ring_dequeue_burst(nsnrt->mem_manager.rx_queues[s].cons,
                                                         (void **)tmp_index, 8, &available);
                    for (u32 i = 0; i < nb_bufs; i++) {
                        idx = tmp_index[i];
                        if (rte_mbuf_refcnt_update(ctx->rx_mbuf[idx], -1) == 1) {
                            rte_pktmbuf_free(ctx->rx_mbuf[idx]);
                            ctx->rx_chunks[idx / MAX_PKT_BURST_RX] -= 1;
                        }
                    }

                    nb_bufs_freed += nb_bufs;
                } while (available);

                // i32 idx = -1;
                // while (rte_ring_dequeue(nsnrt->mem_manager.rx_queues[s].cons, (void **)&idx) >=
                // 0) {
                //     LOG_TRACE("Free pktmbuf at index %d belonging to chunk %d", idx,
                //               idx / MAX_PKT_BURST_RX);
                //     rte_pktmbuf_free(ctx->rx_mbuf[idx]);
                //     ctx->rx_chunks[idx / MAX_PKT_BURST_RX] -= 1;
                // }
            }
        }

        int    mbuf_index  = -1;
        size_t chunk_index = 0;
        bool   free_chunk  = false;
        for (; chunk_index < N_CHUNKS; chunk_index++) {
            if (ctx->rx_chunks[chunk_index] == 0) {
                mbuf_index = RX_BURST_SIZE * chunk_index;
                free_chunk = true;
                break;
            }
        }

        if (free_chunk) {
            u16 nb_rx = rte_eth_rx_burst(nsnrt->port_id, nsnrt->queue_id, &ctx->rx_mbuf[mbuf_index],
                                         RX_BURST_SIZE);

            ctx->rx_chunks[chunk_index] = nb_rx;

            if (nb_rx != 0) {
                g_pkts_counter_rx += nb_rx;
                LOG_TRACE("rte_eth_rx_burst: %u packets received\ttotal %ld", nb_rx,
                          g_pkts_counter_rx);

                for (size_t rx = 0; rx < nb_rx; rx++) {
                    int              queue_index = mbuf_index + rx;
                    struct rte_mbuf *buf         = ctx->rx_mbuf[queue_index];

                    u8 *pktbuf = rte_pktmbuf_mtod(buf, u8 *);

                    // Ethernet
                    eth_hdr_t *ethh = (eth_hdr_t *)pktbuf;
                    switch (ntohs(ethh->ether_type)) {
                    case ETHERNET_P_ARP:
                        arp_receive(nsnrt, pktbuf);
                        free_pkt = true;
                        break;
                    case ETHERNET_P_IP: {
                        nsn_hdr_t *nhdr = (nsn_hdr_t *)ip_receive(nsnrt, pktbuf);
                        if (!nhdr) {
                            free_pkt = true;
                            LOG_WARN("dropping ip/udp packet");
                            break;
                        }

                        // 1) TODO: move this to a more appropriate file AND find a way to
                        // dispatch the incoming packets to the correct queues!
                        // Get destination port ( uh->udp_dport; ) and send data

                        // 2) TODO: should we use try_push instead of push? And avoid blocking here
                        // forever?

                        // 3) TODO: reason about the efficiency of this implementation
                        LOG_TRACE("received msg from source = %ld\n", nhdr->source_id);

                        i32 n_sinks = nsnrt->mem_manager.n_sinks;
                        i32 refs    = 0;
                        if (n_sinks > 0) {
                            for (i32 i = 0; i < n_sinks; i++) {
                                if (nsnrt->mem_manager.rx_queues[i].source_id == nhdr->source_id) {
                                    LOG_TRACE("source = %ld, sink = %lu, queue_idx = %ld",
                                              nhdr->source_id, i, queue_index);
                                    while (rte_ring_enqueue(nsnrt->mem_manager.rx_queues[i].prod,
                                                            (void *)(i64)queue_index) < 0)
                                    {
                                        SPIN_LOOP_PAUSE();
                                    }
                                    refs++;
                                }
                            }
                            rte_mbuf_refcnt_update(buf, refs);
                        } else {
                            free_pkt = true;
                        }
                    } break;
                    default:
                        free_pkt = true;
                    }

                    if (free_pkt) {
                        rte_pktmbuf_free(buf);
                        ctx->rx_chunks[chunk_index] -= 1;
                        free_pkt = false;
                    }
                }
            }
        }

        // TODO(garbu): handle ARP stuff in a better way
        if (trace_time) {
            u8 *dmac = arp_get_hwaddr(nsnrt->dst_dev->addr);
            if (!dmac) {
                arp_request(nsnrt, nsnrt->dev->addr, nsnrt->dst_dev->addr);
            }
        }

        /* Transmit the packets waiting in queue */
        // flush_tx_queue(nsnrt);
        flush_tx_queue_batch(nsnrt);

        trace_time = false;
    }
}

int open_unix_socket(const char *path, bool master) {
    int sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        LOG_ERROR("cannot open unix socket");
        return -1;
    }

    if (master) {
        struct sockaddr_un addr;
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

        if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
            LOG_ERROR("cannot bind unix socket '%s': %s", path, strerror(errno));
            return -1;
        }
    }

    return sockfd;
}

typedef struct ctrlpath_arg {
    int            sockfd;
    nsn_runtime_t *rt;
} ctrlpath_arg_t;

#define REQUEST_IPC_PATH "/tmp/insane_control.socket"
#define SHM_NAME         "insane"
#define SHM_SOCKET_NAME  "insane_socketmempool"

void *control_path(void *arg) {
    ctrlpath_arg_t   *cp = (ctrlpath_arg_t *)arg;
    nsn_memmanager_t *mm = (nsn_memmanager_t *)&(cp->rt->mem_manager);

    cmsg_t cmsg;
    memset(&cmsg, 0, sizeof(cmsg));

    struct sockaddr_un addr;
    socklen_t          addr_len = sizeof(addr);

    int  ret   = 0;
    bool reply = false;
    while (g_running) {
        ret = recvfrom(cp->sockfd, &cmsg, sizeof(cmsg_t), 0, (struct sockaddr *)&addr, &addr_len);
        if (ret < 0) {
            usleep(1000 * 20);
            continue;
        }

        switch (cmsg.type) {
        case mtype_init: {
            cmsg_init_t *p = (cmsg_init_t *)cmsg.payload;

            LOG_DEBUG("[ctrlpath] app with pid %d is requesting a new connection", cmsg.appid);

            nsn_appid_t new_appid       = cp->rt->n_apps++;
            cp->rt->apps_ipc[new_appid] = cmsg.appid;

            cmsg.appid = new_appid;

            p->shm_size = TOTAL_SHM_SIZE;
            p->tx[mempool_dpdk].cons_offset =
                ((u8 *)mm->tx_info[mempool_dpdk].tx_cons - mm->info.buffer);
            p->tx[mempool_dpdk].prod_offset =
                ((u8 *)mm->tx_info[mempool_dpdk].tx_prod - mm->info.buffer);
            p->tx[mempool_dpdk].meta_offset =
                ((u8 *)mm->tx_info[mempool_dpdk].tx_meta - mm->info.buffer);
            p->ioctx_dpdk_offset = ((u8 *)mm->dpdk_ctx - mm->info.buffer);

            p->tx[mempool_socket].cons_offset =
                ((u8 *)mm->tx_info[mempool_socket].tx_cons - mm->info.buffer);
            p->tx[mempool_socket].prod_offset =
                ((u8 *)mm->tx_info[mempool_socket].tx_prod - mm->info.buffer);
            p->tx[mempool_socket].meta_offset =
                ((u8 *)mm->tx_info[mempool_socket].tx_meta - mm->info.buffer);

            strncpy(p->shm_name, SHM_NAME, SHM_MAX_PATH - 1);

            p->shm_socket_size = SOCKET_POOL_SIZE;
            strncpy(p->shm_socket_name, SHM_SOCKET_NAME, SHM_MAX_PATH - 1);

            reply = true;
        } break;
        case mtype_alloc_rxqueue: {
            cmsg_alloc_rxqueue_t *p = (cmsg_alloc_rxqueue_t *)cmsg.payload;
            LOG_DEBUG("[ctrlpath] app with id %d is requesting a new rx queue", cmsg.appid);
            // Allocate the queue, but only if there is enough space
            i64 queue_size = (sizeof(nsn_queue_t) + sizeof(i32a) * (MAX_PKT_BURST));
            if ((cp->rt->mem_manager.info.used_memory + (2 * queue_size)) >
                cp->rt->mem_manager.info.shm_size)
            {
                LOG_ERROR("Error: total memory for index queues exceeded");
                cmsg.error = -1;
                p          = NULL;
            } else {

                u64 sink_id = cp->rt->mem_manager.n_sinks;
                p->sink_id  = sink_id;

                // mm->rx_queues[sink_id].prod =
                //     (nsn_queue_t *)(mm->info.buffer + mm->info.used_memory);
                // mm->info.used_memory += queue_size;

                // mm->rx_queues[sink_id].cons =
                //     (nsn_queue_t *)(mm->info.buffer + mm->info.used_memory);
                // mm->info.used_memory += queue_size;

                // p->offset_prod = ((u8 *)mm->rx_queues[sink_id].prod - mm->info.buffer);
                // p->offset_cons = ((u8 *)mm->rx_queues[sink_id].cons - mm->info.buffer);

                mm->rx_queues[sink_id].source_id = p->source_id;

                cmsg.error = 0;

                char qprod_name[MAX_QUEUE_NAME_SIZE];
                snprintf(qprod_name, MAX_QUEUE_NAME_SIZE, "rx_prod_%ld", sink_id);
                char qcons_name[MAX_QUEUE_NAME_SIZE];
                snprintf(qcons_name, MAX_QUEUE_NAME_SIZE, "rx_cons_%ld", sink_id);

                strncpy(p->cons_name, qcons_name, MAX_QUEUE_NAME_SIZE);
                strncpy(p->prod_name, qprod_name, MAX_QUEUE_NAME_SIZE);

                // int ret1 = nsn_queue__init(mm->rx_queues[sink_id].prod, qprod_name,
                // MAX_PKT_BURST,
                //                            nsn_qtype_spsc);
                // int ret2 = nsn_queue__init(mm->rx_queues[sink_id].cons, qcons_name,
                // MAX_PKT_BURST,
                //                            nsn_qtype_spsc);

                const unsigned flags     = RING_F_SP_ENQ | RING_F_SC_DEQ;
                const unsigned ring_size = MAX_PKT_BURST;

                struct rte_ring *prod =
                    rte_ring_create(qprod_name, ring_size, rte_socket_id(), flags);
                struct rte_ring *cons =
                    rte_ring_create(qcons_name, ring_size, rte_socket_id(), flags);

                if (!prod || !cons) {
                    LOG_ERROR("Error initializing one of the RX queues for the requested sink");
                    cmsg.error = !prod ? -1 : -2;
                }

                mm->rx_queues[sink_id].prod = prod;
                mm->rx_queues[sink_id].cons = cons;

                // Set the SINK MPTYPE
                mm->rx_queues[sink_id].mptype = p->mptype;

                // After this, the sink is active
                cp->rt->mem_manager.n_sinks++;
            }
            reply = true;
        } break;
        }

        // Send the reply
        if (reply &&
            sendto(cp->sockfd, &cmsg, sizeof(cmsg), 0, (struct sockaddr *)&addr, addr_len) < 0)
        {
            LOG_ERROR("cannot send reply for cmsg_init: %s", strerror(errno));
        }

        reply = false;
        memset(&cmsg, 0, sizeof(cmsg));
    }

    return 0;
}

typedef struct datapath_arg {
    arguments_t   *args;
    nsn_runtime_t *rt;
} datapath_arg_t;

int do_dpdk(void *arguments) {
    nsn_runtime_t *nsn_runtime = ((datapath_arg_t *)arguments)->rt;
    arguments_t   *args        = ((datapath_arg_t *)arguments)->args;

    // int ret = 0;
    // ret     = rte_eal_init(args->argc, args->argv);
    // if (ret < 0) {
    //     rte_exit(EXIT_FAILURE, "error with EAL initialization\n");
    // }

    /* Check available ports */
    uint16_t nb_ports = rte_eth_dev_count_avail();
    if (nb_ports < 1)
        rte_exit(EXIT_FAILURE, "error: need at least 1 port\n");

    printf("############### PORTS: %d\n", nb_ports);

    /* Allocate the membuf */
    struct rte_mempool *mbuf_pool =
        rte_pktmbuf_pool_create("mbuf_pool", NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
                                RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "cannot create the mbuf pool\n");
    }

    mem_manager__add_mempool(&nsn_runtime->mem_manager, mbuf_pool, mempool_dpdk);

    uint16_t port_id     = 0; // rte_eth_find_next_owned_by(0, RTE_ETH_DEV_NO_OWNER);
    nsn_runtime->port_id = port_id;

    /* Queue used for tranmission: always queue #0 */
    nsn_runtime->queue_id = 0;

    /* Init port */
    int res = port_init(nsn_runtime, mbuf_pool, args->l_ip_dpdk, args->d_ip_dpdk, args->mtu);
    if (res == -1) {
        fprintf(stderr, "cannot init port %u\n", nsn_runtime->port_id);
        goto exit;
    }

    if (rte_lcore_count() > 1)
        fprintf(stderr, "\nWARNING: Too many lcores enabled. Only 1 used.\n");

    lcore_main(nsn_runtime);

exit:
    // rte_eal_cleanup();
    return 0;
}

static int64_t g_total_msg_sent_socket = 0;
static int64_t g_total_msg_recv_socket = 0;

void *do_socket(void *arguments) {
    if (!arguments) {
        return NULL;
    }
    nsn_runtime_t *nsnrt = ((datapath_arg_t *)arguments)->rt;
    arguments_t   *args  = ((datapath_arg_t *)arguments)->args;

    // Memory area for socket data
    nsn_meminfo_t sk_mempool;
    memset(&sk_mempool, 0, sizeof(nsn_meminfo_t));
    strncpy(sk_mempool.shm_name, SHM_SOCKET_NAME, SHM_MAX_PATH);

    sk_mempool.shm_fd = shm_open(sk_mempool.shm_name, O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IRUSR);
    if (sk_mempool.shm_fd == -1) {
        LOG_ERROR("shm_open: %s (%s)", strerror(errno), sk_mempool.shm_name);
        return NULL;
    }

    sk_mempool.shm_size = SOCKET_POOL_SIZE;
    if (ftruncate(sk_mempool.shm_fd, sk_mempool.shm_size) == -1) {
        LOG_ERROR("ftruncate: %s (%s)", strerror(errno), sk_mempool.shm_name);
        return NULL;
    }

    sk_mempool.buffer = (u8 *)mmap(NULL, sk_mempool.shm_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                                   sk_mempool.shm_fd, 0);
    if (sk_mempool.buffer == MAP_FAILED) {
        LOG_ERROR("mmap: %s (%s)", strerror(errno), sk_mempool.shm_name);
        return NULL;
    }

    mem_manager__add_mempool(&(nsnrt->mem_manager), &sk_mempool, mempool_socket);

    /* Open the UDP socket */
    struct sockaddr_in l_addr, d_addr;

    l_addr.sin_family = AF_INET;
    l_addr.sin_port   = htons(nsnrt->daemon_udp_port);
    inet_aton(args->l_ip_sk, &l_addr.sin_addr);

    d_addr.sin_family = AF_INET;
    d_addr.sin_port   = htons(nsnrt->daemon_udp_port);
    inet_aton(args->d_ip_sk, &d_addr.sin_addr);

    int sd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (sd < 0) {
        LOG_ERROR("Open socket for data: %s", strerror(errno));
        exit(1);
    }

    int ok = 1;
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (void *)&ok, sizeof(ok));

    int buffer = 4000000;
    // setsockopt(sd, SOL_SOCKET, SO_SNDBUF, buffer, sizeof(buffer));
    setsockopt(sd, SOL_SOCKET, SO_RCVBUF, &buffer, sizeof(buffer));

    if (bind(sd, (struct sockaddr *)&l_addr, sizeof(l_addr)) < 0) {
        LOG_ERROR("Bind socket: %s", strerror(errno));
        exit(1);
    }

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    u64  now_time   = now.tv_sec * 1000000000 + now.tv_nsec;
    u64  last_time  = now_time;
    bool trace_time = false;

    /* Start networking loop */
    ssize_t             nb_rx = 0;
    nsn_ioctx_socket_t *ctx   = &(nsnrt->mem_manager.socket_ctx);
    int                 index = -1;
    bool                sent  = true;
    while (g_running) {

        clock_gettime(CLOCK_MONOTONIC, &now);
        now_time = now.tv_sec * 1000000000 + now.tv_nsec;

        if (now_time - last_time >= 1000000000) {
            last_time  = now_time;
            trace_time = true;
        }

        /* Collect free indexes from sink queues */
        for (i32 s = 0; s < nsnrt->mem_manager.n_sinks; s++) {
            if (nsnrt->mem_manager.rx_queues[s].mptype == mempool_socket) {
                // i32a idx = nsn_queue__try_pop(nsnrt->mem_manager.rx_queues[s].cons);
                i32 idx;
                while (rte_ring_dequeue(nsnrt->mem_manager.rx_queues[s].cons, (void **)&idx) >= 0) {
                    // if (idx >= 0) {
                    LOG_TRACE("Free sk_buf at index %d", idx);
                    // nsn_queue__push(ctx->free_rx_idx, idx);
                    rte_ring_enqueue(ctx->free_rx_idx, (void *)(i64)idx);
                }
            }
        }

        /* Receive action */
        if (sent) {
            // index = nsn_queue__try_pop(ctx->free_rx_idx);
            rte_ring_dequeue(ctx->free_rx_idx, (void **)&index);
            sent = false;
        }

        if (index >= 0) {
            /* Non-blocking receive from socket */
            nb_rx = recvfrom(sd, ctx->rx_mbuf[index], sizeof(struct nsn_mbuf), 0, NULL, NULL);
            if (nb_rx > 0) {
                sent = true;
                g_total_msg_recv_socket++;

                // Get header to find the source id for packet dispatching
                nsn_hdr_t *nhdr = (nsn_hdr_t *)ctx->rx_mbuf[index];
                LOG_DEBUG("Socket receive: read %u bytes for sink %ld (nsinks: %d)", nb_rx,
                          nhdr->source_id, nsnrt->mem_manager.n_sinks);

                i32 n_sinks = nsnrt->mem_manager.n_sinks;
                if (n_sinks > 0) {
                    for (i32 i = 0; i < n_sinks; i++) {
                        if (nsnrt->mem_manager.rx_queues[i].source_id == nhdr->source_id) {
                            LOG_TRACE("source = %ld, sink = %lu, queue_idx = %ld", nhdr->source_id,
                                      i, index);
                            // nsn_queue__push(nsnrt->mem_manager.rx_queues[i].prod, index);
                            rte_ring_enqueue(nsnrt->mem_manager.rx_queues[i].prod,
                                             (void *)(i64)index);
                        }
                    }
                } else {
                    // Free packet
                    // nsn_queue__push(ctx->free_rx_idx, index);
                    rte_ring_enqueue(ctx->free_rx_idx, (void *)(i64)index);
                }
            }
        } else {
            // Retry the pop
            sent = true;
        }

        /* Send action */
        nsn_buffer_t buf;
        i32          ret = mem_manager__consume(&nsnrt->mem_manager, false, &buf, mempool_socket);
        if (ret >= 0) {
            nsn_pktmeta_t    meta   = nsnrt->mem_manager.tx_info[mempool_socket].tx_meta[buf.index];
            struct nsn_mbuf *sk_buf = nsnrt->mem_manager.socket_ctx.tx_mbuf[buf.index];
            LOG_TRACE("sending message: %d", buf.index);
            ret =
                sendto(sd, sk_buf, meta.payload_len, 0, (struct sockaddr *)&d_addr, sizeof(d_addr));
            int32_t a = 0;
            while (ret < 0) {
                fflush(stdout);
                // This is a hack. No reasonable explanation. Few times in Release mode and
                // during throughput test, we read the wrong value from the vector. It seems
                // like that address is "shifted" of 0x50 wrt the correct one, so when this
                // happens we correct it back. But of course this requires more investigation.
                // TODO: fix by understanding what's going on here!
                sk_buf = (struct nsn_mbuf *)((char *)sk_buf - 0x50);
                ret    = sendto(sd, sk_buf, meta.payload_len, 0, (struct sockaddr *)&d_addr,
                                sizeof(d_addr));
                a++;
            }
            mem_manager__release(&nsnrt->mem_manager, &buf, mempool_socket);
            g_total_msg_sent_socket++;
            if (a > 0) {
                printf("%u retries\n", a);
                fflush(stdout);
            }
        }

        if (trace_time) {
            LOG_TRACE("total packet SOCKET: TX:%d\tRX:%d", g_total_msg_sent_socket,
                      g_total_msg_recv_socket);
            trace_time = false;
        }
    }

    // Cleanup
    munmap(sk_mempool.buffer, sk_mempool.shm_size);
    shm_unlink(sk_mempool.shm_name);
    close(sk_mempool.shm_fd);
    return NULL;
}

int main(int argc, char *argv[]) {
    signal(SIGINT, handle);

    // Default arguments
    arguments_t arguments;
    arguments.mtu  = 1500;
    arguments.argc = argc;
    arguments.argv = argv;

    // ANTONIO
    strncpy(arguments.l_ip_dpdk, "10.0.0.211", 15);
    strncpy(arguments.d_ip_dpdk, "10.0.0.212", 15);

    // PAOLO
    // strncpy(arguments.l_ip_dpdk, "10.0.0.212", 15);
    // strncpy(arguments.d_ip_dpdk, "10.0.0.211", 15);

    /* Get IPs as optional arguments */
    // 1 => l_ip_dpdk
    // 2 => d_ip_dpdk
    // 3 => l_ip_sk
    // 4 => d_ip_sk
    if (argc == 1 || argc == 5 || argc == 3) {
        if (argc == 5) {
            strcpy(arguments.l_ip_dpdk, argv[1]);
            strcpy(arguments.d_ip_dpdk, argv[2]);
            strcpy(arguments.l_ip_sk, argv[3]);
            strcpy(arguments.d_ip_sk, argv[4]);
        }
        if (argc == 3) {
            strcpy(arguments.l_ip_dpdk, argv[1]);
            strcpy(arguments.d_ip_dpdk, argv[2]);
        }
    } else if (argc >= 4) {
        printf("Wrong arguments.\nUsage: [local_ip_dpdk dest_ip_dpdk local_ip_sk dest_ip_sk]\n");
        return -1;
    }

    /* The runtime of our application */
    nsn_runtime_t nsn_runtime;
    memset(&nsn_runtime, 0, sizeof(nsn_runtime));
    nsn_runtime.daemon_udp_port = INSANE_PORT;

    /* Start INSANE control path*/
    int sockfd = open_unix_socket(REQUEST_IPC_PATH, true);
    int flags  = fcntl(sockfd, F_GETFL);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    ctrlpath_arg_t cparg = {
        .sockfd = sockfd,
        .rt     = &nsn_runtime,
    };

    pthread_t control_path_tid;
    if (pthread_create(&control_path_tid, NULL, control_path, (void *)&cparg) < 0) {
        LOG_ERROR("cannot create control path thread");
        g_running  = false;
        queue_stop = true;
        return -1;
    }

    datapath_arg_t dparg = {
        .args = &arguments,
        .rt   = &nsn_runtime,
    };

    /* Initialize the memory manager */
    // TODO: FIX THE DIFFERENT TX QUEUES
    int ret = mem_manager__init(&nsn_runtime.mem_manager, SHM_NAME);
    if (ret < 0) {
        LOG_ERROR("cannot initialize the memory for the application");
        g_running  = false;
        queue_stop = true;
        return -1;
    }

    // Start DPDK library to get their ring.
    // TODO: change me back
    const char *rte_args[] = {
        "-l",
        "0,1",
    };
    ret = rte_eal_init(2, rte_args);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "error with EAL initialization\n");
    }

    /* Start DPDK */
    // TODO: This should be done only at the first request of DPDK usage
    // pthread_t dpdk_thread;
    // if (pthread_create(&dpdk_thread, NULL, do_dpdk, &dparg) != 0) {
    if (rte_eal_remote_launch(do_dpdk, &dparg, rte_get_next_lcore(-1, 1, 0)) != 0) {
        LOG_ERROR("pthread_create() DPDK error");
        g_running  = false;
        queue_stop = true;
        goto exit;
    }

    /* Start Socket */
    // TODO: This should be done only at the first request of socket usage
    pthread_attr_t tattr;
    pthread_attr_init(&tattr);

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(3, &cpuset);
    pthread_attr_setaffinity_np(&tattr, sizeof(cpuset), &cpuset);

    pthread_t socket_thread;
    if (pthread_create(&socket_thread, &tattr, do_socket, &dparg) != 0) {
        LOG_ERROR("pthread_create() error");
        g_running  = false;
        queue_stop = true;
        goto exit;
    }

exit:
    // pthread_join(dpdk_thread, NULL);
    rte_eal_mp_wait_lcore();
    pthread_join(socket_thread, NULL);
    pthread_join(control_path_tid, NULL);
    close(sockfd);
    remove(REQUEST_IPC_PATH);
    mem_manager__delete(&nsn_runtime.mem_manager);
    rte_eal_cleanup();
    return 0;
}
