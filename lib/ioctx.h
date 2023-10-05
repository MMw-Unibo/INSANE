#ifndef INSANE_IOCTX_H
#define INSANE_IOCTX_H

#include "queue.h"
#include <rte_mbuf.h>

#define MAX_PKT_BURST    4096
#define N_CHUNKS         8192
#define MAX_PKT_BURST_RX 16 // MAX_PKT_BURST

#define NSN_SLOTS     4096
#define NSN_SLOT_SIZE 1470 // Max payload size

// Sockets do not have chunks, but we still reserve more space than NSN_SLOTS
#define RX_SOCK_SLOTS    NSN_SLOTS * 128
#define TX_SOCK_SLOTS    NSN_SLOTS
#define SOCKET_POOL_SIZE ((TX_SOCK_SLOTS + RX_SOCK_SLOTS) * NSN_SLOT_SIZE) // Rx and Tx

struct nsn_mbuf {
    char data[NSN_SLOT_SIZE];
};

//--------------------------------------------------------------------------------------------------
// I/O Context
//--------------------------------------------------------------------------------------------------
typedef struct nsn_ioctx_dpdk {
    int rx_chunks[N_CHUNKS];

    struct rte_mbuf *rx_mbuf[MAX_PKT_BURST_RX * N_CHUNKS];
    struct rte_mbuf *tx_mbuf[MAX_PKT_BURST];
} nsn_ioctx_dpdk_t;

typedef struct nsn_ioctx_socket {
    // nsn_queue_t     *free_rx_idx;
    struct rte_ring *free_rx_idx;

    struct nsn_mbuf *rx_mbuf[RX_SOCK_SLOTS];
    struct nsn_mbuf *tx_mbuf[TX_SOCK_SLOTS];
} nsn_ioctx_socket_t;

#endif // INSANE_IOCTX_H
