#ifndef PROTO_TRP_H
#define PROTO_TRP_H

#define _GNU_SOURCE

#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdlib.h>

#include "../include/insane/insane.h"
#include "list.h"

enum {
    trp_sack = 0x5000,
    /**< This packet is a selective acknowledgement that contains
     * no data.  Rather, the psn and ack_psn fields indicate the
     * minimum and (maximum + 1) sequence numbers, respectively, in
     * a contiguous range that have been received. */
    trp_opcode_mask = 0xf000,
    /**< Mask of all bits used for opcode. */
    trp_reserved_mask = 0x0fff,
    /**< Mask of all bits not currently used. */
    trp_opcode_shift = 12,
    /**< Number of bits that opcode is shifted by. */
};

enum {
    trp_recv_missing = 1,
    trp_ack_update   = 2,
};

// Header of the TRP protocol
struct trp_hdr {
    uint32_t psn;
    uint32_t ack_psn;
    uint16_t opcode;
} __attribute__((__packed__));

// Range of unacknowledged Packet Sequence Number (PSN)
struct psn_range {
    uint32_t min;
    uint32_t max;
};

struct pending_pkt {
    list_head_t   head;                 // List of pending pkt
    uint64_t      next_retransmit;      // Time to retransmit this dgram (used in tx only)
    uint32_t      retransmission_count; // Number of time this has been retransmitted
    nsn_buffer_t *buf;                  // Pointer to the buffer to transmit
    uint32_t      psn;                  // Packet Sequence Number (PSN)
};

struct ee_state {
    /* TX TRP state */
    uint32_t send_last_acked_psn;
    uint32_t send_next_psn;
    uint32_t send_max_psn;

    /* RX TRP state */
    uint32_t    recv_ack_psn; // Next psn to be received
    list_head_t rx_list; // List of buffers received out of order. Elements will have type "struct
                         // pending_pkt*"
    uint32_t         trp_flags;     // Flags to signal if we need to send out acks
    struct psn_range recv_sack_psn; // Selective acknowledgment
};

typedef struct {
    uint32_t         flags;
    uint32_t         send_next_psn;
    uint32_t         recv_ack_psn;
    struct psn_range recv_sack_psn;
} shared_state_t;

typedef struct {
    nsn_sink_t      sink;
    nsn_source_t    src_ack;
    struct ee_state state;
    // The following are needed for the ACK thread, now disabled
    // pthread_t        ack_thread;
    // sem_t            snk_mutex;
    // volatile uint8_t stop;
    // shared_state_t   shared_state;
} nsn_rel_sink_t;

typedef struct {
    nsn_source_t     source;
    nsn_sink_t       snk_ack;
    sem_t            src_mutex;
    uint32_t         psn;
    uint32_t         max_oust_pkts;  // Max oustanding packets before pausing sender
    uint32_t         ous_pkts_count; // Number of unacked pkts (= tx_list size)
    sem_t            list_mutex;
    list_head_t      tx_list; // Unacket packets. List of struct pendink pkt
    uint32_t         last_acked_psn;
    int              tx_pending_size;
    volatile uint8_t stop;
    pthread_t        retransmission_thread;
} nsn_rel_source_t;

// TODO: Add proper documentation
nsn_rel_source_t *nsn_create_rel_source(nsn_stream_t *stream, uint32_t source_id);
void              nsn_destroy_rel_source(nsn_rel_source_t *src);
nsn_rel_sink_t   *nsn_create_rel_sink(nsn_stream_t *stream, uint32_t source_id);
void              nsn_destroy_rel_sink(nsn_rel_sink_t *snk);

// TODO: Add description
nsn_buffer_t nsn_get_buffer_reliable(nsn_rel_source_t *source, size_t size, int flags);

/**
 * @brief    Ask INSANE to send a buffer slot out to the network with reliability
 * @param    source A handle to the source to which the message will be sent
 * @param    buf    The buffer slot contaning the message to be sent
 * @returns  A token to asynchronously retrieve the outcome of the operation
 */
int nsn_emit_data_reliable(nsn_rel_source_t *source, nsn_buffer_t buf);

/**
 * @brief    Consume a message from a sink. Messages are guaranteed to be delivered
 *  in order with at-least-once semantic (like TCP).
 * @param    sink   The sink from which to get data
 * @param    flags  Flags to control the behavior of this function,
                    that can be blocking or non blocking
 * @returns  A buffer slot containing the outcome of the operation and, if
             successful, the read data
 */
nsn_buffer_t nsn_consume_data_reliable(nsn_rel_sink_t *sink, int flags);

#endif
