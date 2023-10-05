#include "proto_trp.h"
#include <immintrin.h>
#include <insane/logger.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define SPIN_LOOP_PAUSE() _mm_pause()

// TODO: These are limits that
#define PENDING_POOL_SIZE   1000000
#define MAX_PAYLOAD_SIZE    1462
#define MAX_OUSTANDING_PKTS 10000 // TODO: Flow control
#define MSG_SIZE            1024

struct packet_context {
    struct ee_state *src_ep;
    size_t           seg_length;
    uint32_t         psn;

    // struct rdmap_packet *rdmap;
};

static inline uint64_t get_clock_realtime_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static struct pending_pkt pending_pool[PENDING_POOL_SIZE];

/** Compares two 32-bit unsigned integers using the rules in RFC 1982 with
 * SERIAL_BITS=32.  Returns true if and only if s1 < s2. */
static bool serial_less_32(uint32_t s1, uint32_t s2) {
    return (s1 < s2 && s2 - s1 < (UINT32_C(1) << 31)) || (s1 > s2 && s1 - s2 > (UINT32_C(1) << 31));
} /* serial_less_32 */

/** Compares two 32-bit unsigned integers using the rules in RFC 1982 with
 * SERIAL_BITS=32.  Returns true if and only if s1 > s2. */
static bool serial_greater_32(uint32_t s1, uint32_t s2) {
    return (s1 < s2 && s2 - s1 > (UINT32_C(1) << 31)) || (s1 > s2 && s1 - s2 < (UINT32_C(1) << 31));
} /* serial_greater_32 */

static void process_trp_sack(nsn_rel_source_t *src, uint32_t psn_min, uint32_t psn_max) {
    struct pending_pkt *entry;
    list_head_t        *item, *p;

    sem_wait(&src->list_mutex);
    if (list__is_empty(&src->tx_list)) {
        return;
    }

    // Eliminate all the pending packets with psn.min <= PSN <= psn.max
    list_for_each_safe(item, p, &src->tx_list) {
        entry = list_entry(item, struct pending_pkt, head);
        if ((psn_min == entry->psn || serial_less_32(psn_min, entry->psn)) &&
            serial_less_32(entry->psn, psn_max))
        {
            list__del(item);
            src->ous_pkts_count--;
        }
    }
    sem_post(&src->list_mutex);
}

static void send_trp_sack(nsn_rel_sink_t *rel_sink /*, shared_state_t *sh*/) {
    nsn_buffer_t     buf;
    struct ee_state *ep = &rel_sink->state;
    struct trp_hdr  *trp;

    // TODO: This might block! We should make it async and just try
    buf     = nsn_get_buffer(rel_sink->src_ack, sizeof(struct trp_hdr), 0);
    buf.len = sizeof(struct trp_hdr);

    trp          = (struct trp_hdr *)buf.data;
    trp->psn     = ep->recv_sack_psn.min;
    trp->ack_psn = ep->recv_sack_psn.max;
    // trp->psn     = sh->recv_sack_psn.min;
    // trp->ack_psn = sh->recv_sack_psn.max;
    trp->opcode = trp_sack;

    LOG_DEBUG("Send Sack for PSN min %lu max %lu", trp->psn, trp->ack_psn);
    nsn_emit_data(rel_sink->src_ack, &buf);

    ep->trp_flags &= ~trp_ack_update;
    // sh->flags &= ~trp_ack_update;
}

static void send_trp_ack(nsn_rel_sink_t *rel_sink /*, shared_state_t *sh*/) {
    nsn_buffer_t     buf;
    struct ee_state *ep = &rel_sink->state;
    struct trp_hdr  *trp;

    // TODO: This might block! We should make it async and just try
    buf = nsn_get_buffer(rel_sink->src_ack, sizeof(struct trp_hdr), 0);

    trp          = (struct trp_hdr *)buf.data;
    trp->psn     = ep->send_next_psn++;
    trp->ack_psn = ep->recv_ack_psn;
    // trp->psn     = sh->send_next_psn++;
    // trp->ack_psn = sh->recv_ack_psn;
    trp->opcode = 0;
    buf.len     = sizeof(struct trp_hdr);

    LOG_DEBUG("Send ack for PSN %lu", trp->psn);
    nsn_emit_data(rel_sink->src_ack, &buf);

    ep->trp_flags &= ~trp_ack_update;
    // sh->flags &= ~trp_ack_update;
}

// I go through all the packets that I sent and check whether they have been acked or not
// If yes, I remove them from the queue. Otherwise, I check if retransmission timeout expired and
// try to retransmit it.
static void sweep_unacked_packets(nsn_rel_source_t *src, uint64_t now) {
    struct pending_pkt *entry;
    list_head_t        *item, *p;
    struct trp_hdr      trp_hdr;
    uint16_t            trp_opcode;

    // int   debug_index;
    // char *debug_data;

    // Async receive
    nsn_buffer_t buf = nsn_consume_data(src->snk_ack, 1);
    // debug_data       = (char *)buf.data;
    // debug_index      = buf.index;

    // If we received a valid buffer, that's an ACK that we must handle
    if (buf.index >= 0) {
        /* Get TRP header */
        trp_hdr.ack_psn = ((struct trp_hdr *)buf.data)->ack_psn;
        trp_hdr.psn     = ((struct trp_hdr *)buf.data)->psn;
        trp_hdr.opcode  = ((struct trp_hdr *)buf.data)->opcode;
        nsn_release_data(src->snk_ack, &buf);

        trp_opcode = trp_hdr.opcode & trp_opcode_mask;
        switch (trp_opcode) {
        case 0:
            /* Normal ACK */
            if (trp_hdr.ack_psn < src->last_acked_psn) {
                LOG_ERROR("Garbage ACK received: %u", trp_hdr.ack_psn);
            }
            src->last_acked_psn = trp_hdr.ack_psn;
            LOG_DEBUG("Received ACK for psn %u [index: %d, data at %p]", trp_hdr.ack_psn,
                      debug_index, debug_data);
            break;
        case trp_sack:
            /* Selective ACK */
            LOG_DEBUG("Received SACK [%u, %u); send_ack_psn %u. [index: %d, data at %p]",
                      trp_hdr.psn, trp_hdr.ack_psn, src->last_acked_psn, debug_index, debug_data);
            process_trp_sack(src, trp_hdr.psn, trp_hdr.ack_psn);
            return;
        default:
            LOG_WARN("Received unexpected opcode %u (PSN was %u); dropping it",
                     trp_opcode >> trp_opcode_shift, trp_hdr.psn);
            return;
        }

        // Remove the acked packet(s) from the list
        sem_wait(&src->list_mutex);
        list_for_each_safe(item, p, &src->tx_list) {
            entry = list_entry(item, struct pending_pkt, head);
            if (entry->psn < trp_hdr.ack_psn) {
                /* What I receive is the stability frontier at the receiver. Hence, packets with
                 * lower PSN have been delivered at receiver and it safe to discard them. */
                list__del(item);
                src->ous_pkts_count--;
            } else {
                // List is ordered, so if we reach a highest PSN than the stability frontier,
                // we can exit
                break;
            }
        }
        sem_post(&src->list_mutex);
    }

    sem_wait(&src->list_mutex);
    if (list__is_empty(&src->tx_list)) {
        sem_post(&src->list_mutex);
        return;
    }
    // For non-acked packets, check if we can retransmit them
    list_for_each(item, &src->tx_list) {
        entry = list_entry(item, struct pending_pkt, head);
        if (now > entry->next_retransmit) {
            // sem_wait(&src->src_mutex);
            // int          debug_index;
            // char        *debug_data;
            nsn_buffer_t b = nsn_get_buffer(src->source, entry->buf->len, 0);
            memcpy(b.data, entry->buf->data, entry->buf->len);
            b.len = entry->buf->len;
            // uint64_t *cnt_list = (uint64_t *)(entry->buf->data + sizeof(struct trp_hdr));
            // uint64_t *cnt      = (uint64_t *)(b.data + sizeof(struct trp_hdr));
            nsn_emit_data(src->source, &b);
            // sem_post(&src->src_mutex);
            // LOG_DEBUG("Retransmitted PSN = %u, with headerPSN = %u, with new content %lu, listed
            // "
            //           "content %lu. [Index: %d, Data at %p]",
            //           entry->psn, ((struct trp_hdr *)b.data)->psn, *cnt, *cnt_list, debug_index,
            //           debug_data);
            // Set timeout for next iteration
            entry->next_retransmit = now + ((uint64_t)1e9 * entry->retransmission_count);
            entry->retransmission_count++;
        }
    }
    sem_post(&src->list_mutex);

} /* sweep_unacked_packets */

static void *do_retransmit(void *arg) {
    nsn_rel_source_t *src = (nsn_rel_source_t *)arg;
    printf("Retransmission thread started\n");

    while (!src->stop) {
        // usleep(100);
        // for (uint8_t i; i < PENDING_POOL_SIZE / 10; i++) {
        //     printf("Starting a loop of retransmissions\n");
        sweep_unacked_packets(src, get_clock_realtime_ns());
        // }
    }
    return NULL;
}

/// FUNCTION "DO_ACK" TO BE USED AS THE ACK_THREAD ACTION
// static void *do_ack(void *arg) {
// nsn_rel_sink_t *snk          = (nsn_rel_sink_t *)arg;
// uint64_t        last_reg_ack = 0;
// shared_state_t  sh;
// uint64_t        count = 0;

// while (!snk->stop) {
//     count++;
//     if (count % 10000 == 0) {
//         sem_wait(&snk->snk_mutex);
//         sh = snk->shared_state;
//         sem_post(&snk->snk_mutex);
//         // Acknowledge the messages we received
//         if (sh.flags & trp_ack_update) {
//             if (sh.flags & trp_recv_missing) {
//                 send_trp_sack(snk, &sh);
//             } else {
//                 last_reg_ack++;
//                 if (last_reg_ack % 10 == 0) {
//                     send_trp_ack(snk, &sh);
//                 }
//             }
//         }
//         count = 0;
//     }
// }
// }

static void init_pending_descriptors() {
    for (uint64_t i = 0; i < PENDING_POOL_SIZE; i++) {
        pending_pool[i].buf       = (nsn_buffer_t *)malloc(sizeof(nsn_buffer_t));
        pending_pool[i].buf->data = (uint8_t *)malloc(MAX_PAYLOAD_SIZE);
    }
}

struct pending_pkt *get_new_pending_descriptor() {
    static uint64_t free_pkts;
    return &pending_pool[free_pkts++];
}

// Returns 0 if the received buf has been queued, -1 if not (and thus the buf can be released
// immediately). This function queues the received buf in an ordered list by packet num (psn)
static int process_data_packet(nsn_buffer_t *buf, struct packet_context *ctx, nsn_rel_sink_t *snk) {
    struct trp_hdr  *trp_hdr;
    struct ee_state *ep = ctx->src_ep;

    /* Get TRP header */
    trp_hdr = (struct trp_hdr *)buf->data;

    /* We deliberately ignore piggibacked ACKs here, as sinks are one-way */
    ctx->psn = trp_hdr->psn;
    if (ctx->psn == ep->recv_ack_psn) {
        ep->recv_ack_psn++;
        if ((ep->trp_flags & trp_recv_missing) && ep->recv_ack_psn == ep->recv_sack_psn.min) {
            ep->recv_ack_psn = ep->recv_sack_psn.max;
            ep->trp_flags &= ~trp_recv_missing;
        }
        ep->trp_flags |= trp_ack_update;

    } else if (serial_less_32(ep->recv_ack_psn, ctx->psn)) {
        /* We detected a sequence number gap.  Try to build a
         * contiguous range so we can send a SACK to lower the number
         * of retransmissions. */
        LOG_DEBUG("Receive psn %u (%lu); next expected psn %u", ctx->psn,
                  *((uint64_t *)(buf->data + sizeof(struct trp_hdr))), ep->recv_ack_psn);
        if (ep->trp_flags & trp_recv_missing) {
            if (ctx->psn == ep->recv_sack_psn.max) {
                ep->recv_sack_psn.max = ctx->psn + 1;
                ep->trp_flags |= trp_ack_update;
            } else if (ctx->psn + 1 == ep->recv_sack_psn.min) {
                ep->recv_sack_psn.min = ctx->psn;
                if (ep->recv_sack_psn.min == ep->recv_ack_psn) {
                    ep->recv_ack_psn = ep->recv_sack_psn.max;
                    ep->trp_flags &= ~trp_recv_missing;
                }
                ep->trp_flags |= trp_ack_update;
            } else if (serial_less_32(ctx->psn, ep->recv_sack_psn.min) ||
                       serial_greater_32(ctx->psn, ep->recv_sack_psn.max))
            {
                /* We've run out of ways to track this
                 * datagram; drop it and wait for it to be
                 * retransmitted along with the surrounding
                 * datagrams. */
                LOG_INFO("Got out of range psn %u; next expected %u sack range: [%u, %u]", ctx->psn,
                         ep->recv_ack_psn, ep->recv_sack_psn.min, ep->recv_sack_psn.max);
                return -1;
            } else {
                /* This segment has been handled; drop the
                 * duplicate. */
                return -1;
            }
        } else {
            ep->trp_flags |= trp_recv_missing | trp_ack_update;
            ep->recv_sack_psn.min = ctx->psn;
            ep->recv_sack_psn.max = ctx->psn + 1;
        }
    } else {
        /* This is a retransmission of a packet which we have already
         * acknowledged; throw it away. */
        LOG_ERROR("Got retransmission psn %u", ctx->psn);

        // struct trp_hdr *debug_hdr = (struct trp_hdr *)buf->data;
        // printf("=== HEADER ===\nOpcode: %u\nPSN: %u\nAck: %u\n===CONTENT: %lu\n",
        // debug_hdr->opcode,
        //        debug_hdr->psn, debug_hdr->ack_psn,
        //        *((uint64_t *)(buf->data + sizeof(struct trp_hdr))));
        return -1;
    }

    // If we accepted the received buf, we need to insert it into the ordered list
    // TODO: Avoid malloc in the get_descriptor()
    list_head_t        *item;
    struct pending_pkt *entry;
    struct pending_pkt *pending = get_new_pending_descriptor();

    // Copy the fields (the "buf" is a stack address)
    pending->buf->data  = buf->data;
    pending->buf->index = buf->index;
    pending->buf->len   = buf->len;

    pending->psn = ctx->psn;

    // uint64_t *cnt   = (uint64_t *)(buf->data + sizeof(struct trp_hdr));
    // uint64_t *cnt_2 = (uint64_t *)(pending->buf->data + sizeof(struct trp_hdr));

    // List is ordered by ascending psn (lowest psn first)
    if (list__is_empty(&ep->rx_list)) {
        list__add(&ep->rx_list, &pending->head);
    } else {
        uint8_t inserted = 0;
        list_for_each(item, &ep->rx_list) {
            entry = list_entry(item, struct pending_pkt, head);
            if (entry->psn > pending->psn) {
                // Add "pending" before "entry"
                list__add_tail(item, &pending->head);
                inserted = 1;
                break;
            }
        }
        // If we did not insert this fragment, it's because it has the highest PSN, so it
        // must be placed as the last entry of the list.
        if (!inserted) {
            list__add_tail(&ep->rx_list, &pending->head);
        }
    }
    return 0;
}

nsn_buffer_t *get_buffer_for_delivery(struct packet_context *ctx) {
    struct pending_pkt *entry;
    nsn_buffer_t       *buf;

    if (!list__is_empty(&ctx->src_ep->rx_list) &&
        (entry = list_first_entry(&ctx->src_ep->rx_list, struct pending_pkt, head))->psn <
            ctx->src_ep->recv_ack_psn)
    {
        // Prepare the result
        buf = entry->buf;
        list__del(&entry->head);

        buf->data += sizeof(struct trp_hdr);
        buf->len -= sizeof(struct trp_hdr);
        // It will be user's responsibility to nsn_release this buffer
        return buf;
    }
    return NULL;
}

nsn_buffer_t nsn_consume_data_reliable(nsn_rel_sink_t *rel_sink, int flags) {
    nsn_buffer_t         *buf_ptr;
    struct packet_context ctx;
    int                   ret;

    // Initialize context for packet processing
    ctx.src_ep = &rel_sink->state;

    // Loop until a message becomes available
    volatile uint8_t can_return = 0;
    uint64_t         count      = 0;
    while (!can_return) {

        // Check if we can deliver immediately a queued packet
        buf_ptr = get_buffer_for_delivery(&ctx);
        if (buf_ptr != NULL) {
            // We have already generated the ACKs for queued packets, so we can return
            // immediately. More importantly, we should NOT call nsn_consume_data() after this,
            // because it could block and stuck the application even if packets are waiting in
            // queue.
            return *buf_ptr;
        }

        // Get a buffer from insane
        nsn_buffer_t buf = nsn_consume_data(rel_sink->sink, flags);
        // Process the buffer and checks its sequence number
        ret = process_data_packet(&buf, &ctx, rel_sink);
        if (ret < 0) {
            nsn_release_data(rel_sink->sink, &buf);
        }

        buf_ptr = get_buffer_for_delivery(&ctx);
        if (buf_ptr != NULL) {
            can_return = 1;
        }

        // If we use the AKC Thread
        // Copy the receiver state to the shared area
        // sem_wait(&rel_sink->snk_mutex);
        // rel_sink->shared_state.flags         = ctx.src_ep->trp_flags;
        // rel_sink->shared_state.send_next_psn = ctx.src_ep->send_next_psn;
        // rel_sink->shared_state.recv_ack_psn  = ctx.src_ep->recv_ack_psn;
        // rel_sink->shared_state.recv_sack_psn = ctx.src_ep->recv_sack_psn;
        // sem_post(&rel_sink->snk_mutex);
        // // Consider the ACK part as done
        // ctx.src_ep->trp_flags &= ~trp_ack_update;

        // Acknowledge the messages we received
        // This cannot work in this way. You send acks only if the receiver calls this function eheh
        count++;
        if (count % 500 == 0) {
            if (ctx.src_ep->trp_flags & trp_ack_update) {
                if (flags & trp_recv_missing) {
                    send_trp_sack(rel_sink);
                } else {
                    send_trp_ack(rel_sink);
                }
            }
            count = 0;
        }
        // Else, keep waiting for the right message to arrive
    }

    return *buf_ptr;
}

nsn_buffer_t nsn_get_buffer_reliable(nsn_rel_source_t *rel_source, size_t size, int flags) {
    // sem_wait(&rel_source->src_mutex);
    nsn_buffer_t buf = nsn_get_buffer(rel_source->source, size + sizeof(struct trp_hdr), flags);
    buf.data += sizeof(struct trp_hdr);
    // sem_post(&rel_source->src_mutex);
    return buf;
}

int nsn_emit_data_reliable(nsn_rel_source_t *rel_source, nsn_buffer_t buf) {
    buf.data -= sizeof(struct trp_hdr);
    buf.len += sizeof(struct trp_hdr);

    // uint32_t debug_1, debug_2;
    // char    *debug_dataptr;
    // int      debug_index;

    struct trp_hdr *trp_hdr = (struct trp_hdr *)buf.data;
    trp_hdr->opcode         = 0;
    trp_hdr->psn            = rel_source->psn++;
    trp_hdr->ack_psn        = 0;

    // debug_1       = trp_hdr->psn;
    // debug_dataptr = (char *)buf.data;
    // debug_index   = buf.index;
    ///////////// DEBUG: Scramble data
    // if (trp_hdr->psn > 5 && trp_hdr->psn % 2 == 0) {
    //     trp_hdr->psn += 1;
    //     uint64_t *cnt = (uint64_t *)(buf->data + sizeof(struct trp_hdr));
    //     *cnt          = (uint64_t)trp_hdr->psn;

    // } else if (trp_hdr->psn > 5 && trp_hdr->psn % 2 != 0) {
    //     trp_hdr->psn -= 1;
    //     uint64_t *cnt = (uint64_t *)(buf->data + sizeof(struct trp_hdr));
    //     *cnt          = (uint64_t)trp_hdr->psn;
    // }
    ////////////

    // Initialize a corresponding descriptor and insert it into the list
    struct pending_pkt *pending_info = get_new_pending_descriptor();
    pending_info->psn                = trp_hdr->psn;
    pending_info->buf->len           = buf.len;
    memcpy(pending_info->buf->data, buf.data, buf.len);
    pending_info->retransmission_count = 0;
    pending_info->next_retransmit      = get_clock_realtime_ns() + (uint64_t)1e7;
    sem_wait(&rel_source->list_mutex);
    list__add_tail(&rel_source->tx_list, &pending_info->head);
    rel_source->ous_pkts_count++;
    sem_post(&rel_source->list_mutex);

    // while (rel_source->ous_pkts_count >= rel_source->max_oust_pkts) {
    //     SPIN_LOOP_PAUSE();
    // }

    // if (((struct trp_hdr *)buf.data)->psn < rel_source->psn - 1) {
    //     LOG_ERROR("[EMIT] Header has PSN = %u, but it should be %u (%u now, %u before). Index is
    //     "
    //               "%d (%d before), data at %p (%p before)",
    //               ((struct trp_hdr *)buf.data)->psn, rel_source->psn - 1, trp_hdr->psn, debug_1,
    //               buf.index, debug_index, (char *)buf.data);
    //     buf.data = debug_dataptr;

    // } else {
    //     LOG_INFO("Emit with PSN=%u and cnt=%lu", ((struct trp_hdr *)buf.data)->psn,
    //              *((uint64_t *)(buf.data + sizeof(struct trp_hdr))));
    // }
    // printf("Sending it out with PSN: %u\n", trp_hdr->psn);
    // sem_wait(&rel_source->src_mutex);
    int tkn = nsn_emit_data(rel_source->source, &buf);
    // sem_post(&rel_source->src_mutex);
    return tkn;
}

nsn_rel_source_t *nsn_create_rel_source(nsn_stream_t *stream, uint32_t source_id) {
    nsn_rel_source_t *src = (nsn_rel_source_t *)malloc(sizeof(nsn_rel_source_t));

    init_pending_descriptors();

    src->source  = nsn_create_source(stream, source_id);
    src->snk_ack = nsn_create_sink(stream, source_id + 1, NULL);
    sem_init(&src->src_mutex, 0, 1);
    src->psn            = 0;
    src->max_oust_pkts  = MAX_OUSTANDING_PKTS;
    src->ous_pkts_count = 0;
    list__init(&src->tx_list);
    sem_init(&src->list_mutex, 0, 1);
    src->tx_pending_size = 0;
    src->last_acked_psn  = 0;
    src->stop            = 0;

    // cpu_set_t cpu;
    // CPU_ZERO(&cpu);
    // CPU_SET(6, &cpu);
    // pthread_attr_t attr;
    // pthread_attr_init(&attr);
    // pthread_attr_setaffinity_np(&attr, sizeof(cpu), &cpu);

    if (pthread_create(&src->retransmission_thread, NULL, do_retransmit, (void *)src) < 0) {
        LOG_ERROR("cannot create retransmission thread");
        src->stop = 1;
        return NULL;
    }

    return src;
}

void nsn_destroy_rel_source(nsn_rel_source_t *src) {
    src->stop = 1;
    pthread_join(src->retransmission_thread, NULL);
    nsn_destroy_source(src->source);
    nsn_destroy_sink(src->snk_ack);
}

nsn_rel_sink_t *nsn_create_rel_sink(nsn_stream_t *stream, uint32_t source_id) {
    nsn_rel_sink_t *snk = malloc(sizeof(nsn_rel_sink_t));
    init_pending_descriptors();

    snk->sink    = nsn_create_sink(stream, source_id, NULL);
    snk->src_ack = nsn_create_source(stream, source_id + 1);

    snk->state.send_last_acked_psn = 0;
    snk->state.send_next_psn       = 0;
    snk->state.send_max_psn        = 0;

    snk->state.recv_ack_psn = 0;
    snk->state.trp_flags    = 0;
    list__init(&snk->state.rx_list);
    snk->state.recv_sack_psn.min = 0;
    snk->state.recv_sack_psn.max = 0;

    // snk->shared_state.flags         = snk->state.trp_flags;
    // snk->shared_state.recv_ack_psn  = snk->state.recv_ack_psn;
    // snk->shared_state.send_next_psn = snk->state.send_next_psn;
    // snk->shared_state.recv_sack_psn = snk->state.recv_sack_psn;

    // snk->stop = 0;
    // sem_init(&snk->snk_mutex, 0, 1);
    // if (pthread_create(&snk->ack_thread, NULL, do_ack, (void *)snk) < 0) {
    //     LOG_ERROR("cannot create acknowledgement thread");
    //     snk->stop = 1;
    //     return NULL;
    // }

    return snk;
}

void nsn_destroy_rel_sink(nsn_rel_sink_t *snk) {
    // snk->stop = 1;
    // pthread_join(snk->ack_thread, NULL);
    nsn_destroy_source(snk->src_ack);
    nsn_destroy_sink(snk->sink);
}

// int main(int argc, char *argv[]) {

//     if (argc != 2) {
//         printf("Usage: %s <-r|-s>\n", argv[0]);
//         printf("-r is receiver mode\n-s is sender mode\n");
//         exit(1);
//     }

//     /* Init library */
//     if (nsn_init() < 0) {
//         fprintf(stderr, "Cannot init INSANE library\n");
//         return -1;
//     }

//     // cpu_set_t cpu;
//     // CPU_ZERO(&cpu);
//     // CPU_SET(5, &cpu);
//     // pthread_t father = pthread_self();
//     // pthread_setaffinity_np(father, sizeof(cpu_set_t), &cpu);

//     /* Init test structs */
//     init_pending_descriptors();

//     /* Create stream */
//     nsn_options_t options = {datapath_fast, consumption_high, determinism_no};
//     nsn_stream_t  stream  = nsn_create_stream(&options);
//     nsn_buffer_t  buf;

//     uint64_t max_msg  = PENDING_POOL_SIZE;
//     size_t   msg_size = MSG_SIZE;

//     if (!strcmp(argv[1], "-r")) {
//         nsn_rel_sink_t *sink = nsn_create_rel_sink(&stream, 0);

//         uint64_t start;
//         uint64_t counter = 0;
//         printf("Waiting for threads to start...\n");
//         usleep(1000);
//         printf("Ready to receive packets\n");
//         while (counter < max_msg) {
//             nsn_buffer_t buf = nsn_consume_data_reliable(sink, 0);
//             counter++;

//             if (counter == 1) {
//                 start = get_clock_realtime_ns();
//             }

//             uint64_t *cnt = (uint64_t *)buf.data;
//             // if (*cnt % 100 == 0) {
//             //     printf("Received message %lu with content %lu\n", counter - 1, *cnt);
//             // }

//             nsn_release_data(sink->sink, &buf);
//         }
//         uint64_t end = get_clock_realtime_ns();
//         printf("Total time %0.2f ms\n", (double)(end - start) / 1e6);
//         nsn_destroy_rel_sink(sink);

//     } else if (!strcmp(argv[1], "-s")) {
//         nsn_rel_source_t *source = nsn_create_rel_source(&stream, 0);

//         // Wait some time to allow threads to start
//         printf("Waiting for threads to start...\n");
//         usleep(1000);

//         printf("Start testing...\n");
//         for (uint64_t i = 0; i < max_msg; i++) {
//             buf = nsn_get_buffer_reliable(source, msg_size, 0);
//             // Fill the content
//             uint64_t *cnt = (uint64_t *)buf.data;
//             *cnt          = i;
//             // printf("Content filled with value %lu\n", *((uint64_t *)buf.data));
//             // fflush(stdout);
//             // Set the length
//             buf.len = msg_size;
//             nsn_emit_data_reliable(source, buf);
//         }
//         printf("Finished sending %ld messages. Waiting for all acks...\n", max_msg);

//         sem_wait(&source->list_mutex);
//         bool empty = list__is_empty(&source->tx_list);
//         sem_post(&source->list_mutex);
//         while (!empty) {
//             usleep(100);
//             sem_wait(&source->list_mutex);
//             empty = list__is_empty(&source->tx_list);
//             sem_post(&source->list_mutex);
//         }

//         printf("All messages have been acked. Exiting...\n");
//         nsn_destroy_rel_source(source);

//     } else {
//         printf("Parameter not recognized. Exiting...\n");
//     }

//     /* Close library */
//     nsn_close();
//     return 0;
// }