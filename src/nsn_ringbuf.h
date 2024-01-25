#ifndef NSN_RINGBUF_H
#define NSN_RINGBUF_H

#include "nsn_types.h"
#

struct nsn_ring_headtail
{
    atu32 head;
    atu32 tail;
};

struct nsn_ringbuf
{
    void *data; /**< Data buffer. */

    u32 size;  /**< Size of ring. */
    u32 mask;  /**< Mask (size-1) of ring. */
    u32 capacity;

    char __pad0 nsn_cache_aligned;

    struct nsn_ring_headtail prod;

    char __pad1 nsn_cache_aligned;

    struct nsn_ring_headtail cons;

    char __pad2 nsn_cache_aligned;
};

inline struct nsn_ringbuf *nsn_ringbuf_create(void *memory, u32 count);

u32 nsn_ringbuf_get_capacity(const struct nsn_ringbuf *rb);
u32 nsn_ringbuf_count(const struct nsn_ringbuf *rb);

u32 nsn_ringbuf_enqueue_burst(struct nsn_ringbuf *rb, const void *obj_table, u32 n, u32 *free_space);
u32 nsn_ringbuf_dequeue_burst(struct nsn_ringbuf *rb, void *obj_table, u32 n, u32 *available);

#endif // NSN_RINGBUF_H