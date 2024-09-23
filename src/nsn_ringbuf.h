#ifndef NSN_RINGBUF_H
#define NSN_RINGBUF_H

#include "nsn_types.h"
#include "nsn_string.h"

struct nsn_ring_headtail
{
    atu32 head;
    atu32 tail;
};

#define NSN_CFG_RINGBUF_MAX_NAME_SIZE 64

typedef struct nsn_ringbuf nsn_ringbuf_t;
nsn_cache_aligned struct nsn_ringbuf
{
    void *data; /**< Data buffer. */
    char name[NSN_CFG_RINGBUF_MAX_NAME_SIZE];

    u32 size;  /**< Number of elements of ring. */
    u32 mask;  /**< Mask (size-1) of ring. */
    u32 capacity;
    u32 esize; /**< Element size. Total byte size is esize*size */

    char __pad0 nsn_cache_aligned;

    struct nsn_ring_headtail prod;

    char __pad1 nsn_cache_aligned;

    struct nsn_ring_headtail cons;

    char __pad2 nsn_cache_aligned;
};

nsn_ringbuf_t *nsn_ringbuf_create(void *memory, string_t name, u32 count);
u32 nsn_ringbuf_destroy(nsn_ringbuf_t *ring);

u32 nsn_ringbuf_get_capacity(nsn_ringbuf_t *rb);
u32 nsn_ringbuf_count(nsn_ringbuf_t *rb);

u32 nsn_ringbuf_enqueue_burst(nsn_ringbuf_t *rb, const void *obj_table, u32 esize, u32 n, u32 *free_space);
u32 nsn_ringbuf_dequeue_burst(nsn_ringbuf_t *rb, void *obj_table, u32 esize, u32 n, u32 *available);

#endif // NSN_RINGBUF_H