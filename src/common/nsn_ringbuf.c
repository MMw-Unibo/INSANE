#include "common/nsn_ringbuf.h"

static inline nsn_ringbuf_t *
nsn_ringbuf_create_elem(void *memory, string_t name, usize esize, u32 count)
{
    // TODO: check if memory is aligned and if count is a power of 2

    // ensure that memory is big enough to hold the ringbuf + data
    // we assume that the ring data is always right after the ring descriptor
    explicit_bzero(memory, sizeof(struct nsn_ringbuf) + count * esize);
    struct nsn_ringbuf *rb = (struct nsn_ringbuf *)memory;

    // set the data pointer
    rb->data = (void *)((u8 *)rb + sizeof(struct nsn_ringbuf));

    // set the name
    memcpy(rb->name, name.data, name.len);

    rb->size     = count;
    rb->mask     = count - 1;
    rb->capacity = rb->mask;

    log_trace("create ringbuf %.*s with %u elements\n", str_varg(name), count);

    // set the head and tail to 0
    rb->prod.head = 0;
    rb->prod.tail = 0;
    rb->cons.head = 0;
    rb->cons.tail = 0;

    return rb;
}

nsn_ringbuf_t *
nsn_ringbuf_create(void *memory, string_t name, u32 count)
{
    return nsn_ringbuf_create_elem(memory, name, sizeof(void *), count);
}

u32 
nsn_ringbuf_destroy(nsn_ringbuf_t *ring)
{
    if (ring == NULL)
    {
        log_error("invalid ring pointer\n");
        return EINVAL;
    }

    // We assume that the ring data is always right after the ring descriptor
    size_t size = sizeof(struct nsn_ringbuf) + ring->size * ring->esize;
    explicit_bzero(ring->data, size);
    
    return 0;
}


u32 
nsn_ringbuf_get_capacity(nsn_ringbuf_t *rb)
{
    return rb->capacity;
}

u32
nsn_ringbuf_get_size(nsn_ringbuf_t *rb)
{
    return rb->size;
}

u32 
nsn_ringbuf_count(nsn_ringbuf_t *rb)
{
	u32 prod_tail = rb->prod.tail;
	u32 cons_tail = rb->cons.tail;
	u32 count     = (prod_tail - cons_tail) & rb->mask;

	return (count > rb->capacity) ? rb->capacity : count;
}

u32
nsn_ringbuf_peek(nsn_ringbuf_t *rb, void *obj_table, u32 n) {
    u32 elems = nsn_ringbuf_count(rb);
    if (elems > 0) {
        u32 size  = rb->size;
        u32 idx   = rb->cons.head & (size - 1);
        u64 *ring = (u64 *)&rb[1];
        u64 *dst  = (u64 *)obj_table;
        for(u32 i = 0; i < elems && i < n; i++) {
            dst[i] =  ring[idx];
            idx = (idx + 1 == size) ? 0 : idx + 1;
        }
    }
    return elems;
}

static inline u32
__nsn_ringbuf_move_prod_head(nsn_ringbuf_t *rb, u32 n, atu32 *old_head, atu32 *new_head, u32 *free_entries)
{
    const u32 capacity = rb->capacity;
    u32 max            = n;
    int success;

    do
    {
        n         = max;
        *old_head = rb->prod.head;

        nsn_compiler_barrier();

        *free_entries = (capacity + rb->cons.tail - *old_head);

        if (nsn_unlikely(n > *free_entries))    n = *free_entries;
        if (nsn_unlikely(n == 0))               return 0;

        *new_head = *old_head + n;

        success = at_cas_weak(&rb->prod.head, old_head, *new_head, mo_rlx, mo_rlx);
    } while (nsn_unlikely(success == 0));

    return n;
}

static inline void
__nsn_ringbuf_enqueue_elems(nsn_ringbuf_t *rb, u32 prod_head, const void *obj_table, u32 esize, u32 n)
{
    if (nsn_likely(esize == 8))
    {
        u32 i;
        const u32 size = rb->size;
        u32 idx = prod_head & rb->mask;
        u64 *ring = (u64 *)(rb + 1);
        const u64 *src = (const u64 *)obj_table;

        if (nsn_likely(idx + n <= size))
        {
            for (i = 0; i < (n & ~0x3); i += 4, idx += 4)
            {
                ring[idx] = src[i];
                ring[idx + 1] = src[i + 1];
                ring[idx + 2] = src[i + 2];
                ring[idx + 3] = src[i + 3];
            }
            switch (n & 0x3)
            {
            case 3:
                ring[idx++] = src[i++]; // fallthrough
            case 2:
                ring[idx++] = src[i++]; // fallthrough
            case 1:
                ring[idx++] = src[i++]; // fallthrough            
            }
        }
        else
        {
            for (i = 0; i < n; i++, idx++)
                ring[idx] = src[i];
            for (idx = 0; i < n; i++, idx++)
                ring[idx] = src[i];
        }
    }
    else
    {
        assert("not implemented" == 0);
    }
}

static inline u32
__nsn_ringbuf_do_enqueue_elems(nsn_ringbuf_t *rb, const void *obj_table, u32 esize, u32 n, u32 *free_space)
{
    atu32 prod_head, prod_next;
    u32 free_entries;

    n = __nsn_ringbuf_move_prod_head(rb, n, &prod_head, &prod_next, &free_entries);
    if (n == 0)
    {
        log_trace("no free entries in ringbuf\n");
        goto end;
    }

    // now we can enqueue entries in the ring
    __nsn_ringbuf_enqueue_elems(rb, prod_head, obj_table, esize, n);

    // update producer tail
    while (at_load(&rb->prod.tail, mo_rlx) != prod_head) {
        nsn_pause();
    }

    at_store(&rb->prod.tail, prod_next, mo_rlx);

end:
    if (free_space != NULL)
        *free_space = free_entries - n;

    return n;
}

u32 
nsn_ringbuf_enqueue_burst(nsn_ringbuf_t *rb, const void *obj_table, u32 esize, u32 n, u32 *free_space)
{
    return __nsn_ringbuf_do_enqueue_elems(rb, obj_table, esize, n, free_space);
}

static inline u32
__nsn_ringbuf_move_cons_head(nsn_ringbuf_t *rb, u32 n, atu32 *old_head, atu32 *new_head, u32 *entries)
{
    u32 max = n;
    int success;

    do {
        n = max;

        *old_head = rb->cons.head;

        nsn_compiler_barrier();

        *entries = (rb->prod.tail - *old_head);

        if (nsn_unlikely(n > *entries))     n = *entries;
        if (nsn_unlikely(n == 0))           return 0;

        *new_head = *old_head + n;

        success = at_cas_weak(&rb->cons.head, old_head, *new_head, mo_rlx, mo_rlx);
    } while (nsn_unlikely(success == 0));

    return n;
}

static inline void
__nsn_ringbuf_dequeue_elems(nsn_ringbuf_t *rb, u32 cons_head, void *obj_table, u32 esize, u32 n)
{
    if (esize == 8) {
        u32 i;
        const u32 size = rb->size;
        u32 idx = cons_head & (size - 1);
        u64 *ring = (u64 *)&rb[1];
        u64 *dst = (u64 *)obj_table;

        if (nsn_likely(idx + n <= size)) {
            for (i = 0; i < (n & ~0x3); i += 4, idx += 4) {
                dst[i] = ring[idx];
                dst[i + 1] = ring[idx + 1];
                dst[i + 2] = ring[idx + 2];
                dst[i + 3] = ring[idx + 3];
            }
            switch (n & 0x3)
            {
            case 3: 
                dst[i++] = ring[idx++];
                nsn_fallthrough;
            case 2:
                dst[i++] = ring[idx++];
                nsn_fallthrough;
            case 1:
                dst[i++] = ring[idx++];
            }
        } else {
            for (i = 0; idx < size && i < n; i++, idx++)
                dst[i] = ring[idx];
            for (idx = 0; i < n; i++, idx++)
                dst[i] = ring[idx];
        }
    } else {
        assert("not implemented" == 0);
    }
}

static inline u32
__nsn_ringbuf_do_dequeue_elems(nsn_ringbuf_t *rb, void *obj_table, u32 esize, u32 n, u32 *available)
{
    atu32 cons_head, cons_next;
    u32 entries;

    n = __nsn_ringbuf_move_cons_head(rb, n, &cons_head, &cons_next, &entries);
    if (n == 0)
        goto end;

    // now we can dequeue entries from the ring
    __nsn_ringbuf_dequeue_elems(rb, cons_head, obj_table, esize, n);

    // NOTE(garbu): update consumer tail
    while (atomic_load_explicit(&rb->cons.tail, memory_order_relaxed) != cons_head)
        nsn_pause();

    atomic_store_explicit(&rb->cons.tail, cons_next, memory_order_release);

end:
    if (available != NULL)
        *available = entries - n;

    return n;
}

u32 
nsn_ringbuf_dequeue_burst(nsn_ringbuf_t *rb, void *obj_table, u32 esize, u32 n, u32 *available)
{
    return __nsn_ringbuf_do_dequeue_elems(rb, obj_table, esize, n, available);
}