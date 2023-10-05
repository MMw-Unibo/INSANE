#include "queue.h"

#include "insane/logger.h"

extern bool queue_stop;

//--------------------------------------------------------------------------------------------------
i32 nsn_queue__init(nsn_queue_t *q, const char *name, size_t size, nsn_qtype_t qtype) {
    if (!q)
        return -1;

    q->qtype = qtype;
    q->size  = size;
    q->head  = 0;
    q->tail  = 0;

    strncpy(q->name, name, MAX_QUEUE_NAME_SIZE - 1);

    memset(q->e, -1, q->size * sizeof(i32a));

    return 0;
}

//--------------------------------------------------------------------------------------------------
i32 nsn_queue__try_pop(nsn_queue_t *q) {
    u32a tail = nsn_atomic_ld(&q->tail, nsn_mem_x);

    do {
        if ((i32)(nsn_atomic_ld(&q->head, nsn_mem_x) - tail) <= 0)
            return -1;

    } while (nsn_unlikely(!nsn_atomic_cmp_xchg(&q->tail, &tail, tail + 1, nsn_mem_a, nsn_mem_x)));

    u32 idx = tail % q->size;

    for (;;) {
        i32 el = nsn_atomic_xchg(&q->e[idx], -1, nsn_mem_r);
        if (nsn_likely(el != -1))
            return el;

        do {
            SPIN_LOOP_PAUSE();
        } while (nsn_atomic_ld(&q->e[idx], nsn_mem_x) == -1);
    }
}

//--------------------------------------------------------------------------------------------------
i32 nsn_queue__pop(nsn_queue_t *q) {
    u32   tail;
    u32   i;
    i32   el;
    i32a *e;
    switch (q->qtype) {
    case nsn_qtype_mpmc:
        tail = nsn_atomic_fetch_add(&q->tail, 1, nsn_mem_s);
        i    = tail % q->size;
        e    = &q->e[i];
        for (;;) {
            el = nsn_atomic_xchg(e, -1, nsn_mem_r);
            if (nsn_likely(el != -1)) {
                // if (el > q->size * 8) {
                //     printf("%d %d %ld %ld %d\n", i, tail, q->tail, q->head, el);
                //     return 0;
                // }
                return el;
            }
            do {
                SPIN_LOOP_PAUSE();
                if (queue_stop)
                    return -1;
            } while (nsn_atomic_ld(e, nsn_mem_x) == -1);
        }
        break;
    case nsn_qtype_spsc:
        tail = nsn_atomic_ld(&q->tail, nsn_mem_x);
        nsn_atomic_sd(&q->tail, tail + 1, nsn_mem_x);
        i = tail % q->size;
        e = &q->e[i];
        for (;;) {
            el = nsn_atomic_ld(e, nsn_mem_x);
            if (nsn_likely(el != -1)) {
                nsn_atomic_sd(e, -1, nsn_mem_r);
                return el;
            }

            SPIN_LOOP_PAUSE();
        }
        break;
    }

    return -1;
}

//--------------------------------------------------------------------------------------------------
i32 nsn_queue__try_push(nsn_queue_t *q, i32 el) {
    u32a head = nsn_atomic_ld(&q->head, nsn_mem_x);

    do {
        if ((int)(head - nsn_atomic_ld(&q->tail, nsn_mem_x)) >= (int)(q->size))
            return -1;
    } while (nsn_unlikely(!nsn_atomic_cmp_xchg(&q->head, &head, head + 1, nsn_mem_a, nsn_mem_x)));

    u32a idx = head % q->size;

    for (i32a ex                                                                           = -1;
         nsn_unlikely(!nsn_atomic_cmp_xchg(&q->e[idx], &ex, el, nsn_mem_r, nsn_mem_x)); ex = -1)
    {
        do {
            SPIN_LOOP_PAUSE();
        } while (nsn_atomic_ld(&q->e[idx], nsn_mem_x) != -1);
    }

    return 0;
}

//--------------------------------------------------------------------------------------------------
void nsn_queue__push(nsn_queue_t *q, i32 el) {
    u32   head;
    u32   i;
    i32a *e;
    switch (q->qtype) {
    case nsn_qtype_mpmc:
        head    = nsn_atomic_fetch_add(&q->head, 1, nsn_mem_s);
        i       = head % q->size;
        i32a ex = -1;
        while (nsn_unlikely(!nsn_atomic_cmp_xchg(&q->e[i], &ex, el, nsn_mem_r, nsn_mem_x))) {
            do {
                SPIN_LOOP_PAUSE();
                if (queue_stop)
                    return;
            } while (nsn_atomic_ld(&q->e[i], nsn_mem_x) != -1);
        }
        ex = -1;
        break;
    case nsn_qtype_spsc:
        head = nsn_atomic_ld(&q->head, nsn_mem_x);
        nsn_atomic_sd(&q->head, head + 1, nsn_mem_x);
        i = head % q->size;
        e = &q->e[i];
        while (nsn_unlikely(nsn_atomic_ld(e, nsn_mem_x) != -1))
            SPIN_LOOP_PAUSE();

        nsn_atomic_sd(e, el, nsn_mem_r);
        break;
    }
}