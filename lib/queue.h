#ifndef INSANE_QUEUE_H
#define INSANE_QUEUE_H

#include <immintrin.h>

#include "common.h"

#define CACHE_LINE_SIZE     64 // x86 cache line length.
#define MAX_QUEUE_NAME_SIZE CACHE_LINE_SIZE

#define SPIN_LOOP_PAUSE() _mm_pause()

typedef atomic_int_fast32_t  i32a;
typedef atomic_uint_fast32_t u32a;
typedef atomic_uint_fast64_t u64a;

//--------------------------------------------------------------------------------------------------
//    Lock-Free FIFO Queue MPMC
//--------------------------------------------------------------------------------------------------
typedef enum nsn_qtype {
    nsn_qtype_spsc,
    nsn_qtype_mpmc,
} nsn_qtype_t;

typedef struct nsn_queue {
    volatile nsn_qtype_t qtype;

    char name[MAX_QUEUE_NAME_SIZE];

    alignas(CACHE_LINE_SIZE) size_t size;
    alignas(CACHE_LINE_SIZE) u32a head;
    alignas(CACHE_LINE_SIZE) u32a tail;

    i32a e[];
} nsn_queue_t;

//--------------------------------------------------------------------------------------------------

i32 nsn_queue__init(nsn_queue_t *q, const char *name, size_t size, nsn_qtype_t qtype);

i32 nsn_queue__try_pop(nsn_queue_t *q);

i32 nsn_queue__pop(nsn_queue_t *q);

i32 nsn_queue__try_push(nsn_queue_t *q, i32 el);

void nsn_queue__push(nsn_queue_t *q, i32 el);

#endif // INSANE_QUEUE_H
