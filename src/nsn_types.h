#ifndef NSN_TYPES_H
#define NSN_TYPES_H

#include "nsn_platform.h"

#if NSN_OS_LINUX
// # define __USE_MISC
# define _GNU_SOURCE
# include <dlfcn.h>
# include <fcntl.h>
# include <pthread.h>
# include <unistd.h>
# include <sys/mman.h>
# include <sys/socket.h>
# include <sys/stat.h>
# include <sys/types.h>
# include <sys/un.h>

# include <linux/mman.h>
#else
# error "Unsupported operating system"
#endif

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <limits.h>

typedef int8_t      i8;
typedef int16_t     i16;
typedef int32_t     i32;
typedef int64_t     i64;

typedef uint8_t     u8;
typedef uint16_t    u16;
typedef uint32_t    u32;
typedef uint64_t    u64;

typedef u8          byte;

typedef size_t      usize;
typedef intptr_t    isize;

typedef float       f32;
typedef double      f64;

// --- Atomic ------------------------------------------------------------------
typedef atomic_int_fast8_t      ati8;
typedef atomic_int_fast16_t     ati16;
typedef atomic_int_fast32_t     ati32;
typedef atomic_int_fast64_t     ati64;

typedef atomic_uint_fast8_t     atu8;
typedef atomic_uint_fast16_t    atu16;
typedef atomic_uint_fast32_t    atu32;
typedef atomic_uint_fast64_t    atu64;

#define mo_rlx      memory_order_relaxed
#define mo_con      memory_order_consume
#define mo_acq      memory_order_acquire
#define mo_rel      memory_order_release
#define mo_acq_rel  memory_order_acq_rel
#define mo_seq      memory_order_seq_cst

#define at_load(a, mo)                      atomic_load_explicit(a, mo)
#define at_store(a, v, mo)                  atomic_store_explicit(a, v, mo)
#define at_xchg(a, v, mo)                   atomic_exchange_explicit(a, v, mo)
#define at_cas(a, e, v, mo_s, mo_f)         atomic_compare_exchange_strong_explicit(a, e, v, mo_s, mo_f)
#define at_cas_weak(a, e, v, mo_s, mo_f)    atomic_compare_exchange_weak_explicit(a, e, v, mo_s, mo_f)
#define at_fadd(a, v, mo)                   atomic_fetch_add_explicit(a, v, mo)
#define at_fsub(a, v, mo)                   atomic_fetch_sub_explicit(a, v, mo)

// -----------------------------------------------------------------------------

#ifndef max
# define max(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef min
# define min(a, b) ((a) < (b) ? (a) : (b))
#endif

#define nsn_unused(x) (void)(x)

#define array_count(a) (sizeof(a) / sizeof((a)[0]))

#define memory_copy(dst, src, size) memcpy(dst, src, size)
#define memory_zero(ptr, size)      memset(ptr, 0, size)
#define memory_zero_struct(ptr)     memory_zero(ptr, sizeof(*(ptr)))
#define memory_zero_array(ptr)      memory_zero(ptr, sizeof((ptr)[0]) * array_count(ptr))

#define kilobytes(x) ((x) * 1024ULL)
#define megabytes(x) (kilobytes(x) * 1024ULL)
#define gigabytes(x) (megabytes(x) * 1024ULL)

static inline usize align_to(usize value, usize alignment)   { return (value + (alignment - 1)) & ~(alignment - 1); }
static inline usize align_down(usize value, usize alignment) { return value & ~(alignment - 1); }
static inline bool  is_power_of_two(usize value)             { return (value & (value - 1)) == 0; }

// --- Time --------------------------------------------------------------------
#define NSEC_PER_SEC    1000000000ULL
#define USEC_PER_SEC    1000000ULL
#define MSEC_PER_SEC    1000ULL

#define nsec_to_sec(nsec)   ((nsec) / NSEC_PER_SEC)
#define nsec_to_msec(nsec)  ((nsec) / (NSEC_PER_SEC / MSEC_PER_SEC))
#define nsec_to_usec(nsec)  ((nsec) / (NSEC_PER_SEC / USEC_PER_SEC))

// --- Collections Helpers -----------------------------------------------------

typedef struct list_head list_head_t;
struct list_head
{
    list_head_t *next;
    list_head_t *prev;
};

#define list_head_init(name)        ((list_head_t){ &(name), &(name) })
#define list_head(name)             list_head_t name = list_head_init(name)

static inline void list_init(list_head_t *h)                        { h->next = h; h->prev = h; }
static inline void list_add(list_head_t *h, list_head_t *n)         { n->next = h->next; n->prev = h; h->next->prev = n; h->next = n; }
static inline void list_add_tail(list_head_t *h, list_head_t *n)    { n->next = h; n->prev = h->prev; h->prev->next = n; h->prev = n; }
static inline bool list_empty(list_head_t *h)                     { return h->next == h; }

#ifndef typeof
#define typeof __typeof__
#endif
#ifndef offsetof
#define offsetof(type, member)                  ((size_t) &((type *)0)->member)
#endif
#ifndef container_of
#define container_of(ptr, type, member)         ((type *)((char *)(ptr)-offsetof(type, member)))
#endif
#define list_entry(ptr, type, member)           container_of(ptr, type, member)
#define list_first_entry(ptr, type, member)     list_entry((ptr)->next, type, member)
#define list_last_entry(ptr, type, member)      list_entry((ptr)->prev, type, member)
#define list_for_each(pos, head)                for (pos = (head)->next; pos != (head); pos = pos->next)
#define list_for_each_safe(pos, n, head)        for (pos = (head)->next, n = pos->next; pos != (head); pos = n, n = pos->next)
#define list_next_entry(pos, member)            list_entry((pos)->member.next, typeof(*(pos)), member)
#define list_for_each_entry(pos, head, member)  for (pos = list_first_entry(head, typeof(*pos), member); &pos->member != (head); pos = list_entry(pos->member.next, typeof(*pos), member))

#define nsn_list_push(head, tail, node) \
    do {                                \
        if (head == NULL) {             \
            head = tail = node;         \
        } else {                        \
            tail->next = node;          \
            tail = node;                \
            node->next = NULL;          \
        }                               \
    } while (0)

#endif // NSN_TYPES_H
