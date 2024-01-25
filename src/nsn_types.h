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

#define at_load(a, mo)                  atomic_load_explicit(a, mo)
#define at_store(a, v, mo)              atomic_store_explicit(a, v, mo)
#define at_xchg(a, v, mo)               atomic_exchange_explicit(a, v, mo)
#define at_cas(a, e, v, mo_s, mo_f)     atomic_compare_exchange_strong_explicit(a, e, v, mo_s, mo_f)
#define at_fadd(a, v, mo)               atomic_fetch_add_explicit(a, v, mo)
#define at_fsub(a, v, mo)               atomic_fetch_sub_explicit(a, v, mo)

// -----------------------------------------------------------------------------

#ifndef max
# define max(a, b) ((a) > (b) ? (a) : (b))
#endif
#ifndef min
# define min(a, b) ((a) < (b) ? (a) : (b))
#endif

#define nsn_unused(x) (void)(x)

#define array_count(a) (sizeof(a) / sizeof((a)[0]))

#define memory_zero(ptr, size)      memset(ptr, 0, size)
#define memory_zero_struct(ptr)     memory_zero(ptr, sizeof(*(ptr)))
#define memory_zero_array(ptr)      memory_zero(ptr, sizeof((ptr)[0]) * array_count(ptr))

#define kilobytes(x) ((x) * 1024ULL)
#define megabytes(x) (kilobytes(x) * 1024ULL)
#define gigabytes(x) (megabytes(x) * 1024ULL)

static inline usize align_to(usize value, usize alignment)   { return (value + (alignment - 1)) & ~(alignment - 1); }
static inline usize align_down(usize value, usize alignment) { return value & ~(alignment - 1); }
static inline bool  is_power_of_two(usize value)             { return (value & (value - 1)) == 0; }

#endif // NSN_TYPES_H
