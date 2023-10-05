#ifndef INSANE_COMMON_H
#define INSANE_COMMON_H

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   i8;
typedef int16_t  i16;
typedef int32_t  i32;
typedef int64_t  i64;

typedef float  f32;
typedef double f64;

typedef i32 nsn_appid_t;
typedef i8  nsn_error_t;

#define SHM_MAX_PATH      256
#define IPC_MAX_PATH_SIZE 100

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) ((sizeof x) / (sizeof x[0]))
#endif

#define nsn_likely(expr)   __builtin_expect(!!(expr), 1)
#define nsn_unlikely(expr) __builtin_expect(!!(expr), 0)

#define nsn_mem_a memory_order_acquire
#define nsn_mem_r memory_order_release
#define nsn_mem_s memory_order_seq_cst
#define nsn_mem_x memory_order_relaxed

#define nsn_atomic_ld        atomic_load_explicit
#define nsn_atomic_sd        atomic_store_explicit
#define nsn_atomic_cmp_xchg  atomic_compare_exchange_strong_explicit
#define nsn_atomic_fetch_add atomic_fetch_add_explicit
#define nsn_atomic_xchg      atomic_exchange_explicit

#define __nsn_packed __attribute__((packed))

u64 get_clock_realtime_ns();

// uint32_t parse_ipv4_string(char* addr) {
//     uint8_t addr_bytes[4];
//     sscanf(addr, "%hhu.%hhu.%hhu.%hhu", &addr_bytes[3], &addr_bytes[2],
//     &addr_bytes[1], &addr_bytes[0]); return addr_bytes[0] | addr_bytes[1] <<
//     8 | addr_bytes[2] << 16 | addr_bytes[3] << 24;
// }

typedef enum mempool_type {
    mempool_dpdk,
    mempool_socket,
} mempool_type_t;

#endif // INSANE_COMMON_H
