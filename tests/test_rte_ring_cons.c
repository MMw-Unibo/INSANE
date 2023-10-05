#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_ring.h>

#define N               50000000
#define BATCH_SIZE      32

static const char    *_TEST_RING_P = "TEST_RING_P";
static const char    *_TEST_RING_C = "TEST_RING_C";
static const unsigned RING_SIZE  = 1024;

struct rte_ring *prod_ring;
struct rte_ring *cons_ring;

bool queue_stop; // NOTE(garbu): unused

//--------------------------------------------------------------------------------------------------
inline uint64_t get_clock_realtime_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

int main(int argc, char **argv) {
    const unsigned flags     = RING_F_SP_ENQ | RING_F_SC_DEQ;
    const unsigned ring_size = RING_SIZE;

    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Cannot init EAL\n");

    prod_ring = rte_ring_create(_TEST_RING_P, ring_size, rte_socket_id(), flags);
    cons_ring = rte_ring_create(_TEST_RING_C, ring_size, rte_socket_id(), flags);

    /* >8 End of ring structure. */
    if (!prod_ring || !cons_ring)
        rte_exit(EXIT_FAILURE, "Problem getting receiving ring\n");

    int64_t count       = 0;
    int64_t *msg[BATCH_SIZE] = {0};
    uint32_t available = 0;
    uint64_t start      = 0;
    uint64_t end        = 0;

    bool two_way  = true;
    bool do_burst = true; 

    if (two_way)
        getchar();

    while (1) {
        if (two_way) 
        {
            if (do_burst)
            {
                uint32_t n;
                do {
                    n = rte_ring_enqueue_burst(prod_ring, (void **)msg, BATCH_SIZE, &available);
                } while (n == 0);
            }
            else
            {
                while (rte_ring_enqueue(prod_ring, (void *)count) < 0)
                    ;
            }
        }

        uint32_t n;
        if (do_burst)
        {
            n = rte_ring_dequeue_burst(cons_ring, (void **)msg, BATCH_SIZE, &available);
            if (n == 0)
                continue;
        }
        else  
        {
            if (rte_ring_dequeue(cons_ring, (void **)&msg) < 0)
                continue;
            else
                n = 1;
        }
            
        if (count == 0) {
            start = get_clock_realtime_ns();
        } 
    
        count += n;
        if (count >= N)
            break;
    }

    end = get_clock_realtime_ns();

    double elapsed = (double)(end - start) / 1000000000.0f;
    fprintf(stderr, "[info] %ld msg in %fs -> %.2fMmsg/s\n", count, elapsed, 
            (count / elapsed) / 1000000.0f);

    /* clean up the EAL */
    rte_eal_cleanup();

    return 0;
}
