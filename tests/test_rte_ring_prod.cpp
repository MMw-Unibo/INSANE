#include <errno.h>
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

#define N          50000000
#define BATCH_SIZE 32

static bool queue_stop = false;
static bool two_way    = true;
static bool do_burst   = false;
static int  count      = 0;

static const char *_TEST_RING_P = "TEST_RING_P";
static const char *_TEST_RING_C = "TEST_RING_C";

struct rte_ring *prod_ring;
struct rte_ring *cons_ring;

//--------------------------------------------------------------------------------------------------
inline uint64_t get_clock_realtime_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static void consume() {
    uint32_t available        = 0;
    int64_t  msgs[BATCH_SIZE] = {0};
    if (do_burst) {
        uint32_t n;
        do {
            n = rte_ring_dequeue_burst(prod_ring, (void **)&msgs, BATCH_SIZE, &available);
        } while (n == 0);
    } else {
        int64_t read;
        while (rte_ring_dequeue(prod_ring, (void **)&read) < 0)
            ;
    }
}

static int produce() {
    uint32_t available        = 0;
    int64_t  msgs[BATCH_SIZE] = {0};
    uint32_t n                = 0;
    if (do_burst) {
        n = rte_ring_enqueue_burst(cons_ring, (void **)msgs, BATCH_SIZE, &available);
    } else {
        if (rte_ring_enqueue(cons_ring, &count) == 0)
            n = 1;
        else
            n = 0;
    }
    return n;
}

int main(int argc, char **argv) {

    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Cannot init EAL\n");

    prod_ring = rte_ring_lookup(_TEST_RING_P);
    cons_ring = rte_ring_lookup(_TEST_RING_C);

    /* >8 End of ring structure. */
    if (!prod_ring || !cons_ring)
        rte_exit(EXIT_FAILURE, "Problem getting sending ring\n");

    uint32_t available        = 0;
    int64_t  msgs[BATCH_SIZE] = {0};

    if (!two_way)
        getchar();

    bool run = true;
    while (run) {
        if (two_way)
            consume();

        int n = produce();
        if (n == 0)
            continue;

        count += n;

        if (count >= N) {
            printf("stop");
            run = false;
        }
    }

    /* clean up the EAL */
    rte_eal_cleanup();

    return 0;
}
