#include <common.h>
#include <queue.h>

#include "test_queue.h"

bool queue_stop = false;

void handler(int signum) {
    queue_stop = true;
}

int main(int argc, char *argv[]) {
    signal(SIGINT, handler);

    int ret = 0;
    ret     = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "error with EAL initialization\n");

    struct shared_memory_info shm_info;
    memset(&shm_info, 0, sizeof(struct shared_memory_info));
    open_shared_memory(SHM_NAME, SHM_SIZE, true, nsn_qtype_mpmc, &shm_info);

    printf("[cons] initializing stuff...\n");

    int      el;
    uint64_t counter = 0;

    printf("[cons] waiting for producer...\n");

    while (!atomic_load(shm_info.running)) {
    }

    printf("[cons] start...\n");

    uint64_t start = get_clock_realtime_ns();
    while (!queue_stop) {
        el = nsn_queue__pop(shm_info.queue);
        if (el != 0)
            printf("el = %d\n", el);
        else
            counter++;
    }
    uint64_t end = get_clock_realtime_ns();

    double elapsed = (double)(end - start) / 1000000000.0f;
    fprintf(stderr, "[cons] %ld msg in %fs -> %fmsg/s\n", counter, elapsed, counter / elapsed);

    close_shared_memory(&shm_info, SHM_NAME);

    return 0;
}