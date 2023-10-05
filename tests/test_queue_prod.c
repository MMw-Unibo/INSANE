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

    open_shared_memory(SHM_NAME, SHM_SIZE, false, nsn_qtype_mpmc, &shm_info);

    atomic_store(shm_info.running, true);

    while (!queue_stop) {
        nsn_queue__push(shm_info.queue, 0);
    }

    close_shared_memory(&shm_info, SHM_NAME);

    return 0;
}