#ifndef TEST_QUEUE_H
#define TEST_QUEUE_H

#include <fcntl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <unistd.h>

#include <sys/mman.h>

#include <rte_eal.h>

#include <queue.h>

#define SHM_NAME         "nsn_test_queue"
#define SHM_SIZE         4096 * 4096
#define QUEUE_ELEMS_SIZE 32

struct shared_memory_info {
    int      shm_fd;
    uint8_t *buffer;
    uint8_t *offset;
    uint64_t total_memory;
    uint64_t used_memory;

    // nsn_queue_t *prod;
    atomic_bool *running;
    nsn_queue_t *queue;
};

int open_shared_memory(const char *name, size_t size, bool master, nsn_qtype_t qtype,
                       struct shared_memory_info *shm_info);

i32 close_shared_memory(struct shared_memory_info *shm_info, const char *name);

#endif // TEST_QUEUE_H