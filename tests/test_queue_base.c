#include "test_queue.h"

int open_shared_memory(const char *name, size_t size, bool master, nsn_qtype_t qtype,
                       struct shared_memory_info *shm_info) {
    int    flags = master ? (O_CREAT | O_EXCL | O_RDWR) : O_RDWR;
    mode_t mode  = master ? (S_IRUSR | S_IRUSR) : 0;

    int fd = shm_open(name, flags, mode);
    if (fd == -1) {
        perror("shm_open");
        return -1;
    }

    shm_info->shm_fd = fd;

    if (ftruncate(shm_info->shm_fd, size) == -1) {
        return -2;
    }

    shm_info->total_memory = size;

    uint8_t *buffer = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_info->shm_fd, 0);
    if (buffer == MAP_FAILED) {
        return -3;
    }

    const size_t queue_size = (sizeof(nsn_queue_t) + sizeof(i32a) * QUEUE_ELEMS_SIZE);

    shm_info->buffer = buffer;
    shm_info->offset = buffer;

    shm_info->running = (atomic_bool *)shm_info->offset;
    shm_info->used_memory += sizeof(atomic_bool);
    shm_info->offset += shm_info->used_memory;

    atomic_init(shm_info->running, false);

    fprintf(stderr, "running = %d\n", atomic_load(shm_info->running));

    shm_info->queue = (nsn_queue_t *)shm_info->offset;
    shm_info->used_memory += queue_size;
    shm_info->offset += shm_info->used_memory;

    if (master)
        nsn_queue__init(shm_info->queue, "queue", QUEUE_ELEMS_SIZE, qtype);

    fprintf(stderr, "[shm_init] queue type = %d\n", shm_info->queue->qtype);

    return 0;
}

i32 close_shared_memory(struct shared_memory_info *shm_info, const char *name) {
    munmap(shm_info->buffer, shm_info->total_memory);
    shm_unlink(name);
    close(shm_info->shm_fd);

    return 0;
}