#include <fcntl.h>
#include <unistd.h>

#include <common.h>
#include <queue.h>

#include <sys/mman.h>

#include "test_queue.h"

bool queue_stop = false;

uint64_t counter = 0;

void handler(int signum) {
    fprintf(stderr, "counter = %ld\n", counter);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    signal(SIGINT, handler);

    int read_pipefd[2];
    int write_pipefd[2];

    if (pipe(read_pipefd) == -1) {
        perror("pipe");
        return -1;
    }

    if (pipe(write_pipefd) == -1) {
        perror("pipe");
        return -1;
    }

    pid_t child_pid = fork();
    if (child_pid == -1) {
        perror("fork");
        return -1;
    }

    int         tot_msg = 100;
    nsn_qtype_t qtype   = nsn_qtype_spsc;
    if (argc >= 2)
        tot_msg = atoi(argv[1]);
    if (argc >= 3)
        qtype = atoi(argv[2]);

    struct shared_memory_info shm_info;
    memset(&shm_info, 0, sizeof(struct shared_memory_info));

    if (child_pid == 0) { // Child
        int    start_msg;
        size_t ret = read(read_pipefd[0], &start_msg, sizeof(int));

        fprintf(stderr, "[child] recv = %d\n", start_msg);

        open_shared_memory(SHM_NAME, SHM_SIZE, false, qtype, &shm_info);

        ret = read(read_pipefd[0], &start_msg, sizeof(int));
        ret = write(write_pipefd[1], (void *)&start_msg, sizeof(int));

        for (size_t i = 0; i < tot_msg; i++) {
            nsn_queue__push(shm_info.queue, 0);
            counter++;
        }

        close_shared_memory(&shm_info, SHM_NAME);

        fprintf(stderr, "[child] exit...\n");

        start_msg = 2;
        ret       = write(write_pipefd[1], (void *)&start_msg, sizeof(int));

        (void)ret;

        exit(EXIT_SUCCESS);
    }

    open_shared_memory(SHM_NAME, SHM_SIZE, true, qtype, &shm_info);

    int    start_msg = 1;
    size_t ret       = write(read_pipefd[1], (void *)&start_msg, sizeof(int));

    printf("[parent] initializing stuff...\n");
    sleep(1);

    ret = write(read_pipefd[1], (void *)&start_msg, sizeof(int));
    ret = read(write_pipefd[0], &start_msg, sizeof(int));

    int      el;
    uint64_t start = get_clock_realtime_ns();
    for (size_t i = 0; i < tot_msg; i++) {
        el = nsn_queue__pop(shm_info.queue);
        if (el != 0)
            printf("el = %d\n", el);
        else
            counter++;
    }

    uint64_t end = get_clock_realtime_ns();

    ret = read(write_pipefd[0], &start_msg, sizeof(int));

    double elapsed = (double)(end - start) / 1000000000.0f;
    fprintf(stderr, "[parent] %ld msg in %fs -> %fmsg/s\n", counter, elapsed, counter / elapsed);

    close_shared_memory(&shm_info, SHM_NAME);

    (void)ret;

    return 0;
}