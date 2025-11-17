#include "lunar_pubsub.h"

size_t sub_cb(void *data, void *args) {
    (void)args;  //Silence unused parameter warning
    struct test_msg *t = data;
    printf("test.x=%d\n", t->x);
    return sizeof(struct test_msg);
}

int main(int argc, char **argv) {
    int   opt;
    int   cpu       = -1;
    const char *role = "sub";

    while ((opt = getopt(argc, argv, "c:")) != -1) {
        switch (opt) {
        case 'c':
            cpu = atoi(optarg);
            break;
        default:
            print_usage_exit(argv[0]);
        }
    }

    if (cpu == -1)
        print_usage_exit(argv[0]);

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    if (sched_setaffinity(getpid(), sizeof(cpuset), &cpuset) < 0) {
        fprintf(stderr, "cannot set affinity: %s (%d)\n", strerror(errno), errno);
    }

    lunar_init();

    while (1) {
        lunar_sub(role,"topic1", sub_cb, NULL);
    }

    lunar_close();
}