#include "lunar_pubsub.h"

size_t sub_cb(void *data) {
    struct test_msg *t = data;
    printf("test.x=%d\n", t->x);
}

int main(int argc, char **argv) {
    int   opt;
    char *transport = "udp";
    int   cpu       = -1;

    while ((opt = getopt(argc, argv, "t:c:")) != -1) {
        switch (opt) {
        case 'c':
            cpu = atoi(optarg);
            break;
        case 't':
            transport = optarg;
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

    lunar_init(transport);

    while (1) {
        lunar_sub("topic1", sub_cb, NULL);
    }

    lunar_close();
}