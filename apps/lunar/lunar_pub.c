#include "lunar_pubsub.h"

size_t pub_cb(void *data, void *args) {
    (void)args;  //Silence unused parameter warning
    struct test_msg *t = data;
    t->x               = 2;

    return sizeof(*t);
}

int main(int argc, char **argv) {
    int   opt;
    const char *role = "pub";
    //char *transport = "udp";
    int   cpu       = -1;

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
        lunar_pub(role,"topic1", pub_cb, NULL);
        sleep(1);
    }

    lunar_close();
}