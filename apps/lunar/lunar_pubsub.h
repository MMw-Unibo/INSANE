#ifndef LUNAR_PUBSUB_H
#define LUNAR_PUBSUB_H

#define _GNU_SOURCE 
#include <errno.h>
#include <getopt.h>
#include <sched.h>
#include <unistd.h>

#include "lunar.h"

struct test_msg {
    int x;
};

static inline void print_usage_exit(const char *prog_name) {
    fprintf(stderr, "Usage: %s -c CPU [-t [udp | trp]\n", prog_name);
    exit(EXIT_FAILURE);
}

#endif // LUNAR_PUBSUB_H
