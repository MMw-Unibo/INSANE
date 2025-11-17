#include "lunar_pubsub.h"

#include <signal.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_mempool.h>




// A simple macro used to check if there are enough command line args
#define ENSURE_ONE_MORE_ARGUMENT(argc, argv, i, argName)                                           \
    if (i + 1 >= argc) {                                                                           \
        usage(argc, argv);                                                                         \
        fprintf(stderr, "! Error: missing value for %s argument\n", argName);                      \
        return false;                                                                              \
    }

#define MAX_TOPIC_NAME_SIZE 32

#define MSG              "hello, DPDK!"
#define MAX_PAYLOAD_SIZE 9000
#define MIN_PAYLOAD_SIZE 16

typedef enum role {
    role_sub,
    role_pub,
    role_pubsub,
    role_subpub,
} role_t;

const char *role_to_string(role_t role) {
    switch (role) {
        case role_sub:    return "sub";
        case role_pub:    return "pub";
        case role_pubsub: return "pubsub";
        case role_subpub: return "subpub";
        default:          return "unknown";
    }
}

static char *role_strings[] = {"SUBSCRIBER", "PUBLISHER", "PUB/SUB", "SUB/PUB"};
static char *dp_strings[]   = {"Slow", "Fast"};

typedef struct test_config {
    role_t         role;
    uint32_t       payload_size;
    int            qos_datapath;
    //int            qos_reliability;
    //int            qos_consumption;
    char           topic[MAX_TOPIC_NAME_SIZE];
    uint64_t       sleep_time;
    uint64_t       max_msg;
} test_config_t;

struct test_data {
    uint64_t payload_size;
    char msg[];
};

volatile bool g_running  = true;
volatile bool queue_stop = false;

//--------------------------------------------------------------------------------------------------
void handle(int signum) {
    (void)signum;
    fprintf(stderr, "Received CTRL+C. Exiting!\n");
    g_running  = false;
    queue_stop = true;
}

//--------------------------------------------------------------------------------------------------
void usage(int argc, char *argv[]) {
    (void)argc;
    printf("Usage: %s [MODE] [OPTIONS]                  \n"
           "MODE: pub|sub|pubsub|subpub                 \n"
           "OPTIONS:                                    \n"
           "-h: display this message and exit           \n"
           "-s: message payload size in bytes           \n"
           "-n: max messages to send (0 = no limit)     \n"
           "-q: quality. Can be fast or slow            \n"
           "-t: specify topic name                      \n"
           "-r: configure sleep time (us) in send       \n",
           argv[0]);
}

//--------------------------------------------------------------------------------------------------
static inline uint64_t get_clock_realtime_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

//--------------------------------------------------------------------------------------------------
// source

size_t pub_cb(void *data, void *arg) {
    struct test_data *t = (struct test_data *)arg;
    size_t len = sizeof(t->payload_size) + (size_t)t->payload_size;
    memcpy(data, t, len);
    return len;
}

void do_pub(test_config_t *params) {
    uint64_t          counter = 0;
    struct test_data *data;
    const char *role = role_to_string(params->role);
    data = malloc(sizeof(*data) + params->payload_size);
    data->payload_size = params->payload_size;

    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {
        if (params->sleep_time) {
            usleep(params->sleep_time);
        }
        //tx_time = get_clock_realtime_ns();
        lunar_pub(role, params->topic, pub_cb, (void *)data);
        counter++;
    }
    printf("Finished sending %lu messages. Exiting...\n", counter);
    lunar_destroy_source(params->topic);
    free(data);
}

//--------------------------------------------------------------------------------------------------
size_t sub_cb(void *data, void *args) {
    (void)args;  //Silence unused parameter warning
    struct test_data *t = (struct test_data *)data;
    return t->payload_size;
}

void do_sub(test_config_t *params) {
    struct test_data *data;
    uint64_t first_time, last_time;
    const char *role = role_to_string(params->role);
    data = malloc(sizeof(*data) + params->payload_size);
    data->payload_size = params->payload_size;
    printf("Ready to receive packets\n");
    uint64_t counter = 0;
    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {
        if (counter == 0) {
            first_time = get_clock_realtime_ns();
        }
        lunar_sub(role, params->topic, sub_cb, (void *)data);
        counter++;
    }
    last_time = get_clock_realtime_ns();

    /* Compute results */
    uint64_t elapsed_time_ns = last_time - first_time;
    double   mbps =
        ((counter * params->payload_size * 8) * ((double)1e3)) / ((double)elapsed_time_ns);
    double throughput = ((counter) * ((double)1e3)) / ((double)elapsed_time_ns);

    /* Print results */
    fprintf(stdout,
            "[ TEST RESULT ]                 \n"
            "Received messages:   %lu        \n"
            "Elapsed time:        %.3f ms    \n"
            "Measured throughput: %.3f Mmsg/s\n"
            "Measured banwdidth:  %.3f Mbps  \n\n",
            counter, (double)elapsed_time_ns / ((double)1e6), throughput, mbps);

    fprintf(stdout, "%lu,%u,%.3f,%.3f,%.3f\n", counter, params->payload_size,
            (double)elapsed_time_ns / ((double)1e6), throughput, mbps);
    lunar_destroy_sink(params->topic);
    free(data);
}

//--------------------------------------------------------------------------------------------------
// ping
size_t pubsub_ping_cb(void *data, void *arg) {
    struct test_data *t = (struct test_data *)arg;
    size_t len = sizeof(t->payload_size) + (size_t)t->payload_size;
    memcpy(data, t, len);
    return len;
}

size_t pubsub_pong_cb(void *data, void *arg) {
    (void)arg;  //Silence unused parameter warning
    struct test_data *t = (struct test_data *)data;

    // Do something with the data
    return t->payload_size;
}
void do_pubsub(test_config_t *params) {
    uint64_t          counter = 0;
    struct test_data *data;
    uint64_t          send_time, response_time, latency;
    const char *role = role_to_string(params->role);

    data               = malloc(sizeof(*data) + params->payload_size);
    data->payload_size = params->payload_size;

    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {
        if (params->sleep_time) {
            usleep(params->sleep_time);
        }

        // Send ping
        send_time = get_clock_realtime_ns();
        lunar_pub(role, params->topic, pubsub_ping_cb, (void *)data);

        // Receive Pong
        lunar_sub(role, params->topic, pubsub_pong_cb, (void *)data);
        response_time = get_clock_realtime_ns();

        // Compute and print RTT
        counter++;
        latency = response_time - send_time;
        fprintf(stdout, "(%ld) RTT: %.3f us\n", counter, (float)latency / 1000.0F);
    }
    lunar_destroy_sink(params->topic);
    lunar_destroy_source(params->topic);
    free(data);
}

//--------------------------------------------------------------------------------------------------
// pong
size_t subpub_ping_cb(void *data, void *arg) {
    struct test_data *t = (struct test_data *)data;
    memcpy(arg, data, t->payload_size);
    return t->payload_size;
}
size_t subpub_pong_cb(void *data, void *arg) {
    struct test_data *t = (struct test_data *)arg;
    size_t len = sizeof(t->payload_size)+(size_t)t->payload_size;
    memcpy(data, t, len);
    return len;
}
void do_subpub(test_config_t *params) {
    uint64_t counter = 0;
    const char *role = role_to_string(params->role);

    struct test_data *data = malloc(sizeof(*data) + params->payload_size);
    data->payload_size = params->payload_size;
    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {

        lunar_sub(role, params->topic, subpub_ping_cb, (void *)data);
        //LOG_TRACE("Forwarding sample\n");
        lunar_pub(role, params->topic, subpub_pong_cb, (void *)data);

        counter++;
    }

    lunar_destroy_sink(params->topic);
    lunar_destroy_source(params->topic);
    free(data);
}

//--------------------------------------------------------------------------------------------------
int parse_arguments(int argc, char *argv[], test_config_t *config) {
    /* Argument number */
    if (argc < 2) {
        fprintf(stderr, "! Invalid number of arguments\n"
                        "! You must specify at least the running MODE\n");
        return -1;
    }
    /* Default values */
    config->role         = role_sub;
    config->payload_size = strlen(MSG) + 1;
    config->qos_datapath = NSN_QOS_DATAPATH_DEFAULT;
    strcpy(config->topic, "default");
    config->sleep_time = 0;
    config->max_msg    = 0;

    /* Test role (mandatory argument) */
    if (!strcmp(argv[1], "sub")) {
        config->role = role_sub;
    } else if (!strcmp(argv[1], "pub")) {
        config->role = role_pub;
    } else if (!strcmp(argv[1], "pubsub")) {
        config->role = role_pubsub;
    } else if (!strcmp(argv[1], "subpub")) {
        config->role = role_subpub;
    } else if (!strncmp(argv[1], "-h", 2) || !strncmp(argv[1], "--help", 6)) {
        return -1; // Success, but termination required
    } else {
        fprintf(stderr, "Unrecognized argument: %s\n", argv[1]);
        return -1;
    }

    /* Parse the optional arguments */
    for (int i = 2; i < argc; ++i) {
        // Helper
        if (!strncmp(argv[i], "-h", 2) || !strncmp(argv[i], "--help", 6)) {
            return -1; // Success, but termination required
        }
        // Message payload size
        if (!strncmp(argv[i], "-s", 2) || !strncmp(argv[i], "--size", 6)) {
            char *ptr;
            ENSURE_ONE_MORE_ARGUMENT(argc, argv, i, "--size")
            config->payload_size = strtol(argv[++i], &ptr, 10);
            if (*ptr != '\0') {
                fprintf(stderr, "! Invalid value for --size option: %s\n", argv[i]);
                return -1;
            }
            if (config->payload_size <= MIN_PAYLOAD_SIZE || config->payload_size > MAX_PAYLOAD_SIZE)
            {
                fprintf(stderr, "! Invalid value for --size option: %s\n", argv[i]);
                return -1;
            }
            continue;
        }
        // Max number of messages
        if (!strncmp(argv[i], "-n", 2) || !strncmp(argv[i], "--num-msg", 9)) {
            char *ptr;
            ENSURE_ONE_MORE_ARGUMENT(argc, argv, i, "--num-msg")
            config->max_msg = strtol(argv[++i], &ptr, 10);
            if (*ptr != '\0') {
                fprintf(stderr, "! Invalid value for --size option: %s\n", argv[i]);
                return -1;
            }
            if (config->max_msg == 0) {
                fprintf(stderr, "! max_msg: %s\n", argv[i]);
                return -1;
            }
            continue;
        }
        // Datapath qos
        if (!strncmp(argv[i], "-q", 2) || !strncmp(argv[i], "--dp-qos", 8)) {
            ENSURE_ONE_MORE_ARGUMENT(argc, argv, i, "--dp-qos")
            i++;
            if (!strcmp(argv[i], "fast")) {
                config->qos_datapath = NSN_QOS_DATAPATH_FAST;
            } else if (!strcmp(argv[i], "slow")) {
                config->qos_datapath = NSN_QOS_DATAPATH_DEFAULT;
            } else {
                fprintf(stderr, "! Invalid value for --dp-qos option: %s\n", argv[i]);
                return -1;
            }
            continue;
        }
        // Source id
        if (!strncmp(argv[i], "-t", 2) || !strncmp(argv[i], "--topic", 7)) {
            //char *ptr;
            ENSURE_ONE_MORE_ARGUMENT(argc, argv, i, "--topic")
            strcpy(config->topic, argv[++i]);
            continue;
        }

        // Sleep time
        if (!strncmp(argv[i], "-r", 2) || !strncmp(argv[i], "--sleep-time", 12)) {
            char *ptr;
            ENSURE_ONE_MORE_ARGUMENT(argc, argv, i, "--sleep-time")
            config->sleep_time = strtol(argv[++i], &ptr, 10);
            if (*ptr != '\0') {
                fprintf(stderr, "! Invalid value for sleep-time option: %s\n", argv[i]);
                return -1;
            }
            /*
            if (config->sleep_time < 0) {
                fprintf(stderr, "! Invalid value for --size option: %s\n", argv[i]);
                return -1;
            }*/
            continue;
        }
    }

    // Print out the configuration
    printf("Running with the following arguments:   \n"
           "\tRole............. : %s                \n"
           "\tPayload size..... : %d                \n"
           "\tMax messages..... : %lu               \n"
           "\tDatapath QoS..... : %s                \n"
           "\tTopic............ : %s                \n"
           "\tSleep time....... : %ld               \n\n",
           role_strings[config->role], config->payload_size, config->max_msg,
           dp_strings[config->qos_datapath], config->topic, config->sleep_time);

    return 0;
}

//--------------------------------------------------------------------------------------------------
// MAIN
int main(int argc, char *argv[]) {
    signal(SIGINT, handle);

    /* Check test arguments */
    test_config_t params;
    if (parse_arguments(argc, argv, &params) < 0) {
        usage(argc, argv);
        return -1;
    }

    /* Init library */
    if (lunar_init() < 0) {
        fprintf(stderr, "Cannot init LUNAR MoM\n");
        return -1;
    }

    /* Do test */
    if (params.role == role_sub) {
        do_sub(&params);
    } else if (params.role == role_pub) {
        do_pub(&params);
    } else if (params.role == role_pubsub) {
        do_pubsub(&params);
    } else if (params.role == role_subpub) {
        do_subpub(&params);
    } else {
        fprintf(stderr, "Test not supported\n");
        return -1;
    }

    /* Close MoM */
    lunar_close();

    return 0;
}