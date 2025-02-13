// // --- include files -----------------------------------------------------------
// #include "nsn_types.h"
// #include "nsn.h"
// #include "nsn_os.h"
// #include "nsn_os_inc.h"
// #include "nsn_string.h"

// // --- c files -----------------------------------------------------------------
// #include "nsn.c"
// #include "nsn_memory.c"
// #include "nsn_os_inc.c"
// #include "nsn_shm.c"
// #include "nsn_string.c"
// #include "nsn_ringbuf.c"

// #define NSN_LOG_IMPLEMENTATION_H
// #include "nsn_log.h"

#define _GNU_SOURCE
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <nsn/nsn.h>

#define nsn_unused(x) ((void)(x))

// A simple macro used to check if there are enough command line args
#define ENSURE_ONE_MORE_ARGUMENT(argc, argv, i, argName)                                           \
    if (i + 1 >= argc) {                                                                           \
        usage(argc, argv);                                                                         \
        fprintf(stderr, "! Error: missing value for %s argument\n", argName);                      \
        return false;                                                                              \
    }

#define MSG              "That's INSANE!"
#define MAX_PAYLOAD_SIZE 1472
#define MIN_PAYLOAD_SIZE 16

typedef enum role {
    role_sink,
    role_source,
    role_ping,
    role_pong,
} role_t;

static char *role_strings[] = {"SINK", "SOURCE", "PING", "PONG"};
static char *dp_strings[]   = {"Slow", "Fast"};
static char *rel_strings[] = {"Unreliable", "Reliable"};

typedef struct test_config {
    role_t         role;
    uint32_t       payload_size;
    int            qos_datapath;
    int            qos_reliability;
    int64_t        app_source_id;
    uint64_t       sleep_time;
    uint64_t       max_msg;
} test_config_t;

struct test_data {
    uint64_t cnt;
    uint64_t tx_time;
    // char     msg[64];
};

volatile bool g_running  = true;
volatile bool queue_stop = false;

//--------------------------------------------------------------------------------------------------
void handle(int signum) {
    nsn_unused(signum);
    fprintf(stderr, "Received CTRL+C. Exiting!\n");
    g_running  = false;
    queue_stop = true;
}

//--------------------------------------------------------------------------------------------------
void usage(int argc, char *argv[]) {
    nsn_unused(argc);
    printf("Usage: %s [MODE] [OPTIONS]                        \n"
           "MODE: source|sink|ping|pong                       \n"
           "OPTIONS:                                          \n"
           "-h: display this message and exit                 \n"
           "-s: message payload size in bytes                 \n"
           "-n: max messages to send (0 = no limit)           \n"
           "-q: datapath QoS. Can be fast or slow             \n"
           "-r: reliability QoS. Can be reliable or unreliable\n"
           "-a: specify app-defined source id                 \n"
           "-t: configure sleep time (s) in send              \n",
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
void do_source(nsn_stream_t *stream, test_config_t *params) {
    // char             *msg     = MSG;
    uint64_t          counter = 0;
    nsn_buffer_t      buf;
    struct test_data *data;
    int               ret;

    nsn_source_t source = nsn_create_source(stream, params->app_source_id);

    uint64_t tx_time;
    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {

        if (params->sleep_time) {
            sleep(params->sleep_time);
        }

        tx_time = get_clock_realtime_ns();
        buf     = nsn_get_buffer(params->payload_size, 0);

        if (nsn_buffer_is_valid(&buf)) {
            data = (struct test_data *)buf.data;
            data->tx_time = tx_time;
            data->cnt     = counter++;
            // strncpy(data->msg, msg, strlen(msg) + 1);

            buf.len = params->payload_size;

            ret = nsn_emit_data(source, buf);
            // Check the outcome
            // TODO: unimplemented
            nsn_unused(ret);

            // LOG_DEBUG("%ld)\ttime: %ld (%lu)", counter, data->tx_time);
        }
    }
    printf("Finished sending %lu messages. Exiting...\n", counter);
    nsn_destroy_source(source);
}

//--------------------------------------------------------------------------------------------------
// sink
void do_sink(nsn_stream_t *stream, test_config_t *params) {

    nsn_sink_t sink = nsn_create_sink(stream, params->app_source_id, NULL);
    uint64_t   first_time = 0, last_time = 0;

    printf("Ready to receive packets\n");
    uint64_t counter = 0;
    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {

        nsn_buffer_t buf = nsn_consume_data(sink, NSN_BLOCKING);

        if (counter == 0) {
            first_time = get_clock_realtime_ns();
        }
        counter++;
        // struct test_data *data = (struct test_data *)buf.data;
        // fprintf(stderr, "(%ld) received: %ld, %s)\n", counter, data->cnt, data->msg);
        nsn_release_data(buf);
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
    
    nsn_destroy_sink(sink);
}

//--------------------------------------------------------------------------------------------------
// ping
void do_ping(nsn_stream_t *stream, test_config_t *params) {
    nsn_sink_t   sink   = nsn_create_sink(stream, params->app_source_id, NULL);
    nsn_source_t source = nsn_create_source(stream, params->app_source_id);

    // char  *msg     = MSG;
    // size_t msg_len = strlen(MSG);

    uint64_t          counter = 0;
    struct test_data *data;
    nsn_buffer_t      buf_recv, buf_send;
    uint64_t          send_time, response_time, latency;

    if(params->payload_size < sizeof(struct test_data)) {
        fprintf(stderr, "Payload size too small\n");
        return;
    }

    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {

        if (params->sleep_time) {
            sleep(params->sleep_time);
        }

        buf_send  = nsn_get_buffer(params->payload_size, NSN_BLOCKING);
        send_time = get_clock_realtime_ns();
        if (!nsn_buffer_is_valid(&buf_send)) {
            fprintf(stderr, "Failed to get buffer\n");
            continue;
        }
        
        data          = (struct test_data *)buf_send.data;
        data->cnt     = counter++;
        data->tx_time = send_time;
        buf_send.len  = params->payload_size;
        // strncpy(data->msg, msg, msg_len);
        nsn_emit_data(source, buf_send);

        buf_recv      = nsn_consume_data(sink, NSN_BLOCKING);
        response_time = get_clock_realtime_ns();
        latency       = response_time - send_time;
        nsn_release_data(buf_recv);
        
        fprintf(stdout, "%.3f\n", (float)latency / 1000.0f);
    }

    nsn_destroy_sink(sink);
    nsn_destroy_source(source);
}

//--------------------------------------------------------------------------------------------------
// pong
void do_pong(nsn_stream_t *stream, test_config_t *params) {
    uint64_t counter = 0;

    nsn_sink_t   sink   = nsn_create_sink(stream, params->app_source_id, NULL);
    nsn_source_t source = nsn_create_source(stream, params->app_source_id);

    nsn_buffer_t buf;
    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {
        buf = nsn_consume_data(sink, NSN_BLOCKING);
        if (!nsn_buffer_is_valid(&buf)) {
            fprintf(stderr, "Failing to receive. Continuing...\n");
            continue;
        }
        // fprintf(stderr, "Forwarding sample %lu idx=%lu\n",
        //           ((struct test_data *)buf.data)->cnt, buf.index);
        counter++;
        nsn_emit_data(source, buf);
    }

    nsn_destroy_sink(sink);
    nsn_destroy_source(source);
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
    config->role            = role_sink;
    config->payload_size    = strlen(MSG) + 1;
    config->qos_datapath    = NSN_QOS_DATAPATH_DEFAULT;
    config->qos_reliability = NSN_QOS_RELIABILITY_UNRELIABLE;
    config->app_source_id   = 0;
    config->sleep_time      = 0;
    config->max_msg         = 0;

    /* Test role (mandatory argument) */
    if (!strcmp(argv[1], "sink")) {
        config->role = role_sink;
    } else if (!strcmp(argv[1], "source")) {
        config->role = role_source;
    } else if (!strcmp(argv[1], "ping")) {
        config->role = role_ping;
    } else if (!strcmp(argv[1], "pong")) {
        config->role = role_pong;
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
            continue;
        }
        // QoS Datapath
        if (!strncmp(argv[i], "-q", 2) || !strncmp(argv[i], "--qos-dp", 8)) {
            ENSURE_ONE_MORE_ARGUMENT(argc, argv, i, "--qos-dp")
            i++;
            if (!strcmp(argv[i], "fast")) {
                config->qos_datapath = NSN_QOS_DATAPATH_FAST;
            } else if (!strcmp(argv[i], "slow")) {
                config->qos_datapath = NSN_QOS_DATAPATH_DEFAULT;
            } else {
                fprintf(stderr, "! Invalid value for --qos-dp option: %s\n", argv[i]);
                return -1;
            }
            continue;
        }
        // QoS Reliability
        if (!strncmp(argv[i], "-r", 2) || !strncmp(argv[i], "--qos-rel", 8)) {
            config->qos_reliability = NSN_QOS_RELIABILITY_RELIABLE;
            continue;
        }        
        // Source id
        if (!strncmp(argv[i], "-a", 2) || !strncmp(argv[i], "--app-source-id", 15)) {
            char *ptr;
            ENSURE_ONE_MORE_ARGUMENT(argc, argv, i, "--app-source-id")
            config->app_source_id = strtol(argv[++i], &ptr, 10);
            if (*ptr != '\0') {
                fprintf(stderr, "! Invalid value for --app-source-id option: %s\n", argv[i]);
                return -1;
            }
            continue;
        }
        // Sleep time
        if (!strncmp(argv[i], "-t", 2) || !strncmp(argv[i], "--sleep-time", 12)) {
            char *ptr;
            ENSURE_ONE_MORE_ARGUMENT(argc, argv, i, "--sleep-time")
            config->sleep_time = strtol(argv[++i], &ptr, 10);
            if (*ptr != '\0') {
                fprintf(stderr, "! Invalid value for sleep-time option: %s\n", argv[i]);
                return -1;
            }
            continue;
        }
    }

    // Print out the configuration
    printf("Running with the following arguments:   \n"
           "\tRole............. : %s                \n"
           "\tPayload size..... : %d                \n"
           "\tMax messages..... : %lu               \n"
           "\tDatapath QoS..... : %s                \n"
           "\tReliability QoS.. : %s                \n"
           "\tSource id........ : %ld               \n"
           "\tSleep time....... : %ld               \n\n",
           role_strings[config->role], config->payload_size, config->max_msg,
           dp_strings[config->qos_datapath], rel_strings[config->qos_reliability],
           config->app_source_id, config->sleep_time);

    return 0;
}

//--------------------------------------------------------------------------------------------------
// MAIN
int main(int argc, char *argv[]) {
    signal(SIGINT, handle);
    printf("Welcome to the test application of the INSANE middleware\n");

    /* Check test arguments */
    test_config_t params;
    if (parse_arguments(argc, argv, &params) < 0) {
        usage(argc, argv);
        return -1;
    }

    /* Init library */
    if (nsn_init() < 0) {
        fprintf(stderr, "Cannot init INSANE library\n");
        return -1;
    }

    /* Create stream */
    nsn_options_t options = {
            .consumption = NSN_QOS_CONSUMPTION_POLL, 
            .datapath = params.qos_datapath, 
            .determinism = NSN_QOS_DETERMINISM_DEFAULT,
            .reliability = params.qos_reliability};
    nsn_stream_t stream  = nsn_create_stream(options);

    /* Do test */
    if (params.role == role_sink) {
        do_sink(&stream, &params);
    } else if (params.role == role_source) {
        do_source(&stream, &params);
    } else if (params.role == role_ping) {
        do_ping(&stream, &params);
    } else if (params.role == role_pong) {
        do_pong(&stream, &params);
    } else {
        fprintf(stderr, "Test not supported\n");
        return -1;
    }

    /* Close library */
    nsn_destroy_stream(stream);
    nsn_close();

    return 0;
}