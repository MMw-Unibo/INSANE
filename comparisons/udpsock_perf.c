#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define unused(x) (void)(x)

#define ENSURE_ONE_MORE_ARGUMENT(argc, argv, i, argName)                                           \
    if (i + 1 >= argc) {                                                                           \
        usage(argc, argv);                                                                         \
        fprintf(stderr, "! Error: missing value for %s argument\n", argName);                      \
        return 0;                                                                                  \
    }

#define MSG              "hello, DPDK!"
#define MAX_PAYLOAD_SIZE 1472
#define MIN_PAYLOAD_SIZE 16

#define INSANE_PORT    9999
#define DST_QUEUE_SIZE 4194304

#define IP_SRC "192.168.56.211"
#define IP_DST "192.168.56.212"

typedef enum role {
    role_sink,
    role_source,
    role_ping,
    role_pong,
} role_t;

static char *role_strings[] = {"SINK", "SOURCE", "PING", "PONG"};

typedef struct test_config {
    role_t             role;
    uint32_t           payload_size;
    uint64_t           sleep_time;
    uint64_t           max_msg;
    uint16_t           port_id;
    uint16_t           queue_id;
    uint8_t            blocking;
    struct sockaddr_in dst_addr;

} test_config_t;

struct test_data {
    uint64_t cnt;
    uint64_t tx_time;
    // char     msg[64];
};

volatile uint8_t g_running  = 1;
volatile uint8_t queue_stop = 0;

//--------------------------------------------------------------------------------------------------
void handle(int signum) {
    
    unused(signum);
    fprintf(stderr, "Received CTRL+C. Exiting!\n");
    g_running  = 0;
    queue_stop = 1;
    exit(0);
}

//--------------------------------------------------------------------------------------------------
void usage(int argc, char *argv[]) {
    unused(argc);
    printf("Usage: %s [MODE] [OPTIONS]                   \n"
           "MODE: source|sink|ping|pong                  \n"
           "OPTIONS:                                     \n"
           "-h: display this message and exit            \n"
           "-s: message payload size in bytes            \n"
           "-n: max messages to send (0 = no limit)      \n"
           "-r: configure sleep time (s) in send         \n"
           "-b: configure recv socket to be non-blocking \n",
           argv[0]);
}

//--------------------------------------------------------------------------------------------------
static inline uint64_t get_clock_realtime_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

//--------------------------------------------------------------------------------------------------
void do_source(int sd, test_config_t *params) {
    // char             *msg     = MSG;
    uint64_t          counter = 0;
    char             *payload;
    struct test_data *data;
    int               ret;

    // Allocate payload of proper size
    payload = (char *)malloc(params->payload_size);
    bzero(payload, params->payload_size);

    uint64_t tx_time;
    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {

        if (params->sleep_time) {
            sleep(params->sleep_time);
        }

        tx_time = get_clock_realtime_ns();

        // Fill it up the buffer
        data          = (struct test_data *)payload;
        data->tx_time = tx_time;
        data->cnt     = counter++;
        // strncpy(data->msg, msg, strlen(msg) + 1);

        ret = sendto(sd, payload, params->payload_size, 0, (struct sockaddr *)&params->dst_addr,
                     sizeof(params->dst_addr));
        if (ret < 0) {
            perror("Error sending UDP packet");
            break;
        }
        // fprintf(stdout, "Sent %d bytes\n", ret);
    }
    printf("Finished sending %lu messages. Exiting...\n", counter);
    free(payload);
}

//--------------------------------------------------------------------------------------------------
void do_sink(int sd, test_config_t *params) {
    char             *payload;
    uint64_t          first_time = 0, last_time = 0;
    uint64_t          counter = 0;
    ssize_t           nb_rx;

    // Allocate payload of proper size
    payload = (char *)malloc(params->payload_size);
    bzero(payload, params->payload_size);

    printf("Ready to receive data\n");
    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {

        // If blocking, this will just block, read, and continue. If non-blocking, -1 is returned
        // and we busy-loop until we receive any data
        while ((nb_rx = recvfrom(sd, payload, params->payload_size, 0, NULL, NULL)) <= 0)
            ;
        if (params->blocking && nb_rx < 0) {
            perror("Error receiving UDP message");
        }


        if (counter == 0) {
            first_time = get_clock_realtime_ns();
        }

        counter++;

        // struct test_data *data = (struct test_data *)payload;
        // fprintf(stderr, "(%ld) received: %ld, %s)\n", counter, *data.cnt, *data.msg);
    }
    last_time = get_clock_realtime_ns();

    free(payload);

    /* Compute results */
    uint64_t elapsed_time_ns = last_time - first_time;
    double   mbps =
        ((counter * params->payload_size * 8) * ((double)1e3)) / ((double)elapsed_time_ns);
    double throughput = ((counter) * ((double)1e3)) / ((double)elapsed_time_ns);

    /* Print results */
    // fprintf(stdout,
    //         "[ TEST RESULT ]                 \n"
    //         "Received messages:   %lu        \n"
    //         "Elapsed time:        %.3f ms    \n"
    //         "Measured throughput: %.3f Mmsg/s\n"
    //         "Measured banwdidth:  %.3f Mbps  \n\n",
    //         counter, (double)elapsed_time_ns / ((double)1e6), throughput, mbps);
    fprintf(stdout, "%lu,%u,%.3f,%.3f,%.3f\n", counter, params->payload_size,
            (double)elapsed_time_ns / ((double)1e6), throughput, mbps);
}

//--------------------------------------------------------------------------------------------------
void do_ping(int sd, test_config_t *params) {
    // char            *msg     = MSG;
    uint64_t         counter = 0;
    uint64_t         send_time, response_time, latency;
    ssize_t          ret;

    if(params->payload_size < sizeof(struct test_data)) {
        fprintf(stderr, "Payload size too small\n");
        return;
    }
    struct test_data *data = (struct test_data*)malloc(params->payload_size);

    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {

        if (params->sleep_time) {
            sleep(params->sleep_time);
        }

        /* Take time*/
        send_time = get_clock_realtime_ns();

        /* Fill the packet */
        data->tx_time = send_time;
        data->cnt     = counter++;
        // strncpy(data.msg, msg, strlen(msg) + 1);

        /* Send the packet */
        ret = sendto(sd, data, params->payload_size, 0, (struct sockaddr *)&params->dst_addr,
                     sizeof(params->dst_addr));
        if (ret < 0) {
            perror("Error sending UDP packet");
            break;
        }
        // fprintf(stdout, "(%lu) time: %ld", counter, send_time);

        /* Wait for pong */
        while ((ret = recvfrom(sd, data, params->payload_size, 0, NULL, NULL)) <= 0)
            ;
        if (params->blocking && ret < 0) {
            perror("Error receiving UDP message");
        }

        /* Compute latency */
        response_time = get_clock_realtime_ns();
        latency       = response_time - send_time;

        fprintf(stdout, "%.3f\n", (float)latency / 1000.0f);
    }

    free(data);
}

//--------------------------------------------------------------------------------------------------
void do_pong(int sd, test_config_t *params) {
    ssize_t          ret;
    uint64_t         counter = 0;

    if(params->payload_size < sizeof(struct test_data)) {
        fprintf(stderr, "Payload size too small\n");
        return;
    }
    struct test_data *data = (struct test_data*)malloc(params->payload_size);

    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {

        /* Wait for the ping */
        while ((ret = recvfrom(sd, data, params->payload_size, 0, NULL, NULL)) <= 0)
            ;
        if (params->blocking && ret < 0) {
            perror("Error receiving UDP message");
        }
        ++counter;
        /* Send it back */
        // fprintf(stdout, "Forwarding sample %lu", data->cnt);
        ret = sendto(sd, data, params->payload_size, 0, (struct sockaddr *)&params->dst_addr,
                     sizeof(params->dst_addr));
        if (ret < 0) {
            perror("Error sending UDP packet");
            break;
        }
    }

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
    config->role         = role_sink;
    config->payload_size = strlen(MSG) + 1;
    config->sleep_time   = 0;
    config->max_msg      = 0;
    config->port_id      = 0;
    config->queue_id     = 0;
    config->blocking     = 1;

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
                fprintf(stderr, "! Invalid value for --num-msg option: %s\n", argv[i]);
                return -1;
            }
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
            continue;
        }
        // Blocking socket
        if (!strncmp(argv[i], "-b", 2) || !strncmp(argv[i], "--blocking", 11)) {
            config->blocking = 0;
            continue;
        }
    }

    // Print out the configuration
    printf("Running with the following arguments:   \n"
           "\tRole............. : %s                \n"
           "\tPayload size..... : %d                \n"
           "\tMax messages..... : %lu               \n"
           "\tSleep time....... : %ld               \n"
           "\tBlocking......... : %s                \n\n",
           role_strings[config->role], config->payload_size, config->max_msg, config->sleep_time,
           config->blocking ? "yes" : "no");

    return 0;
}

//--------------------------------------------------------------------------------------------------
// MAIN
int main(int argc, char *argv[]) {
    signal(SIGINT, handle);
    printf("Welcome to the test of the UDP socket performance\n");

    /* Check test arguments */
    test_config_t params;
    if (parse_arguments(argc, argv, &params) < 0) {
        usage(argc, argv);
        return -1;
    }

    /* Setup socket */
    struct sockaddr_in src_addr;

    src_addr.sin_family = AF_INET;
    src_addr.sin_port   = htons(INSANE_PORT);
    inet_aton(IP_SRC, &src_addr.sin_addr);

    params.dst_addr.sin_family = AF_INET;
    params.dst_addr.sin_port   = htons(INSANE_PORT);
    inet_aton(IP_DST, &params.dst_addr.sin_addr);

    // Open socket for UDP.
    int type = params.blocking ? SOCK_DGRAM : SOCK_DGRAM | SOCK_NONBLOCK;
    int sd   = socket(AF_INET, type, 0);
    if (sd < 0) {
        fprintf(stderr, "Open socket for data: %s", strerror(errno));
        exit(1);
    }

    int ok = 1;
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (void *)&ok, sizeof(ok));
    int buffer = DST_QUEUE_SIZE;
    // setsockopt(sd, SOL_SOCKET, SO_SNDBUF, buffer, sizeof(buffer));
    setsockopt(sd, SOL_SOCKET, SO_RCVBUF, &buffer, sizeof(buffer));

    if (bind(sd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
        fprintf(stderr, "Bind socket: %s", strerror(errno));
        exit(1);
    }

    /* Do test */
    if (params.role == role_sink) {
        do_sink(sd, &params);
    } else if (params.role == role_source) {
        do_source(sd, &params);
    } else if (params.role == role_ping) {
        do_ping(sd, &params);
    } else if (params.role == role_pong) {
        do_pong(sd, &params);
    } else {
        fprintf(stderr, "Test not supported\n");
        return -1;
    }

    /* Terminate */
    close(sd);
    return 0;
}