#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
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
#include <netinet/tcp.h>

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
    uint64_t           payload_size;
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

static ssize_t send_data(int sd, char *data, size_t size, test_config_t *params) {
    ssize_t nb_tx = 0;
    ssize_t ret;
    char *tmp_data = data;
    while(nb_tx < (ssize_t)size) {
        if((ret = write(sd, tmp_data, size - nb_tx)) < 0) {  
            if (!params->blocking && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                // retry
                continue;
            }
            fprintf(stderr, "write() size failed: %s\n", strerror(errno));
            return -1;
        }  
        nb_tx += ret;
        tmp_data += ret;
    }
    if(nb_tx != (ssize_t)size) {
        fprintf(stderr, "error: sent %lu bytes, but expected were %lu\n", nb_tx, size);
        return -1;
    }

    return nb_tx;
}

static ssize_t recv_data(int sd, char *data, size_t size, test_config_t *params) {
    ssize_t nb_rx = 0;
    ssize_t ret;
    char *tmp_data = data;
    while (nb_rx < (ssize_t)size) {            
        if((ret = read(sd, tmp_data, size - nb_rx)) <= 0) {
            if(!params->blocking && ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                // retry
                continue;
            }
            // Something failed 
            if (ret == 0) {
                fprintf(stderr, "read() failed: connection reset by peer\n");
                return ret;
            } else {
                fprintf(stderr, "read() failed: %s\n", strerror(errno));
                return -1;
            }
        }
        nb_rx    += ret;
        tmp_data += ret;
    }
    
    if (nb_rx != (ssize_t)size) {
        fprintf(stderr, "Received packet size does not match the expected size\n");
        return -1;
    }    

    return nb_rx;
}

//--------------------------------------------------------------------------------------------------
void do_source(int sd, test_config_t *params) {
    // char             *msg     = MSG;
    uint64_t          counter = 0;
    char             *payload;
    struct test_data *data;
    ssize_t           ret;

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
        data->cnt     = counter;
        // strncpy(data->msg, msg, strlen(msg) + 1);

        /* First, send the packet size */
        if ((ret = send_data(sd, (char*)&params->payload_size, sizeof(params->payload_size), params)) < (ssize_t)sizeof(params->payload_size)) {
            goto stop;
        }        

        /* Then, send the actual data */
        if ((ret = send_data(sd, payload, params->payload_size, params)) < (ssize_t)params->payload_size) {
            goto stop;
        }

        ++counter;

    }
    printf("Finished sending %lu messages. Exiting...\n", counter);

    // Wait for the other part to close the connection
    while((ret = read(sd, payload, 1)) > 0) {
        usleep(1);
    }

stop:
    free(payload);
}

//--------------------------------------------------------------------------------------------------
void do_sink(int sd, test_config_t *params) {
    char     *payload;
    uint64_t first_time = 0, last_time = 0;
    uint64_t counter = 0;
    ssize_t  ret;
    ssize_t   recv_size;
    
    // Allocate payload of proper size
    payload = (char *)malloc(params->payload_size);
    bzero(payload, params->payload_size);

    printf("Ready to receive data\n");
    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {

        /* First receive the packet size */
        if ((ret = recv_data(sd, (char*)&recv_size, sizeof(recv_size), params)) < (ssize_t)sizeof(recv_size)) {
            goto stop;
        }
        if (recv_size != (ssize_t)params->payload_size) {
            fprintf(stderr, "Received packet size does not match the expected size\n");
            goto stop;
        }
        
        /* Receive the packet data */
        if ((ret = recv_data(sd, payload, recv_size, params)) < recv_size) {
            goto stop;
        }

        if (counter == 0) {
            first_time = get_clock_realtime_ns();
        }

        ++counter;
        // struct test_data *data = (struct test_data *)payload;
        // fprintf(stderr, "(%ld) received: %ld, %s)\n", counter, data->cnt, data->msg);
    }
    last_time = get_clock_realtime_ns();


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
    fprintf(stdout, "%lu,%lu,%.3f,%.3f,%.3f\n", counter, params->payload_size,
            (double)elapsed_time_ns / ((double)1e6), throughput, mbps);

stop:
    free(payload);
}

//--------------------------------------------------------------------------------------------------
void do_ping(int sd, test_config_t *params) {
    // char            *msg     = MSG;
    uint64_t         counter = 0;
    uint64_t         send_time, response_time, latency;
    ssize_t          ret;
    ssize_t           recv_size;

    if(params->payload_size < sizeof(struct test_data)) {
        fprintf(stderr, "Payload size too small\n");
        return;
    }
    struct test_data *data = (struct test_data*)malloc(params->payload_size);

    // For the latency test, we must disable the Nagle's algorithm or the system will not send data immediately
    setsockopt(sd, IPPROTO_TCP, TCP_NODELAY, (int[]){1}, sizeof(int));

    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {

        if (params->sleep_time) {
            sleep(params->sleep_time);
        }

        /* Take the time*/
        send_time = get_clock_realtime_ns();

        /* Fill the packet */
        data->tx_time = send_time;
        data->cnt     = counter++;
        // strncpy(data.msg, msg, strlen(msg) + 1);

        /* First, send the packet size */
        if ((ret = send_data(sd, (char*)&params->payload_size, sizeof(params->payload_size), params)) < (ssize_t)sizeof(params->payload_size)) {
            goto stop;
        }        

        /* Then, send the actual data */
        if ((ret = send_data(sd, (char*)data, params->payload_size, params)) < (ssize_t)params->payload_size) {
            goto stop;
        }

        // fprintf(stdout, "(%lu) time: %ld", counter, send_time);

        /* Wait for the ping packet size */
        if ((ret = recv_data(sd, (char*)&recv_size, sizeof(recv_size), params)) < (ssize_t)sizeof(recv_size)) {
            goto stop;
        }
        if (recv_size != (ssize_t)params->payload_size) {
            fprintf(stderr, "Received packet size does not match the expected size\n");
            goto stop;
        }
        
        /* Receive the ping packet data */
        if ((ret = recv_data(sd, (char*)data, recv_size, params)) < recv_size) {
            goto stop;
        }

        /* Compute latency */
        response_time = get_clock_realtime_ns();
        latency       = response_time - send_time;
        
        fprintf(stdout, "%.3f\n", (float)latency / 1000.0f);
    }

    // Wait for the other part to close the connection
    while((ret = read(sd, data, 1)) > 0) {
        if (!params->blocking && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            // retry
            usleep(1);
            continue;
        }
    }

stop:
    free(data);
}

//--------------------------------------------------------------------------------------------------
void do_pong(int sd, test_config_t *params) {
    ssize_t  ret;
    uint64_t counter = 0;
    ssize_t  recv_size;

    if(params->payload_size < sizeof(struct test_data)) {
        fprintf(stderr, "Payload size too small\n");
        return;
    }

    // For the latency test, we must disable the Nagle's algorithm or the system will not send data immediately
    setsockopt(sd, IPPROTO_TCP, TCP_NODELAY, (int[]){1}, sizeof(int));

    struct test_data *data = (struct test_data*)malloc(params->payload_size);

    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {

        /* Wait for the ping packet size */
        if ((ret = recv_data(sd, (char*)&recv_size, sizeof(recv_size), params)) < (ssize_t)sizeof(recv_size)) {
            goto stop;
        }
        
        /* Receive the ping packet data */
        if ((ret = recv_data(sd, (char*)data, recv_size, params)) < recv_size) {
            goto stop;
        }
        if (recv_size != (ssize_t)params->payload_size) {
            fprintf(stderr, "Received packet size does not match the expected size\n");
            goto stop;
        }

        ++counter;
        recv_size = ret;

        /* First, send back the packet size */
        if ((ret = send_data(sd, (char*)&recv_size, sizeof(recv_size), params)) < (ssize_t)sizeof(recv_size)) {
            goto stop;
        }        

        /* Then, send the actual data */
        if ((ret = send_data(sd, (char*)data, recv_size, params)) < recv_size) {
            goto stop;
        }
    }
stop:
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
           "\tPayload size..... : %lu               \n"
           "\tMax messages..... : %lu               \n"
           "\tSleep time....... : %ld               \n"
           "\tBlocking......... : %s                \n\n",
           role_strings[config->role], config->payload_size, config->max_msg, config->sleep_time,
           config->blocking ? "yes" : "no");

    return 0;
}

static int start_server(test_config_t *params) {
    /* Setup socket */
    struct sockaddr_in src_addr;

    src_addr.sin_family = AF_INET;
    src_addr.sin_port   = htons(INSANE_PORT);
    inet_aton(IP_SRC, &src_addr.sin_addr);

    params->dst_addr.sin_family = AF_INET;
    params->dst_addr.sin_port   = htons(INSANE_PORT);
    inet_aton(IP_DST, &params->dst_addr.sin_addr);

    // Open socket for TCP.
    int type = params->blocking ? SOCK_STREAM : SOCK_STREAM | SOCK_NONBLOCK;
    int sd   = socket(AF_INET, type, 0);
    if (sd < 0) {
        fprintf(stderr, "Open socket for data: %s", strerror(errno));
        exit(1);
    }

    // Set socket options
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (int[]){1}, sizeof(int));
    setsockopt(sd, SOL_SOCKET, SO_SNDBUF, (int[]){DST_QUEUE_SIZE}, sizeof(int));
    setsockopt(sd, SOL_SOCKET, SO_RCVBUF, (int[]){DST_QUEUE_SIZE}, sizeof(int));

    // Bind the socket to the source address
    if (bind(sd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
        fprintf(stderr, "Bind socket: %s", strerror(errno));
        exit(1);
    }

    // Listen for incoming connections
    if (listen(sd, 1) < 0) {
        fprintf(stderr, "Listen socket: %s", strerror(errno));
        exit(1);
    }

    // Accept the connection
    struct sockaddr_in client_addr;
    socklen_t          client_addr_len = sizeof(client_addr);

    int conn_sd;
    while((conn_sd = accept(sd, (struct sockaddr *)&client_addr, &client_addr_len)) < 0) {
        if (!params->blocking && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            usleep(1);
            continue;
        }
        fprintf(stderr, "Accept connection: %s", strerror(errno));
        return conn_sd;
    }

    // Check if the connection is from the expected address
    if (!strcmp(inet_ntoa(client_addr.sin_addr), IP_DST) && client_addr.sin_port != params->dst_addr.sin_port) {
        fprintf(stderr, "Connection from %s:%u but expected from %s:%u. Closing...\n",
                    inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), IP_DST, ntohs(params->dst_addr.sin_port));
        close(conn_sd);
        exit(1);
    }

    return conn_sd;
}

static int start_client(test_config_t *params) {
    /* Setup socket */
    struct sockaddr_in src_addr;

    src_addr.sin_family = AF_INET;
    src_addr.sin_port   = htons(INSANE_PORT);
    inet_aton(IP_SRC, &src_addr.sin_addr);

    params->dst_addr.sin_family = AF_INET;
    params->dst_addr.sin_port   = htons(INSANE_PORT);
    inet_aton(IP_DST, &params->dst_addr.sin_addr);

    // Open socket for TCP.
    int type = params->blocking ? SOCK_STREAM : SOCK_STREAM | SOCK_NONBLOCK;
    int sd   = socket(AF_INET, type, 0);
    if (sd < 0) {
        fprintf(stderr, "Open socket for data: %s", strerror(errno));
        exit(1);
    }

    // Set socket options
    // Set socket options
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (int[]){1}, sizeof(int));
    setsockopt(sd, SOL_SOCKET, SO_SNDBUF, (int[]){DST_QUEUE_SIZE}, sizeof(int));
    setsockopt(sd, SOL_SOCKET, SO_RCVBUF, (int[]){DST_QUEUE_SIZE}, sizeof(int));

    // Bind the socket to the source address
    if (bind(sd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
        fprintf(stderr, "Bind socket: %s", strerror(errno));
        exit(1);
    }

    // Try connect
    int ret = connect(sd, (struct sockaddr *)&params->dst_addr, sizeof(params->dst_addr));
    if(ret < 0 && (params->blocking || (!params->blocking && errno != EINPROGRESS))) {
        fprintf(stderr, "[tcpsock] connect() failed: %s (%d).\nHave you started the server?", strerror(errno), errno);
        close(sd);
        return -1;
    } 

    // If non-blocking, wait for the connection to be established
    if (!params->blocking) {
        // Wait for the connection to be established
        fd_set writefds;
        FD_ZERO(&writefds);
        FD_SET(sd, &writefds);

        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 1000; // 1 ms

        ret = select(sd + 1, NULL, &writefds, NULL, &timeout);
        if (ret <= 0) {
            if (ret == 0) {
                fprintf(stderr, "connect() timed out.\nHave you started the server?\n");
            } else {
                fprintf(stderr, "select() failed: %s\n", strerror(errno));
            }
            close(sd);
            return -1;
        }

        int error = 0;
        socklen_t len = sizeof(error);
        if (getsockopt(sd, SOL_SOCKET, SO_ERROR, &error, &len) == -1) {
            close(sd);
            fprintf(stderr, "[tcpsock] getsockopt() failed: %s\n", strerror(errno));
            return -1;
        }

        if (error != 0) {
            close(sd);
            fprintf(stderr, "[tcpsock] connect() failed: %s (%d)\nHave you started the server?\n", strerror(error), error);
            return -1;
        }
    }

    return sd;
}

//--------------------------------------------------------------------------------------------------
// MAIN
int main(int argc, char *argv[]) {
    signal(SIGINT, handle);
    printf("Welcome to the test of the TCP socket performance\n");

    /* Check test arguments */
    test_config_t params;
    if (parse_arguments(argc, argv, &params) < 0) {
        usage(argc, argv);
        return -1;
    }

    int sd;;
    /* Do test */
    if (params.role == role_sink) {
        sd = start_server(&params);
        if (sd < 0) {
            fprintf(stderr, "Error starting server\n");
            return -1;
        }
        do_sink(sd, &params);
    } else if (params.role == role_source) {
        sd = start_client(&params);
        if (sd < 0) {
            fprintf(stderr, "Error starting client\n");
            return -1;
        }
        do_source(sd, &params);
    } else if (params.role == role_ping) {
        sd = start_client(&params);
        if (sd < 0) {
            fprintf(stderr, "Error starting client\n");
            return -1;
        }
        do_ping(sd, &params);
    } else if (params.role == role_pong) {
        sd = start_server(&params);
        if(sd < 0) {
            fprintf(stderr, "Error starting server\n");
            return -1;
        }
        do_pong(sd, &params);
    } else {
        fprintf(stderr, "Test not supported\n");
        return -1;
    }

    /* Terminate */
    close(sd);
    return 0;
}
