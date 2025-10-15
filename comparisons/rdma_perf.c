#define _GNU_SOURCE

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
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

#include <infiniband/verbs.h>

#define ENSURE_ONE_MORE_ARGUMENT(argc, argv, i, argName)                                           \
    if (i + 1 >= argc) {                                                                           \
        usage(argc, argv);                                                                         \
        fprintf(stderr, "! Error: missing value for %s argument\n", argName);                      \
        return 0;                                                                              \
    }

#define MSG              "hello, RDMA!"
#define MAX_PAYLOAD_SIZE 1048576
#define MIN_PAYLOAD_SIZE 16

// Memory area for data. Must be power of 2.
#define MAX_DATA_SIZE MAX_PAYLOAD_SIZE
// Infiniband device port
#define IB_PORT 1
// RoCE GID. //TODO: Understand what is it. Start here:
// https://docs.nvidia.com/networking/pages/viewpage.action?pageId=19798092#RDMAoverConvergedEthernet(RoCE)-GIDTablePopulation
#define GIDX 0
// RDMA MTU, to be chosen from the enum list.
// For RoCE, it should be less than the minimum MTU
// on the overall data path (usually 1500)
#define IB_MTU IBV_MTU_1024
// App-defined WR id. I use only one here, but the ping-pong example
// used this field to distinguish between ping/pong messages.
#define TESTRDMA_WRID 2509
// Max QP
#define MAX_QP 256
// TCP/IP info
#define TCP_PORT 9999

struct endpoint {
    int           lid;
    int           qpn;
    int           psn;
    union ibv_gid gid;
    int           sl;
    int           gidx;
};

///////////////////////////////////// ctx //////////////////
// struct ibv_comp_channel *channel = NULL;
struct ibv_context *context = NULL;
struct ibv_device  *ib_dev  = NULL;
struct ibv_pd      *pd      = NULL;
struct ibv_mr      *mr      = NULL;
// NOTE(garbu): if we may want to use the timestamp we must switch to the
// struct ibv_cq_ext.
struct ibv_cq    *cq  = NULL;
struct ibv_qp    *qp  = NULL;
struct ibv_qp_ex *qpx = NULL;
// static int        pending;
////////////////////////////////////////////////////////////

typedef enum role {
    role_sink,
    role_source,
    role_ping,
    role_pong,
} role_t;

static char *role_strings[] = {"SINK", "SOURCE", "PING", "PONG"};

typedef struct test_config {
    role_t   role;
    uint32_t payload_size;
    uint64_t sleep_time;
    uint64_t max_msg;
    uint16_t port_id;
    uint16_t queue_id;
    char     dst_addr[16];
} test_config_t;

struct test_data {
    uint64_t cnt;
    uint64_t tx_time;
    char     msg[64];
};

volatile uint8_t g_running  = 1;
volatile uint8_t queue_stop = 0;

//--------------------------------------------------------------------------------------------------
static inline uint64_t get_clock_realtime_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

//----------------------------------------------------------------------------------------------
// Handle user work request
static inline int parse_single_wc(struct ibv_wc *wc) {
    if (wc->status != IBV_WC_SUCCESS) {
        fprintf(stderr, "Failed status %s (%d) for wr_id %d\n", ibv_wc_status_str(wc->status), wc->status,
                  (int)wc->wr_id);
        return -1;
    }

    // Check the ID
    if ((int)wc->wr_id != TESTRDMA_WRID) {
        fprintf(stderr, "Completion for unknown wr_id %d\n", (int)wc->wr_id);
        return -1;
    }

    // Case 1 - Immediate data
    if (wc->opcode == IBV_WC_RECV) {

        // Retrieve data len
        // size_t len = wc->byte_len;

        // Do something with the received data
        // printf("Received data with length %u\n", len);
        // fflush(stdout);

        // Print data
        // write(1, "Received data: ", 15);
        // write(1, mr->addr, len);
        // write(1, "\n", 1);
        return 0;

    }
    // Case 2 - Recv value
    else if (wc->opcode == IBV_WC_RECV_RDMA_WITH_IMM)
    {
        fprintf(stderr, "Reception of data with immediate not supported yet\n");
        return -1;
    } else {
        fprintf(stderr, "Invalid opcode received: %d\n", wc->opcode);
        return -1;
    }
}

//----------------------------------------------------------------------------------------------
// Connect to remote QP: this effectively advances QP state to RTS
static inline int connect_ctx(int port, int my_psn, enum ibv_mtu mtu, int sl, int sgid_idx,
                              struct endpoint *dest) {
    struct ibv_qp_attr attr = {
        .qp_state           = IBV_QPS_RTR,
        .path_mtu           = mtu,
        .dest_qp_num        = dest->qpn,
        .rq_psn             = dest->psn,
        .max_dest_rd_atomic = 1,
        .min_rnr_timer      = 12,
        .ah_attr            = {.dlid          = dest->lid,
                               .sl            = sl,
                               .src_path_bits = 0,
                               .port_num      = port,
                               // When using RoCE, GRH must be configured:
                               .is_global = 1,
                               .grh       = {.hop_limit = 1, .dgid = dest->gid, .sgid_index = sgid_idx}},

    };

    // Advances QP state from INIT to RTR
    // Each flag signals that the specific attr in the attr field must be updated
    if (ibv_modify_qp(qp, &attr,
                      IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
                          IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER))
    {
        fprintf(stderr, "Failed to modify QP to RTR\n");
        perror("error: ");
        return 1;
    }

    attr.qp_state      = IBV_QPS_RTS;
    attr.timeout       = 14;
    attr.retry_cnt     = 7;
    attr.rnr_retry     = 7;
    attr.sq_psn        = my_psn;
    attr.max_rd_atomic = 1;

    // Advances QP state to RTS
    // Each flag signals that the specific attr in the attr field must be updated
    if (ibv_modify_qp(qp, &attr,
                      IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY |
                          IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC))
    {
        fprintf(stderr, "Failed to modify QP to RTS\n");
        perror("error: ");
        return 1;
    }

    return 0;
}

//----------------------------------------------------------------------------------------------
void gid_to_wire_gid(const union ibv_gid *gid, char wgid[]) {
    uint32_t tmp_gid[4];
    int      i;

    memcpy(tmp_gid, gid, sizeof(tmp_gid));
    for (i = 0; i < 4; ++i) {
        sprintf(&wgid[i * 8], "%08x", htobe32(tmp_gid[i]));
    }
}

//----------------------------------------------------------------------------------------------
void wire_gid_to_gid(const char *wgid, union ibv_gid *gid) {
    char     tmp[9];
    __be32   v32;
    int      i;
    uint32_t tmp_gid[4];

    for (tmp[8] = 0, i = 0; i < 4; ++i) {
        memcpy(tmp, wgid + i * 8, 8);
        sscanf(tmp, "%x", &v32);
        tmp_gid[i] = be32toh(v32);
    }
    memcpy(gid, tmp_gid, sizeof(*gid));
}

//----------------------------------------------------------------------------------------------
struct endpoint *client_exch_dest(const char *servername, int port,
                                  const struct endpoint *local_ep) {
    struct addrinfo *res, *t;
    struct addrinfo  hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};
    char            *service;
    char             msg[sizeof "0000:000000:000000:00000000000000000000000000000000"];
    int              n;
    int              sockfd   = -1;
    struct endpoint *rem_dest = NULL;
    char             gid[33];

    if (asprintf(&service, "%d", port) < 0) {
        return NULL;
    }

    n = getaddrinfo(servername, service, &hints, &res);
    if (n < 0) {
        fprintf(stderr, "%s for %s:%d\n", gai_strerror(n), servername, port);
        free(service);
        return NULL;
    }

    for (t = res; t; t = t->ai_next) {
        sockfd = socket(t->ai_family, t->ai_socktype, t->ai_protocol);
        if (sockfd >= 0) {
            if (!connect(sockfd, t->ai_addr, t->ai_addrlen)) {
                break;
            }
            close(sockfd);
            sockfd = -1;
        }
    }

    freeaddrinfo(res);
    free(service);

    if (sockfd < 0) {
        fprintf(stderr, "Couldn't connect to %s:%d\n", servername, port);
        return NULL;
    }

    // Send local address to the remote side
    gid_to_wire_gid(&local_ep->gid, gid);
    sprintf(msg, "%04x:%06x:%06x:%s", local_ep->lid, local_ep->qpn, local_ep->psn, gid);
    if (write(sockfd, msg, sizeof msg) != sizeof msg) {
        fprintf(stderr, "Couldn't send local address\n");
        goto out;
    }

    // Read remote address and send back ACK
    if (read(sockfd, msg, sizeof msg) != sizeof msg ||
        write(sockfd, "done", sizeof "done") != sizeof "done")
    {
        perror("client read/write");
        fprintf(stderr, "Couldn't read/write remote address\n");
        goto out;
    }

    // Allocate memory for the remote address descriptor
    rem_dest = malloc(sizeof *rem_dest);
    if (!rem_dest) {
        goto out;
    }

    sscanf(msg, "%x:%x:%x:%s", &rem_dest->lid, &rem_dest->qpn, &rem_dest->psn, gid);
    wire_gid_to_gid(gid, &rem_dest->gid);

out:
    close(sockfd);
    return rem_dest;
}

//----------------------------------------------------------------------------------------------
struct endpoint *server_exch_dest(int ib_port, enum ibv_mtu mtu, int port, int sl, int sgid_idx,
                                  const struct endpoint *local_ep) {
    struct addrinfo *res, *t;
    struct addrinfo  hints = {
         .ai_flags = AI_PASSIVE, .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};
    char            *service;
    char             msg[sizeof "0000:000000:000000:00000000000000000000000000000000"];
    int              n;
    int              sockfd   = -1, connfd;
    struct endpoint *rem_dest = NULL;
    char             gid[33];

    if (asprintf(&service, "%d", port) < 0)
        return NULL;

    n = getaddrinfo(NULL, service, &hints, &res);

    if (n < 0) {
        fprintf(stderr, "%s for port %d\n", gai_strerror(n), port);
        free(service);
        return NULL;
    }

    for (t = res; t; t = t->ai_next) {
        sockfd = socket(t->ai_family, t->ai_socktype, t->ai_protocol);
        if (sockfd >= 0) {
            n = 1;
            setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &n, sizeof n);
            if (!bind(sockfd, t->ai_addr, t->ai_addrlen))
                break;
            close(sockfd);
            sockfd = -1;
        }
    }

    freeaddrinfo(res);
    free(service);

    if (sockfd < 0) {
        fprintf(stderr, "Couldn't listen to port %d\n", port);
        return NULL;
    }

    // Listen & Accept
    listen(sockfd, 1);
    connfd = accept(sockfd, NULL, NULL);
    close(sockfd);
    if (connfd < 0) {
        fprintf(stderr, "accept() failed\n");
        return NULL;
    }

    // Read remote address
    n = read(connfd, msg, sizeof msg);
    if (n != sizeof msg) {
        perror("server read");
        fprintf(stderr, "%d/%d: Couldn't read remote address\n", n, (int)sizeof msg);
        goto out;
    }

    rem_dest = malloc(sizeof *rem_dest);
    if (!rem_dest) {
        goto out;
    }

    // Parse address and progress QP
    sscanf(msg, "%x:%x:%x:%s", &rem_dest->lid, &rem_dest->qpn, &rem_dest->psn, gid);
    wire_gid_to_gid(gid, &rem_dest->gid);

    if (connect_ctx(ib_port, local_ep->psn, mtu, sl, sgid_idx, rem_dest)) {
        fprintf(stderr, "Couldn't connect to remote QP\n");
        free(rem_dest);
        rem_dest = NULL;
        goto out;
    }

    // Prepare message with local address and send it remotely, waiting for ACK
    gid_to_wire_gid(&local_ep->gid, gid);
    sprintf(msg, "%04x:%06x:%06x:%s", local_ep->lid, local_ep->qpn, local_ep->psn, gid);

    if (write(connfd, msg, sizeof msg) != sizeof msg ||
        read(connfd, msg, sizeof msg) != sizeof "done")
    {
        fprintf(stderr, "Couldn't send/recv local address\n");
        free(rem_dest);
        rem_dest = NULL;
        goto out;
    }

out:
    close(connfd);
    return rem_dest;
}
//----------------------------------------------------------------------------------------------
// Wrap the code to post a receive request
static inline int post_recv(char *addr, uint32_t length) {
    // TODO: check that addr + len is within the MR boundary
    struct ibv_sge list    = {.addr = (uint64_t)addr, .length = length, .lkey = mr->lkey};
    int            num_sge = 1;

    struct ibv_recv_wr wr = {
        .wr_id   = TESTRDMA_WRID, /* User defined WR ID */
        .next    = NULL,          /* Pointer to next WR in list, NULL if last WR */
        .sg_list = &list,         /* Pointer to the s/g array */
        .num_sge = num_sge,       /* Size of the s/g array */
    };
    struct ibv_recv_wr *bad_wr;
    int                 i;

    for (i = 0; i < num_sge; ++i) {
        if (ibv_post_recv(qp, &wr, &bad_wr)) {
            perror("post send");
            break;
        }
    }

    return i;
}

//----------------------------------------------------------------------------------------------
// Wrap the code to post a send request
// Send flags: IBV_SEND_SIGNALED
static inline int post_send(char *addr, uint32_t length, int send_flags) {
    struct ibv_sge list    = {.addr = (uint64_t)addr, .length = length, .lkey = mr->lkey};
    
    /* If data to send is less than the inline threshold, send data inline */
    // int            num_sge = 1;
    // struct ibv_qp_init_attr init_attr;
    // struct ibv_qp_attr      attr;
    /* THIS CALL CAUSES A LOT OF OVERHEAD. DO NOT USE IT ON THE CRITICAL PATH */
    // ibv_query_qp(qp, &attr, IBV_QP_CAP, &init_attr);
    // if (init_attr.cap.max_inline_data >= length) {
    //     send_flags |= IBV_SEND_INLINE;
    // }

    /* OLD API */
    // struct ibv_send_wr wr = {
    //     .wr_id      = TESTRDMA_WRID,      /* User defined WR ID */
    //     .sg_list    = &list,              /* Pointer to the s/g array */
    //     .num_sge    = num_sge,            /* Size of the s/g array */
    //     .opcode     = IBV_WR_SEND,        /* Operation type */
    //     .send_flags = send_flags,
    // };
    // struct ibv_send_wr *bad_wr;
    // return ibv_post_send(ctx->qp, &wr, &bad_wr);

    /* NEW API */
    // This is an example of the "new" send API. The verbs work request API (ibv_wr_*) allows
    // efficient posting of work to a send queue using function calls instead of the struct
    // based ibv_post_send() scheme. This approach is designed to minimize CPU branching and
    // locking during the posting process.

    // Start critical section
    ibv_wr_start(qpx);

    qpx->wr_id    = TESTRDMA_WRID;
    qpx->wr_flags = send_flags;
    ibv_wr_send(qpx);
    ibv_wr_set_sge(qpx, list.lkey, list.addr, list.length);

    // End critical section on exit
    return ibv_wr_complete(qpx);
}

//----------------------------------------------------------------------------------------------
// Initialize the context: creates PD and QP. Moves QP to INIT state.
int init_ibv_context() {

    // Open device
    context = ibv_open_device(ib_dev);
    if (!context) {
        printf("cannot get context for %s\n", ibv_get_device_name(ib_dev));
        goto clean_buf;
    }

    // Create a Protection Domain for the device
    pd = ibv_alloc_pd(context);
    if (!pd) {
        printf("cannot allocate PD\n");
        goto clean_device;
    }

    // We do not check for ODP as we do not use it
    // We do not check for HW completion timestamp (ts)
    // We do not check if we can use device memory (DM) for allocation

    // Queue depths
    int rx_depth = 256;
    int tx_depth = 256;

    /* Create completion queueue (without HW completion ts) */
    cq = ibv_create_cq(context, rx_depth + 1, NULL, NULL, 0);
    if (!cq) {
        printf("cannot create a completion queue (CQ)\n");
        goto clean_pd;
    }

    /* Create queue pairs */
    {
        // Attributes. We choose the extended version
        struct ibv_qp_init_attr_ex init_attr_ex;
        memset(&init_attr_ex, 0, sizeof(init_attr_ex));
        init_attr_ex.send_cq = cq;
        init_attr_ex.recv_cq = cq;
        init_attr_ex.srq     = NULL;
        init_attr_ex.cap.max_send_wr =
            tx_depth; // Requested max number of outstanding WRs in the SQ
        init_attr_ex.cap.max_recv_wr =
            rx_depth; // Requested max number of outstanding WRs in the RQ
        init_attr_ex.cap.max_send_sge =
            1;        // Requested max scatter/gather elements in a WR in the SQ
        init_attr_ex.cap.max_recv_sge = 1; // Requested max number of s/g elements in a WR in the RQ
        init_attr_ex.qp_type          = IBV_QPT_RC; // QP Transport Service Type
        init_attr_ex.comp_mask        = IBV_QP_INIT_ATTR_PD | IBV_QP_INIT_ATTR_SEND_OPS_FLAGS;
        init_attr_ex.pd               = pd;
        init_attr_ex.send_ops_flags   = IBV_QP_EX_WITH_SEND;
        init_attr_ex.sq_sig_all       = 0; // By default, do not generate completions for operations

        qp = ibv_create_qp_ex(context, &init_attr_ex);
        if (!qp) {
            printf("cannot create a Queue Pair (QP)\n");
            goto clean_cq;
        }
        qpx = ibv_qp_to_qp_ex(qp);

        // The function ibv_create_qp_ex() updated the qp_init_attr_ex->cap struct with the
        // actual QP values of the QP that was created; the values will be greater than or equal
        // to the values requested. Example, like follows:
        // struct ibv_qp_attr      attr;
        // struct ibv_qp_init_attr init_attr;
        // ibv_query_qp(qp, &attr, IBV_QP_CAP, &init_attr);
    }

    /* Transition QP state. ibv_modify_qp is used to progress the QP State Machine */
    {
        struct ibv_qp_attr attr;
        memset(&attr, 0, sizeof(attr));

        attr.qp_state        = IBV_QPS_INIT;
        attr.pkey_index      = 0;
        attr.port_num        = IB_PORT;
        attr.qp_access_flags = 0;

        // ibv_modify_qp() modifies the attributes of QP qp with the attributes in attr
        // according to the mask attr_mask. The argument attr_mask specifies the QP attributes
        // to be modified.
        if (ibv_modify_qp(qp, &attr,
                          IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS))
        {
            fprintf(stderr, "Failed to modify QP to INIT\n");
            perror("error: ");
            goto clean_qp;
        }
    }
    return 0;

clean_qp:
    ibv_destroy_qp(qp);

clean_cq:
    ibv_destroy_cq(cq);

clean_pd:
    ibv_dealloc_pd(pd);

clean_device:
    ibv_close_device(context);

clean_buf:
    // free(buf);

    // channel = ibv_create_comp_channel()

    return -1;
}

//----------------------------------------------------------------------------------------------
// Allocate data memory and initialize a MR with it
int init_mr(char *memory, size_t memory_size) {
    // Get info about the default page size
    int page_size = sysconf(_SC_PAGESIZE);

    // Allocate the memory, aligned based on size
    int res = posix_memalign((void**)&memory, page_size, memory_size);
    if (res < 0 || !memory) {
        printf("cannot allocate aligned memory: %s\n", strerror(errno));
        return -1;
    }

    // Memory protection. Possible values (composable):
    // IBV_ACCESS_LOCAL_WRITE   Enable Local Write Access
    // IBV_ACCESS_REMOTE_WRITE  Enable Remote Write Access
    // IBV_ACCESS_REMOTE_READ   Enable Remote Read Access
    // IBV_ACCESS_REMOTE_ATOMIC Enable Remote Atomic Operation Access (if supported)
    // IBV_ACCESS_MW_BIND       Enable Memory Window
    int access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ;

    // Register the memory as MR
    mr = ibv_reg_mr(pd, memory, memory_size, access_flags);
    if (!mr) {
        printf("cannot register a memory region\n");
        return -1;
    }

    // For better performance, we could prefetch parts of the MR
    // with the ibv_advise_mr() verb. We don't do that for the moment

    return 0;
}

//--------------------------------------------------------------------------------------------------
void handle(int signum) {
    (void) signum; // Unused parameter
    fprintf(stderr, "Received CTRL+C. Exiting!\n");
    g_running  = 0;
    queue_stop = 1;
    exit(0);
}

//--------------------------------------------------------------------------------------------------
void usage(int argc, char *argv[]) {
    (void) argc; // Unused parameter
    printf("Usage: %s [MODE] [REMOTE] [OPTIONS]          \n"
           "MODE: source|sink|ping|pong                  \n"
           "REMOTE: <ip:port> if \"client\" or \"ping\"  \n"
           "OPTIONS:                                     \n"
           "-h: display this message and exit            \n"
           "-s: message payload size in bytes            \n"
           "-n: max messages to send (0 = no limit)      \n"
           "-r: configure sleep time (s) in send         \n"
           "-b: configure recv socket to be non-blocking \n",
           argv[0]);
}

//--------------------------------------------------------------------------------------------------
void do_source(test_config_t *params, struct endpoint *local_ep) {
    char             *msg     = MSG;
    uint64_t          counter = 0;
    struct ibv_wc     wc;
    struct test_data *data;
    int               ret;

    struct endpoint *rem_dest;

    // Exchange QP info with the sink
    rem_dest = client_exch_dest(params->dst_addr, TCP_PORT, local_ep);
    if (!rem_dest) {
        fprintf(stderr, "Failed to exchange remote QP info\n");
        return;
    }

    // Move the QP state to RTS
    if (connect_ctx(IB_PORT, local_ep->psn, IB_MTU, local_ep->sl, local_ep->gidx, rem_dest)) {
        fprintf(stderr, "Failed to move QP to RTS\n");
        return;
    }

    // Print remote address
    inet_ntop(AF_INET6, &rem_dest->gid, (char*)local_ep->gid.raw, sizeof local_ep->gid.raw);
    printf("  remote address: LID 0x%04x, QPN 0x%06x, PSN 0x%06x, GID %s\n", rem_dest->lid,
           rem_dest->qpn, rem_dest->psn, (char *)local_ep->gid.raw);

    uint64_t tx_time;
    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {

        if (params->sleep_time) {
            sleep(params->sleep_time);
        }

        tx_time = get_clock_realtime_ns();

        // Fill it up the buffer
        data          = (struct test_data *)mr->addr;
        data->tx_time = tx_time;
        data->cnt     = counter++;
        strncpy(data->msg, msg, strlen(msg) + 1);

        // Send the packet
        ret = post_send(mr->addr, params->payload_size, IBV_SEND_SIGNALED);
        // fprintf(stderr, "Successfully posted send\n");

        // Get SEND completion
        // This slows down performance but ensures the receiver
        // confirms the reception of all data
        do {
            ret = ibv_poll_cq(cq, 1, &wc);
            if (ret < 0) {
                fprintf(stderr, "Poll CQ failed %d\n", ret);
                return;
            }
        } while (ret < 1);
        if (wc.status != IBV_WC_SUCCESS) {
            fprintf(stderr, "Failed status %s (%d) for wr_id %d\n", ibv_wc_status_str(wc.status),
                      wc.status, (int)wc.wr_id);
            return;
        }
    }

    printf("Finished sending %lu messages. Exiting...\n", counter);
}

//--------------------------------------------------------------------------------------------------
void do_sink(test_config_t *params, struct endpoint *local_ep) {
    struct ibv_wc     wc;
    uint64_t          first_time = 0, last_time = 0;
    uint64_t          counter = 0;
    int               nb_rx, ne;

    // Exchange QP info with the sink. The function internally moves the QP from INIT to RTS
    struct endpoint *rem_dest;
    rem_dest = server_exch_dest(IB_PORT, IB_MTU, TCP_PORT, local_ep->sl, local_ep->gidx, local_ep);
    if (!rem_dest) {
        fprintf(stderr, "Failed to exchange remote QP info with the source\n");
        return;
    }

    // Prepare a number of receive request (rx-depth of QP is the limit)
    for (uint64_t i = 0; i < 256; ++i) {
        nb_rx = post_recv(mr->addr, mr->length);
        if (nb_rx < 1) {
            fprintf(stderr, "Couldn't post receive %lu (%d)\n", i, nb_rx);
            return;
        }
    }

    // Print remote address
    char gid[33];
    inet_ntop(AF_INET6, &rem_dest->gid, gid, sizeof gid);
    printf("  remote address: LID 0x%04x, QPN 0x%06x, PSN 0x%06x, GID %s\n", rem_dest->lid,
           rem_dest->qpn, rem_dest->psn, gid);

    printf("Ready to receive data\n");

    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {

        // Poll CQ to detect new data
        do {
            ne = ibv_poll_cq(cq, 1, &wc);
            if (ne < 0) {
                fprintf(stderr, "poll CQ failed %d\n", ne);
                return;
            }
        } while (ne < 1);

        // Check if it is for us, and if yes, parse the data
        if (parse_single_wc(&wc) < 0) {
            fprintf(stderr, "Failed to parse WC\n");
            continue;
        }
        // fprintf(stderr, "Received SEND operation");

        if (counter == 0) {
            first_time = get_clock_realtime_ns();
        }

        counter++;
        // fprintf(stderr, "(%ld) received: %ld, %s)\n", counter, *data.cnt, *data.msg);

        // Post receive request
        nb_rx = post_recv(mr->addr, mr->length);
        if (nb_rx < 1) {
            fprintf(stderr, "Couldn't post receive (%d)\n", nb_rx);
            return;
        }
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
    fprintf(stdout, "%lu,%u,%.3f,%.3f,%.3f\n", counter, params->payload_size,
            (double)elapsed_time_ns / ((double)1e6), throughput, mbps);
}

//--------------------------------------------------------------------------------------------------
void do_ping(test_config_t *params, struct endpoint *local_ep) {
    char             *msg = MSG;
    struct ibv_wc     wc;
    uint64_t          counter = 0;
    struct test_data *data;
    uint64_t          send_time, response_time, latency;
    ssize_t           ret;

    struct endpoint *rem_dest;

    // Exchange QP info with the sink
    rem_dest = client_exch_dest(params->dst_addr, TCP_PORT, local_ep);
    if (!rem_dest) {
        fprintf(stderr, "Failed to exchange remote QP info\n");
        return;
    }

    // Move the QP state to RTS
    if (connect_ctx(IB_PORT, local_ep->psn, IB_MTU, local_ep->sl, local_ep->gidx, rem_dest)) {
        fprintf(stderr, "Failed to move QP to RTS\n");
        return;
    }

    // Print remote address
    inet_ntop(AF_INET6, &rem_dest->gid, (char*)local_ep->gid.raw, sizeof local_ep->gid.raw);
    printf("  remote address: LID 0x%04x, QPN 0x%06x, PSN 0x%06x, GID %s\n", rem_dest->lid,
           rem_dest->qpn, rem_dest->psn, (char *)local_ep->gid.raw);

    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {

        if (params->sleep_time) {
            sleep(params->sleep_time);
        }

        /* Take time*/
        send_time = get_clock_realtime_ns();

        /* Fill the packet */
        data          = (struct test_data *)mr->addr;
        data->tx_time = send_time;
        data->cnt     = counter++;
        strncpy(data->msg, msg, strlen(msg) + 1);

        /* Send the packet */
        ret = post_send(mr->addr, params->payload_size, IBV_SEND_SIGNALED);
        if (ret < 0) {
            fprintf(stderr, "Error posting send");
            return;
        }

        // Get SEND completion
        // This slows down performance but ensures the receiver
        // confirms the reception of all data
        do {
            ret = ibv_poll_cq(cq, 1, &wc);
            if (ret < 0) {
                fprintf(stderr, "Poll CQ failed %lu\n", ret);
                return;
            }
        } while (ret < 1);
        if (wc.status != IBV_WC_SUCCESS) {
            fprintf(stderr, "Failed status %s (%d) for wr_id %d\n", ibv_wc_status_str(wc.status),
                      wc.status, (int)wc.wr_id);
            return;
        }

        // Post receive request
        ret = post_recv(mr->addr, mr->length);
        if (ret < 1) {
            fprintf(stderr, "Couldn't post receive (%lu)\n", ret);
            return;
        }

        // Poll CQ to detect new data
        do {
            ret = ibv_poll_cq(cq, 1, &wc);
            if (ret < 0) {
                fprintf(stderr, "poll CQ failed %lu\n", ret);
                return;
            }
        } while (ret < 1);

        // Check if it is for us, and if yes, parse the data
        if (parse_single_wc(&wc) < 0) {
            fprintf(stderr, "Failed to parse WC\n");
            continue;
        }

        /* Compute latency */
        response_time = get_clock_realtime_ns();
        latency       = response_time - send_time;

        fprintf(stdout, "%.3f\n", (float)latency / 1000.0F);
    }
}

//--------------------------------------------------------------------------------------------------
void do_pong(test_config_t *params, struct endpoint *local_ep) {
    int               ret;
    struct ibv_wc     wc;
    uint64_t          counter;

    // Exchange QP info with the sink. The function internally moves the QP from INIT to RTS
    struct endpoint *rem_dest;
    rem_dest = server_exch_dest(IB_PORT, IB_MTU, TCP_PORT, local_ep->sl, local_ep->gidx, local_ep);
    if (!rem_dest) {
        fprintf(stderr, "Failed to exchange remote QP info with the source\n");
        return;
    }

    // Print remote address
    char gid[33];
    inet_ntop(AF_INET6, &rem_dest->gid, gid, sizeof gid);
    printf("  remote address: LID 0x%04x, QPN 0x%06x, PSN 0x%06x, GID %s\n", rem_dest->lid,
           rem_dest->qpn, rem_dest->psn, gid);

    printf("Ready to receive data\n");

    counter = 0;
    while (g_running && (params->max_msg == 0 || counter < (params->max_msg))) {

        // Post receive request
        ret = post_recv(mr->addr, mr->length);
        if (ret < 1) {
            fprintf(stderr, "Couldn't post receive (%d)\n", ret);
            return;
        }

        // Poll CQ to detect new data
        do {
            ret = ibv_poll_cq(cq, 1, &wc);
            if (ret < 0) {
                fprintf(stderr, "Poll CQ failed %d\n", ret);
                return;
            }
        } while (ret < 1);

        // fprintf(stderr, "Polled a new WC\n");

        // Check if it is for us, and if yes, parse the data
        if (parse_single_wc(&wc) < 0) {
            fprintf(stderr, "Failed to parse WC\n");
            continue;
        }

        // fprintf(stderr, "Forwarding sample %lu\n", ((struct test_data *)mr->addr)->cnt);

        /* Send it back. */
        ret = post_send(mr->addr, params->payload_size, IBV_SEND_SIGNALED);
        if (ret < 0) {
            fprintf(stderr, "Error posting send");
            return;
        }
        // fprintf(stderr, "Posted send request\n");

        // Get SEND completion
        do {
            ret = ibv_poll_cq(cq, 1, &wc);
            if (ret < 0) {
                fprintf(stderr, "Poll CQ failed %d\n", ret);
                return;
            }
        } while (ret < 1);

        counter++;
    }
}

//--------------------------------------------------------------------------------------------------
int parse_arguments(int argc, char *argv[], test_config_t *config) {
    int i = 0;

    /* Argument number */
    if (argc < 2) {
        fprintf(stderr, "! Invalid number of arguments\n"
                        "! You must specify at least the running MODE\n");
        return -1;
    }

    i += 2;

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

    /* Remote endpoint, if CLIENT or PING */
    if (config->role == role_source || config->role == role_ping) {
        if (argc < 3 || argv[2][0] == '-') {
            fprintf(stderr, "! Invalid number of arguments\n"
                            "! You must specify at least the REMOTE IP address\n");
            return -1;
        }
        // Save dst address in host mode
        strcpy(config->dst_addr, argv[2]);
        i++;
    }

    /* Default values */
    config->payload_size = strlen(MSG) + 1;
    config->sleep_time   = 0;
    config->max_msg      = 0;
    config->port_id      = 0;
    config->queue_id     = 0;

    /* Parse the optional arguments */
    for (; i < argc; ++i) {
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
    }

    // Print out the configuration
    printf("Running with the following arguments:   \n"
           "\tRole............. : %s                \n"
           "\tPayload size..... : %d                \n"
           "\tMax messages..... : %lu               \n"
           "\tSleep time....... : %ld               \n",
           role_strings[config->role], config->payload_size, config->max_msg, config->sleep_time);

    return 0;
}

//--------------------------------------------------------------------------------------------------
// MAIN
int main(int argc, char *argv[]) {
    signal(SIGINT, handle);
    printf("Welcome to the test of the raw RDMA (2-sided) performance\n");

    /* Check test arguments */
    test_config_t params;
    if (parse_arguments(argc, argv, &params) < 0) {
        usage(argc, argv);
        return -1;
    }

    /* Get RDMA device info and print them */
    int                 num_devices;
    struct ibv_device **dev_list = ibv_get_device_list(&num_devices);
    if (!dev_list) {
        fprintf(stderr, "Failed to get IB devices list");
        goto exit;
    }
    fprintf(stderr, "Found %d RDMA devices\n", num_devices);

    // Get the first device on the list
    ib_dev           = dev_list[0];
    const char *name = ibv_get_device_name(ib_dev);
    fprintf(stderr, "Using the first device: %s\n", name);

    /* Initialize PD and QP. QP is set to INIT state */
    int res = init_ibv_context();
    if (res < 0) {
        goto exit;
    }

    /* Allocate memory are and register it with the NIC as MR */
    char  *memory = NULL;
    size_t memory_size = MAX_DATA_SIZE;
    res                = init_mr(memory, memory_size);
    if (res < 0) {
        goto exit;
    }

    // Get local endpoint info
    struct endpoint local_ep;
    local_ep.gidx = GIDX;
    local_ep.sl   = 0; // Service Level. Used only for UD mode. Set to 0 here
    char                 gid[33];
    struct ibv_port_attr ib_port_info;
    if (ibv_query_port(context, IB_PORT, &ib_port_info)) {
        fprintf(stderr, "Couldn't get port info\n");
        goto exit;
    }
    local_ep.lid = ib_port_info.lid;
    if (ib_port_info.link_layer != IBV_LINK_LAYER_ETHERNET && !local_ep.lid) {
        fprintf(stderr, "Couldn't get local LID\n");
        return 1;
    }

    // For Infiniband, it would be sufficient:
    // memset(&local_ep.gid, 0, sizeof(local_ep.gid));
    // For RoCE:
    if (ibv_query_gid(context, IB_PORT, local_ep.gidx, &local_ep.gid)) {
        fprintf(stderr, "can't read sgid of index %d\n", local_ep.gidx);
        return 1;
    }

    local_ep.qpn = qp->qp_num;
    local_ep.psn = lrand48() & 0xffffff; // Random initial PSN. That's important for security!
    inet_ntop(AF_INET6, &local_ep.gid, gid, sizeof gid);
    printf("  local address:  LID 0x%04x, QPN 0x%06x, PSN 0x%06x, GID %s\n", local_ep.lid,
           local_ep.qpn, local_ep.psn, gid);

    /* Do test */
    if (params.role == role_sink) {
        do_sink(&params, &local_ep);
    } else if (params.role == role_source) {
        do_source(&params, &local_ep);
    } else if (params.role == role_ping) {
        do_ping(&params, &local_ep);
    } else if (params.role == role_pong) {
        do_pong(&params, &local_ep);
    } else {
        fprintf(stderr, "Test not supported\n");
        return -1;
    }

    /* Clean and terminate */
    ibv_free_device_list(dev_list);
    ibv_dereg_mr(mr);
    return 0;

exit:
    ibv_free_device_list(dev_list);
    ibv_dereg_mr(mr);
    // TODO: free the remote address descriptor allocated during the TCP info exchange
    return -1;
}