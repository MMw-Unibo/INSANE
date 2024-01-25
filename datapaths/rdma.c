#define _GNU_SOURCE
#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "../src/nsn_datapath.h"

#include <infiniband/verbs.h>

// Infiniband device port
#define IB_PORT         1
// RoCE GID. //TODO: Understand what is it. Start here:
// https://docs.nvidia.com/networking/pages/viewpage.action?pageId=19798092#RDMAoverConvergedEthernet(RoCE)-GIDTablePopulation
#define GIDX            0
// RDMA MTU, to be chosen from the enum list.
// For RoCE, it should be less than the minimum MTU
// on the overall data path (uually 1500)
#define IB_MTU          IBV_MTU_1024
// App-defined WR id. I use only one here, but the ping-pong example
// used this field to distinguish between ping/pong messages.
#define TESTRDMA_WRID   2509
// Max QP
#define MAX_QP          256
// TCP/IP info
#define SERVER_ADDR     "192.168.56.212"
#define PORT            9999

struct endpoint {
    unsigned int  lid;
    unsigned int  qpn;
    unsigned int  psn;
    union ibv_gid gid;
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
static int        pending;
////////////////////////////////////////////////////////////

//----------------------------------------------------------------------------------------------
// Handle user work request
static inline int 
parse_single_wc(struct ibv_wc *wc) {
    if (wc->status != IBV_WC_SUCCESS) {
        fprintf(stderr, "Failed status %s (%d) for wr_id %d\n", ibv_wc_status_str(wc->status),
                wc->status, (int)wc->wr_id);
        return 1;
    }

    // Check the ID
    if ((int)wc->wr_id != TESTRDMA_WRID) {
        fprintf(stderr, "Completion for unknown wr_id %d\n", (int)wc->wr_id);
        return 1;
    }

    // Case 1 - Immediate data
    if (wc->opcode == IBV_WC_RECV) {

        // Retrieve data len
        size_t len = wc->byte_len;
        printf("Received data with length %lu\n", len);
        fflush(stdout);

        // Print data
        // write(1, "Received data: ", 15);
        // write(1, mr->addr, len);
        // write(1, "\n", 1);

    }
    // Case 2 - Recv value
    else if (wc->opcode == IBV_WC_RECV_RDMA_WITH_IMM)
    {
        printf("Reception of data with immediate not supported yet\n");
        fflush(stdout);
        return 1;
    } else {
        printf("Invalid opcode received\n");
        fflush(stdout);
        return 1;
    }
    return 0;
}

//----------------------------------------------------------------------------------------------
// Connect to remote QP: this effectively advances QP state to RTS
static int 
connect_ctx(int port, int my_psn, enum ibv_mtu mtu, int sl, int sgid_idx, struct endpoint *dest) 
{
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
static void 
gid_to_wire_gid(const union ibv_gid *gid, char wgid[]) 
{
    uint32_t tmp_gid[4];
    int      i;

    memcpy(tmp_gid, gid, sizeof(tmp_gid));
    for (i = 0; i < 4; ++i) {
        sprintf(&wgid[i * 8], "%08x", htobe32(tmp_gid[i]));
    }
}

//----------------------------------------------------------------------------------------------
static void 
wire_gid_to_gid(const char *wgid, union ibv_gid *gid) 
{
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
static struct endpoint *
client_exch_dest(const char *servername, int port, const struct endpoint *my_dest) 
{
    struct addrinfo *res, *t;
    struct addrinfo  hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};
    char            *service;
    char             msg[sizeof "0000:000000:000000:00000000000000000000000000000000"];
    int              n;
    int              r;
    int              i;
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
    gid_to_wire_gid(&my_dest->gid, gid);
    sprintf(msg, "%04x:%06x:%06x:%s", my_dest->lid, my_dest->qpn, my_dest->psn, gid);
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
static struct endpoint *
server_exch_dest(int ib_port, enum ibv_mtu mtu, int port, int sl, int sgid_idx,
                 const struct endpoint *my_dest) 
{
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

    if (connect_ctx(ib_port, my_dest->psn, mtu, sl, sgid_idx, rem_dest)) {
        fprintf(stderr, "Couldn't connect to remote QP\n");
        free(rem_dest);
        rem_dest = NULL;
        goto out;
    }

    // Prepare message with local address and send it remotely, waiting for ACK
    gid_to_wire_gid(&my_dest->gid, gid);
    sprintf(msg, "%04x:%06x:%06x:%s", my_dest->lid, my_dest->qpn, my_dest->psn, gid);

    if (write(connfd, msg, sizeof msg) != sizeof msg ||
        read(connfd, msg, sizeof msg) != sizeof "done") {
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
static int 
post_recv(char *addr, uint32_t length) 
{
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
static int 
post_send(char *addr, uint32_t length, int send_flags) 
{
    struct ibv_sge list    = {.addr = (uint64_t)addr, .length = length, .lkey = mr->lkey};
    int            num_sge = 1;

    // // If data to send is less than the inline threshold, send data inline
    // struct ibv_qp_init_attr init_attr;
    // struct ibv_qp_attr      attr;
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
static int 
init_ibv_context() 
{
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
            1; // Requested max scatter/gather elements in a WR in the SQ
        init_attr_ex.cap.max_recv_sge = 1; // Requested max number of s/g elements in a WR in the RQ
        init_attr_ex.qp_type          = IBV_QPT_RC; // QP Transport Service Type
        init_attr_ex.comp_mask        = IBV_QP_INIT_ATTR_PD | IBV_QP_INIT_ATTR_SEND_OPS_FLAGS;
        init_attr_ex.pd               = pd;
        init_attr_ex.send_ops_flags   = IBV_QP_EX_WITH_SEND;

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
                          IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS)) {
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
static int 
init_mr(char *memory, size_t memory_size) 
{
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


NSN_DATAPATH_INIT(rdma)
{
    nsn_unused(ctx);

    int num_devices = 0;
    struct ibv_device **dev_list = NULL;    
    dev_list = ibv_get_device_list(&num_devices);

    if (num_devices == 0)
        return -1;
        
    ib_dev           = dev_list[0];
    const char *name = ibv_get_device_name(ib_dev);
    printf("Using the first: %s\n", name);

    // Initialize PD and QP. QP is set to INIT state
    int res = init_ibv_context();
    if (res < 0)
        return -1;

    printf("DATAAAAA: %p (%ld)\n", ctx->data_memory, ctx->data_memory_size);

    res = init_mr(ctx->data_memory, ctx->data_memory_size);
    if (res < 0)
        return -1;

    // Get local endpoint info
    struct endpoint      my_dest;
    int                  gidx = GIDX;
    char                 gid[33];
    int                  sl = 0; // Service Level. Used only for UD mode. Set to 0 here
    struct ibv_port_attr ib_port_info;
    if (ibv_query_port(context, IB_PORT, &ib_port_info)) {
        fprintf(stderr, "Couldn't get port info\n");
        return -1;
    }

    my_dest.lid = ib_port_info.lid;
    if (ib_port_info.link_layer != IBV_LINK_LAYER_ETHERNET && !my_dest.lid) {
        fprintf(stderr, "Couldn't get local LID\n");
        return -1;
    }

    // For Infiniband, it would be sufficient:
    // memset(&my_dest.gid, 0, sizeof(my_dest.gid));
    // For RoCE:
    if (ibv_query_gid(context, IB_PORT, gidx, &my_dest.gid)) {
        fprintf(stderr, "can't read sgid of index %d\n", gidx);
        return -1;
    }

    my_dest.qpn = qp->qp_num;
    my_dest.psn = lrand48() & 0xffffff; // Random initial PSN. That's important for security!
    inet_ntop(AF_INET6, &my_dest.gid, gid, sizeof gid);
    printf("  local address:  LID 0x%04x, QPN 0x%06x, PSN 0x%06x, GID %s\n", my_dest.lid,
           my_dest.qpn, my_dest.psn, gid);

    // Send local endpoint info to the remote side, read the remote info
    // This uses a TCP socket to exchange the necessary information
    struct endpoint *rem_dest;

    // In case of server, this also moves the QP state from INIT to RTS
    rem_dest = server_exch_dest(IB_PORT, IB_MTU, PORT, sl, gidx, &my_dest);
    if (!rem_dest) {
        return -1;
    }

    return 0;
}