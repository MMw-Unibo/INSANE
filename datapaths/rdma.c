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

#include "../src/base/nsn_string.c"
#include "../src/base/nsn_memory.c"
#include "../src/base/nsn_os_linux.c"

#include "../src/common/nsn_temp.h"
#include "../src/common/nsn_ringbuf.c"
#include "../src/common/nsn_config.c"

#include <infiniband/verbs.h>

// ---------------------------------------------------------------------------------------------
// ------- Functions for RDMA operations -------------------------------------------------------
//----------------------------------------------------------------------------------------------

// Infiniband device port TODO: Can this be different from 1?
#define IB_PORT 1
// RoCE GID.
// https://docs.nvidia.com/networking/pages/viewpage.action?pageId=19798092#RDMAoverConvergedEthernet(RoCE)-GIDTablePopulation
#define GIDX 0
// RDMA MTU, to be chosen from the enum list.
// For RoCE, it should be less than the minimum MTU
// on the overall data path (usually 1500)
#define IB_MTU IBV_MTU_1024
// Max QP
#define MAX_QP 256

struct conn_state {
    int           lid;
    int           qpn;
    int           psn;
    union ibv_gid gid;
    int           sl;
    int           gidx;
};

// ------------- Plugin specific constants and structures ----------------
#define MAX_PARAM_STRING_SIZE 2048
#define MAX_TX_BURST 64

struct arp_peer {
    char* ip_str; // IP in string form
    u32   ip_net; // IP in network byte order
};

struct rdma_conn {
    struct ibv_cq    *cq;
    struct ibv_qp    *qp;
    struct ibv_qp_ex *qpx;
    struct conn_state local_state;
    struct conn_state remote_state;  
};

// Per-endpoint state
struct rdma_ep {
    struct ibv_pd      *pd;
    struct ibv_mr      *mr;
    struct rdma_conn *conns; // Array of connections to remote peers
    atu32   connected_peers;  // Number of connected peers
    int     sock_svc_fd; // Server socket file descriptor
};
//----------------------------------------------------------------------------------------------
// Handle user work request. Returns the buffer_id of the recv on success, or -1 on failure. If successful, it sets the size of the data in the proper memory area.
static inline int parse_single_wc(struct ibv_wc *wc, nsn_endpoint_t* ep) {
    if (wc->status != IBV_WC_SUCCESS) {
        fprintf(stderr, "[rdma] failed WC: %s (%d) for wr_id %d\n", ibv_wc_status_str(wc->status), wc->status,
                  (int)wc->wr_id);
        return -1;
    }

    // Case 1 - Immediate data
    if (wc->opcode == IBV_WC_RECV || wc->opcode == IBV_WC_RECV_RDMA_WITH_IMM) {
        // Retrieve data len
        usize *size = &((nsn_meta_t*)(nsn_mm_zone_get_ptr(ep->tx_meta_zone)) + wc->wr_id)->len;
        *size = wc->byte_len;
        return wc->wr_id; // Returns the buffer_id
    } else {
        fprintf(stderr, "[rdma] invalid WC opcode received: %d\n", wc->opcode);
        return -1;
    }
}

//----------------------------------------------------------------------------------------------
// Connect to remote QP: this effectively advances QP state to RTS
static inline int connect_ctx(int port, int my_psn, enum ibv_mtu mtu, int sl, int sgid_idx, struct ibv_qp *qp,
                              struct conn_state *dest) {
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
struct conn_state client_exch_dest(const char *server_ip, int port, char* client_ip,
                                  const struct conn_state *local_ep) {
    struct addrinfo *res, *t;
    struct addrinfo   hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};
    char             *service;
    char              msg[sizeof "0000:000000:000000:00000000000000000000000000000000"];
    int               n;
    int               sockfd   = -1;
    struct conn_state rem_dest;
    char              gid[33];

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "[rdma] couldn't connect to %s:%d\n", server_ip, port);
        return (struct conn_state){0};
    }

    int reuseaddr = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) == -1) {
        close(sockfd);
        fprintf(stderr, "[rdma] setsockopt() failed: %s\n", strerror(errno));
        return (struct conn_state){0};
    }

    int reuseport = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &reuseport, sizeof(reuseaddr)) == -1) {
        close(sockfd);
        fprintf(stderr, "[rdma] setsockopt() failed: %s\n", strerror(errno));
        return (struct conn_state){0};
    }

    // Local endpoint info - must ensure the right client port
    struct sockaddr_in sock_addr;
    memory_zero_struct(&sock_addr);
    sock_addr.sin_family      = AF_INET;
    sock_addr.sin_port        = htons(port);
    sock_addr.sin_addr.s_addr = inet_addr(client_ip);
    if (bind(sockfd, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) == -1) {
        close(sockfd);
        fprintf(stderr, "[rdma] bind() failed: %s\n", strerror(errno));
        return (struct conn_state){0};
    }

    // Try to connect to peer. If fail, the conn manager will retry
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    int ret = connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if(ret < 0) {
        fprintf(stderr, "[rdma] connect() failed: %s (%d)\n", strerror(errno), errno);
        close(sockfd);
        return (struct conn_state){0};
    }    

    // Send local address to the remote side
    gid_to_wire_gid(&local_ep->gid, gid);
    sprintf(msg, "%04x:%06x:%06x:%s", local_ep->lid, local_ep->qpn, local_ep->psn, gid);
    if (write(sockfd, msg, sizeof msg) != sizeof msg) {
        fprintf(stderr, "[rdma] couldn't send local address\n");
        goto out;
    }

    // Read remote address and send back ACK
    if (read(sockfd, msg, sizeof msg) != sizeof msg ||
        write(sockfd, "done", sizeof "done") != sizeof "done")
    {
        fprintf(stderr, "[rdma] couldn't read/write remote address: %s\n", strerror(errno));
        goto out;
    }

    sscanf(msg, "%x:%x:%x:%s", &rem_dest.lid, &rem_dest.qpn, &rem_dest.psn, gid);
    wire_gid_to_gid(gid, &rem_dest.gid);

out:
    close(sockfd);
    return rem_dest;
}

//----------------------------------------------------------------------------------------------
struct conn_state server_exch_dest(int connfd, int ib_port, enum ibv_mtu mtu, int sl, int sgid_idx,
                                  struct ibv_qp *qp, const struct conn_state *local_ep) {
    char msg[sizeof "0000:000000:000000:00000000000000000000000000000000"];
    int  n;
    char gid[33];

    struct conn_state rem_dest = (struct conn_state){0};

    // Read remote address
    n = read(connfd, msg, sizeof msg);
    if (n != sizeof msg) {
        fprintf(stderr, "[rdma] %d/%d: Couldn't read remote address: %s\n", n, (int)sizeof msg, strerror(errno));
        return (struct conn_state){0};
    }

    // Parse address and progress QP
    sscanf(msg, "%x:%x:%x:%s", &rem_dest.lid, &rem_dest.qpn, &rem_dest.psn, gid);
    wire_gid_to_gid(gid, &rem_dest.gid);

    if (connect_ctx(ib_port, local_ep->psn, mtu, sl, sgid_idx, qp, &rem_dest)) {
        fprintf(stderr, "[rdma] couldn't connect to remote QP\n");
        return (struct conn_state){0};
    }

    // Prepare message with local address and send it remotely, waiting for ACK
    gid_to_wire_gid(&local_ep->gid, gid);
    sprintf(msg, "%04x:%06x:%06x:%s", local_ep->lid, local_ep->qpn, local_ep->psn, gid);

    if (write(connfd, msg, sizeof msg) != sizeof msg ||
        read(connfd, msg, sizeof msg) != sizeof "done")
    {
        fprintf(stderr, "[rdma] couldn't send/recv local address\n");
        return (struct conn_state){0};
    }
    return rem_dest;
}
//----------------------------------------------------------------------------------------------
// Wrap the code to post a receive request
static inline int post_recv(uint64_t wr_id, char *addr, uint32_t length, struct ibv_qp *qp, struct ibv_mr *mr) {
    // TODO: check that addr + len is within the MR boundary
    struct ibv_sge list    = {.addr = (uint64_t)addr, .length = length, .lkey = mr->lkey};
    int            num_sge = 1;

    struct ibv_recv_wr wr = {
        .wr_id   = wr_id,         /* User defined WR ID: here, the buffer index */
        .next    = NULL,          /* Pointer to next WR in list, NULL if last WR */
        .sg_list = &list,         /* Pointer to the s/g array */
        .num_sge = num_sge,       /* Size of the s/g array */
    };
    struct ibv_recv_wr *bad_wr;
    int                 i;

    for (i = 0; i < num_sge; ++i) {
        if (ibv_post_recv(qp, &wr, &bad_wr)) {
            fprintf(stderr, "[rdma] post send error: %s\n", strerror(errno));
            break;
        }
    }

    return i;
}

//----------------------------------------------------------------------------------------------
// Wrap the code to post a send request
// Send flags: IBV_SEND_SIGNALED
static inline int post_send(char *addr, uint32_t length, int send_flags, struct ibv_qp_ex *qpx, struct ibv_mr *mr, uint64_t wr_id) {
    struct ibv_sge list    = {.addr = (uint64_t)addr, .length = length, .lkey = mr->lkey};
    
    /* NEW API */
    // This is an example of the "new" send API. The verbs work request API (ibv_wr_*) allows
    // efficient posting of work to a send queue using function calls instead of the struct
    // based ibv_post_send() scheme. This approach is designed to minimize CPU branching and
    // locking during the posting process.

    // Start critical section
    ibv_wr_start(qpx);

    qpx->wr_id    = wr_id;
    qpx->wr_flags = send_flags;
    ibv_wr_send(qpx);
    ibv_wr_set_sge(qpx, list.lkey, list.addr, list.length);

    // End critical section on exit
    return ibv_wr_complete(qpx);
}

//----------------------------------------------------------------------------------------------
// Initialize the context: creates PD and QP. Moves QP to INIT state.
static struct ibv_qp* create_qp(struct ibv_context *context, struct ibv_pd *pd, struct ibv_cq *cq, int rx_depth, int tx_depth) {
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

    struct ibv_qp *qp = ibv_create_qp_ex(context, &init_attr_ex);
    if (!qp) {
        fprintf(stderr, "[rdma] cannot create a Queue Pair (QP)\n");
        goto exit;
    }
    
    // The function ibv_create_qp_ex() updated the qp_init_attr_ex->cap struct with the
    // actual QP values of the QP that was created; the values will be greater than or equal
    // to the values requested. Example, like follows:
    // struct ibv_qp_attr      attr;
    // struct ibv_qp_init_attr init_attr;
    // ibv_query_qp(qp, &attr, IBV_QP_CAP, &init_attr);

    /* Transition QP state. ibv_modify_qp is used to progress the QP State Machine */
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
        fprintf(stderr, "[rdma] failed to modify QP to INIT\n");
        perror("error: ");
        goto clean_qp;
    }
    
exit:
    return qp;
clean_qp:
    ibv_destroy_qp(qp);
    qp = NULL;
    return NULL;
}

//-----------------------------------------------------------------------------------------------
// Prepare the completion queue (CQ) and queue pair (QP) for connection to a specific peer.
static inline int prepare_cq_qp(struct ibv_context *context, struct rdma_conn *conn_p, struct arp_peer *peer, struct ibv_pd *pd, int rx_depth, int tx_depth) {
    /* Create completion queue (without HW completion ts) */
    conn_p->cq = ibv_create_cq(context, rx_depth + 1, NULL, NULL, 0);
    if (!conn_p->cq) {
        printf("[rdma] cannot create a completion queue (CQ) for peer %s\n", peer->ip_str);
        return -1;
    }

    /* Create queue pair (QP), set to INIT state */
    conn_p->qp = create_qp(context, pd, conn_p->cq, rx_depth, tx_depth);
    if (!conn_p->qp) {
        printf("[rdma] cannot create a Queue Pair (QP) for peer %s\n", peer->ip_str);
        ibv_destroy_cq(conn_p->cq);
        conn_p->cq = NULL;
        return -1;
    }

    /* Get the extended QP version from QP */
    conn_p->qpx = ibv_qp_to_qp_ex(conn_p->qp);

    // Get local endpoint info
    // Currently I keep separate info because it depends on the QP.
    conn_p->local_state.gidx = GIDX;
    conn_p->local_state.sl   = 0; // Service Level. Used only for UD mode. Set to 0 here
    char gid[33];
    struct ibv_port_attr ib_port_info;
    if (ibv_query_port(context, IB_PORT, &ib_port_info)) {
        fprintf(stderr, "[rdma] couldn't get port info for peer %s\n", peer->ip_str);
        ibv_destroy_cq(conn_p->cq);
        conn_p->cq = NULL;
        ibv_destroy_qp(conn_p->qp);
        conn_p->qp = NULL;
        return -1;
    }
    conn_p->local_state.lid = ib_port_info.lid;
    if (ib_port_info.link_layer != IBV_LINK_LAYER_ETHERNET && !conn_p->local_state.lid) {
        fprintf(stderr, "[rdma] couldn't get local LID for peer %s\n", peer->ip_str);
        ibv_destroy_cq(conn_p->cq);
        conn_p->cq = NULL;
        ibv_destroy_qp(conn_p->qp);
        conn_p->qp = NULL;
        return -1;
    }
    // For RoCE:
    if (ibv_query_gid(context, IB_PORT, conn_p->local_state.gidx, &conn_p->local_state.gid)) {
        fprintf(stderr, "[rdma] can't read sgid of index %d for peer %s\n", conn_p->local_state.gidx, peer->ip_str);
        ibv_destroy_cq(conn_p->cq);
        conn_p->cq = NULL;
        ibv_destroy_qp(conn_p->qp);
        conn_p->qp = NULL;
        return -1;
    }

    conn_p->local_state.qpn = conn_p->qp->qp_num;
    conn_p->local_state.psn = lrand48() & 0xffffff; // Random initial PSN. That's important for security!
    inet_ntop(AF_INET6, &conn_p->local_state.gid, gid, sizeof gid);
    printf("[rdma] Peer %s local address:  LID 0x%04x, QPN 0x%06x, PSN 0x%06x, GID %s\n", peer->ip_str, conn_p->local_state.lid, conn_p->local_state.qpn, conn_p->local_state.psn, gid);    

    return 0;
}

//----------------------------------------------------------------------------------------------
// Register with the NIC an arbitrary memory area for zero-copy send/receive
// WARNING: "addr" and "len" MUST be aligned to the "page size"
struct ibv_mr* register_mr(struct ibv_pd *pd, char *addr, size_t len) {
    
    fprintf(stderr, "[rdma] registering memory area %p, len %lu\n", addr, len);

    // Pin pages in memory (necessary if we do not use hugepages)
    mlock(addr, len);
    
    // Memory protection. Possible values (composable):
    // IBV_ACCESS_LOCAL_WRITE   Enable Local Write Access
    // IBV_ACCESS_REMOTE_WRITE  Enable Remote Write Access
    // IBV_ACCESS_REMOTE_READ   Enable Remote Read Access
    // IBV_ACCESS_REMOTE_ATOMIC Enable Remote Atomic Operation Access (if supported)
    // IBV_ACCESS_MW_BIND       Enable Memory Window
    int access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ;

    // Register the memory as MR
    struct ibv_mr* mr = ibv_reg_mr(pd, addr, len, access_flags);
    if (!mr) {
        printf("cannot register a memory region: %s\n", strerror(errno));
        return mr;
    }

    // For better performance, we could prefetch parts of the MR
    // with the ibv_advise_mr() verb. We don't do that for the moment

    return mr;
}

// ----------------------------------------------------------------------------------------------
// ----------------------------------------------------------------------------------------------
// Plugin state
static temp_mem_arena_t scratch;
static struct arp_peer* peers; // Works as ARP cache
static u16 n_peers;
static char* local_ip;
static uint32_t local_ip_net;
static int sock_svc_fd;
static struct ibv_device  *ib_dev;
static struct ibv_context *context;
static int rx_depth;
static int tx_depth;
//----------------------------------------------------------------------------------------------
// API functions
NSN_DATAPATH_UPDATE(rdma) {
    if (endpoint == NULL) {
        fprintf(stderr, "[rdma] invalid endpoint\n");
        return -1;
    }

    // Case 1. Delete endpoint data.
    if(endpoint->data) {
        struct rdma_ep *conn = (struct rdma_ep *)endpoint->data;  
        
        // Close the server socket
        if (conn->sock_svc_fd >= 0) {
            close(conn->sock_svc_fd);
            conn->sock_svc_fd = -1;
        }

        // Close all the connections
        for(int p = 0; p < n_peers; p++) {
            struct rdma_conn *conn_p = &conn->conns[p];
            if (conn_p->cq) {
                ibv_destroy_cq(conn_p->cq);
                conn_p->cq = NULL;
            }
            if (conn_p->qp) {
                ibv_destroy_qp(conn_p->qp);
                conn_p->qp = NULL;
            }
        }
        
        // free the array of connections
        free(conn->conns);
        // deregister memory
        ibv_dereg_mr(conn->mr);
        // remove PD for the endpoint
        ibv_dealloc_pd(conn->pd);
        // free the endpoint plugin state
        free(endpoint->data);
        endpoint->data = NULL;
    }
    // Case 2. Create endpoint data.
    else {  
        // create the state of the endpoint, which will hold connection data
        endpoint->data = malloc(sizeof(struct rdma_ep));
        if (endpoint->data == NULL) {
            fprintf(stderr, "[rdma] malloc() failed\n");
            return -1;
        }
        endpoint->data_size = sizeof(struct rdma_ep);

        // Initialize the state of the endpoint
        struct rdma_ep *conn = (struct rdma_ep *)endpoint->data;

        // Create a Protection Domain for the endpoint
        conn->pd = ibv_alloc_pd(context);
        if (!conn->pd) {
            printf("cannot allocate PD\n");
            goto error_2;
        }
        // We do not check for ODP as we do not use it
        // We do not check for HW completion timestamp (ts)
        // We do not check if we can use device memory (DM) for allocation

        /* Allocate memory are and register it with the NIC as MR */
        char *addr = (char*)endpoint->tx_zone;
        usize len = endpoint->tx_zone->total_size;

        conn->mr = register_mr(conn->pd, addr, len);
        if (!conn->mr) {
            goto error_1;
        }
        
        // Create an array of QPs and CQs, one for each peer
        conn->conns = (struct rdma_conn*)malloc(n_peers * sizeof(struct rdma_conn));
        if (!conn->conns) {
            fprintf(stderr, "[rdma] malloc() failed for connections\n");
            goto clean_pd;
        }

        // Try connect to the peers
        for(int p = 0; p < n_peers; p++) {
            struct rdma_conn *conn_p = &conn->conns[p];
            memset(conn_p, 0, sizeof(struct rdma_conn));

            if (prepare_cq_qp(context, conn_p, &peers[p], conn->pd, rx_depth, tx_depth) < 0) {
                fprintf(stderr, "[rdma] prepare_cq_qp() failed for peer %s\n", peers[p].ip_str);
                continue;
            } 

            // Exchange QP info with the sink
            conn_p->remote_state = client_exch_dest(peers[p].ip_str, endpoint->app_id, local_ip, &conn_p->local_state);
            if (conn_p->remote_state.psn == 0 && conn_p->remote_state.qpn == 0) {
                fprintf(stderr, "[rdma] failed to exchange remote QP info with peer %s\n", peers[p].ip_str);
                ibv_destroy_cq(conn_p->cq);
                conn_p->cq = NULL;
                ibv_destroy_qp(conn_p->qp);
                conn_p->qp = NULL;
                continue;
            }

            // Move the QP state to RTS
            if (connect_ctx(IB_PORT, conn_p->local_state.psn, IB_MTU, conn_p->local_state.sl, conn_p->local_state.gidx,  conn_p->qp, &conn_p->remote_state)) {
                fprintf(stderr, "[rdma] failed to move QP to RTS\n");
                ibv_destroy_cq(conn_p->cq);
                conn_p->cq = NULL;
                ibv_destroy_qp(conn_p->qp);
                conn_p->qp = NULL;
                continue;
            }

            atomic_fetch_add(&conn->connected_peers, 1);

            // Print remote address
            inet_ntop(AF_INET6, &conn_p->remote_state.gid, (char*)conn_p->remote_state.gid.raw, sizeof conn_p->remote_state.gid.raw);
            printf("[rdma] Connected to peer %s. Remote address: LID 0x%04x, QPN 0x%06x, PSN 0x%06x, GID %s\n", peers[p].ip_str, conn_p->remote_state.lid, conn_p->remote_state.qpn, conn_p->remote_state.psn, (char *)conn_p->remote_state.gid.raw);
        }

        /* Establish a server socket */
        struct addrinfo *res, *t;
        struct addrinfo  hints = {
            .ai_flags = AI_PASSIVE, .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM};
        char *service;
        uint16_t port = endpoint->app_id;
    
        if (asprintf(&service, "%d", port) < 0) {
            goto server_fail;
        }
        int n = getaddrinfo(NULL, service, &hints, &res);
        if (n < 0) {
            fprintf(stderr, "%s for port %d\n", gai_strerror(n), port);
            free(service);
            goto server_fail;
        }
        for (t = res; t; t = t->ai_next) {
            conn->sock_svc_fd = socket(t->ai_family, t->ai_socktype, t->ai_protocol);
            if (conn->sock_svc_fd >= 0) {
                n = 1;
                setsockopt(conn->sock_svc_fd, SOL_SOCKET, SO_REUSEADDR, &n, sizeof n);

                int flags = fcntl(conn->sock_svc_fd, F_GETFL, 0);
                if (flags == -1) {
                    fprintf(stderr, "[tcpsock] fcntl() failed: %s\n", strerror(errno));
                    close(conn->sock_svc_fd);
                    conn->sock_svc_fd = -1;
                    goto server_fail;
                }
                flags |= O_NONBLOCK;
                if (fcntl(conn->sock_svc_fd, F_SETFL, flags) == -1) {
                    fprintf(stderr, "[tcpsock] fcntl() failed: %s\n", strerror(errno));
                    close(conn->sock_svc_fd);
                    conn->sock_svc_fd = -1;
                    goto server_fail;
                }   

                if (!bind(conn->sock_svc_fd, t->ai_addr, t->ai_addrlen))
                    break;
                close(conn->sock_svc_fd);
                conn->sock_svc_fd = -1;
            }
        }
        freeaddrinfo(res);
        free(service);
        if (conn->sock_svc_fd < 0) {
            fprintf(stderr, "[rdma] couldn't listen to port %d\n", port);
            goto server_fail;
        }

        // Listen & Accept
        listen(conn->sock_svc_fd, 1);

        // Prepare a number of receive request for each connected peer (rx-depth of QP is the limit)
        nsn_buf_t buf;
        for (int p = 0; p < n_peers; p++) {

            // only if the peer is connected
            if (conn->conns[p].remote_state.psn == 0 && conn->conns[p].remote_state.qpn == 0) {
                continue;
            }

            for (int i = 0; i < rx_depth; ++i) {
                struct rdma_conn *conn_p = &conn->conns[p];
                if (conn_p->remote_state.psn == 0 && conn_p->remote_state.qpn == 0) {
                    continue;
                }          

                // dequeue a free buffer
                u32 np = nsn_ringbuf_dequeue_burst(endpoint->free_slots, &buf, sizeof(buf), 1, NULL);
                if (np == 0) {
                    printf("[rdma] no free slots to receive from ring %p [%u]\n", endpoint->free_slots, nsn_ringbuf_count(endpoint->free_slots));
                    continue;
                }

                // use the buffer to post a receive request
                char  *addr       = (char*)(nsn_mm_zone_get_ptr(endpoint->tx_zone)) + (buf.index * endpoint->io_bufs_size);    
                uint32_t max_size = (uint32_t)endpoint->io_bufs_size;

                int nb_rx = post_recv(buf.index, addr, max_size, conn_p->qp, conn->mr);
                if (nb_rx < 1) {
                    fprintf(stderr, "[rdma] couldn't post receive %d (%d)\n", i, nb_rx);
                    continue;
                }
            }
        }

        return 0;
server_fail:
        for(int p = 0; p < n_peers; p++) {
            struct rdma_conn *conn_p = &conn->conns[p];      
            if (conn_p->cq) {
                ibv_destroy_cq(conn_p->cq);
                conn_p->qp = NULL;
            }
            if (conn_p->qp) {
                ibv_destroy_qp(conn_p->qp);
                conn_p->qp = NULL;
            }
        }
clean_pd:
        ibv_dealloc_pd(conn->pd);
error_2:
        ibv_dereg_mr(conn->mr);
error_1:
        free(conn);
        return -1;
    }

    return 0;
}

NSN_DATAPATH_CONN_MANAGER(rdma)
{
    if (endpoint_list == NULL) {
        fprintf(stderr, "[rdma] connection manager: invalid endpoint_list\n");
        return -1;
    }
    if (list_empty(endpoint_list)) {
        return 0;
    }

    ep_initializer_t *ep_in;
    list_for_each_entry(ep_in, endpoint_list, node) {    
        nsn_endpoint_t *ep = ep_in->ep;
        struct rdma_ep *conn = (struct rdma_ep *)ep->data;

        // already connected to all peers - skip
        u32 conn_peers = at_load(&conn->connected_peers, mo_rlx);
        if (conn_peers == n_peers) {
            continue;
        }

        // Accept incoming connections
        bool found;
        int connfd;
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        while((connfd = accept(conn->sock_svc_fd, (struct sockaddr *)&client_addr, &addr_len)) > 0) {
            found = false;
            for (int p = 0; p < n_peers; p++) {
                // connection was for peer p
                if(client_addr.sin_addr.s_addr == peers[p].ip_net && client_addr.sin_port == htons(ep->app_id)) {
                    found = true;
                    struct rdma_conn *conn_p = &conn->conns[p];

                    if (prepare_cq_qp(context, conn_p, &peers[p], conn->pd, rx_depth, tx_depth) < 0) {
                        fprintf(stderr, "[rdma] prepare_cq_qp() failed for peer %s\n", peers[p].ip_str);
                        close(connfd);
                        continue;
                    }              

                    struct conn_state rem = server_exch_dest(connfd, IB_PORT, IB_MTU, conn_p->local_state.sl, conn_p->local_state.gidx, conn_p->qp, &conn_p->local_state);
                    close(connfd);
                    if (rem.gid.raw[0] == 0 && rem.qpn == 0 && rem.psn == 0) {
                        fprintf(stderr, "[rdma] failed to exchange remote QP info with the source\n");
                        continue;
                    }
                    conn_p->remote_state = rem;
                    atomic_fetch_add(&conn->connected_peers, 1);
                    fprintf(stderr, "[rdma] Connected to peer %s. Remote address: LID 0x%04x, QPN 0x%06x, PSN 0x%06x\n",
                            peers[p].ip_str, conn_p->remote_state.lid, conn_p->remote_state.qpn, conn_p->remote_state.psn);
                    
                    // Post a number of receive requests for the peer 
                    nsn_buf_t buf;
                    for (int i = 0; i < rx_depth; ++i) {
                        // dequeue a free buffer
                        u32 np = nsn_ringbuf_dequeue_burst(ep->free_slots, &buf, sizeof(buf), 1, NULL);
                        if (np == 0) {
                            printf("[rdma] no free slots to receive from ring %p [%u]\n", ep->free_slots, nsn_ringbuf_count(ep->free_slots));
                            continue;
                        }

                        // use the buffer to post a receive request
                        char  *addr  = (char*)(nsn_mm_zone_get_ptr(ep->tx_zone)) + (buf.index * ep->io_bufs_size);    
                        uint32_t max_size = (uint32_t)ep->io_bufs_size;

                        int nb_rx = post_recv(buf.index, addr, max_size, conn_p->qp, conn->mr);
                        if (nb_rx < 1) {
                            fprintf(stderr, "[rdma] couldn't post receive %d (%d)\n", i, nb_rx);
                            continue;
                        }
                    }
                    break;
                }
            }
            if (!found) {
                close(connfd);
                fprintf(stderr, "[rdma] received connection from unknown peer %s:%d. Closed.\n",
                        inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
            }
        }
    }

    return 0;
}

NSN_DATAPATH_INIT(rdma)
{
    nsn_thread_ctx_t this_thread = nsn_thread_ctx_alloc();
    this_thread.is_main_thread   = false;
    nsn_thread_set_ctx(&this_thread);

    scratch = nsn_thread_scratch_begin(NULL, 0);

    // 1a) Initialize local state 
    n_peers = ctx->n_peers;
    peers = mem_arena_push(scratch.arena, n_peers * sizeof(struct arp_peer));
    for (int i = 0; i < n_peers; i++) {
        peers[i].ip_str = ctx->peers[i];
        peers[i].ip_net = inet_addr(peers[i].ip_str);
    }

    // 1b) Retrieve the local IP from the list of parameters
    string_t local_ip_str;
    local_ip_str.data = mem_arena_push(scratch.arena, MAX_PARAM_STRING_SIZE);
    local_ip_str.len = 0;
    int ret = nsn_config_get_string_from_list(&ctx->params, str_lit("ip"), &local_ip_str);
    if (ret < 0) {
        fprintf(stderr, "[rdma] nsn_config_get_string_from_list() failed: no option \"ip\" found\n");
        goto early_fail;
    }
    local_ip = to_cstr(local_ip_str);
    local_ip_net = inet_addr(local_ip);
    fprintf(stderr, "[rdma] parameter: ip: %s\n", local_ip);

    // 1c) Retrieve the device name from the list of parameters
    string_t ib_dev_name;
    ib_dev_name.data = mem_arena_push(scratch.arena, MAX_PARAM_STRING_SIZE);
    ib_dev_name.len = 0;
    ret = nsn_config_get_string_from_list(&ctx->params, str_lit("device"), &ib_dev_name);
    if (ret < 0) {
        fprintf(stderr, "[rdma] nsn_config_get_string_from_list() failed: no option \"device\" found\n");
        goto early_fail;
    }
    const char *ib_dev_name_cstr = to_cstr(ib_dev_name);
    fprintf(stderr, "[rdma] parameter: device: %s\n", ib_dev_name_cstr);

    /* Get RDMA device info and print them */
    int                 num_devices;
    struct ibv_device **dev_list = ibv_get_device_list(&num_devices);
    if (!dev_list) {
        fprintf(stderr, "[rdma] failed to get IB devices list");
        goto early_fail;
    }
    fprintf(stderr, "[rdma] found %d RDMA devices\n", num_devices);

    // Find the requested device from the available devices list
    ib_dev = NULL;
    for (int i = 0; i < num_devices; i++) {
        if (!strcmp(ibv_get_device_name(dev_list[i]), ib_dev_name_cstr)) {
            ib_dev = dev_list[i];
            fprintf(stderr, "Found RDMA device %s\n", ibv_get_device_name(ib_dev));
            break;
        }
    }
    if (!ib_dev) {
        fprintf(stderr, "[rdma] failed to find requested RDMA device %s\n", ib_dev_name_cstr);
        goto early_rdma_fail;
    }

    /* Initialize the IB context by opening the device */
    context = ibv_open_device(ib_dev);
    if (!context) {
        printf("cannot get context for %s\n", ibv_get_device_name(ib_dev));
        goto early_rdma_fail;
    }

    // RDMA queue depth
    tx_depth = 256;
    rx_depth = 256;

    // Setup the communication channels to the peers
    ep_initializer_t *ep_in;
    list_for_each_entry(ep_in, endpoint_list, node) {
        ret = rdma_datapath_update(ep_in->ep);
        if (ret < 0) {
            fprintf(stderr, "[rdma] rdma_datapath_update() failed\n");
            goto rdma_fail;
        }
    }

    ibv_free_device_list(dev_list);
    return 0;

rdma_fail:
    ibv_close_device(context);
early_rdma_fail:
    ibv_free_device_list(dev_list);
early_fail:
    nsn_thread_scratch_end(scratch);
    return -1;
}

NSN_DATAPATH_TX(rdma)
{
    int nb_tx = 0;
    int ret;
    struct ibv_wc wc;

    if (buf_count > MAX_TX_BURST) {
        fprintf(stderr, "[tcpdpdk] tx burst too large\n");
        return -1;
    }
    
    struct rdma_ep *conn = (struct rdma_ep *)endpoint->data;
    for(int p = 0; p < n_peers; p++) {
        //if the peer is not connected, skip
        struct rdma_conn *conn_p = &conn->conns[p];
        if (conn_p->remote_state.psn == 0 && conn_p->remote_state.qpn == 0) {
            continue;
        }

        for (usize i = 0; i < buf_count; i++) {

            char* data = (char*)(nsn_mm_zone_get_ptr(endpoint->tx_zone)) + (bufs[i].index * endpoint->io_bufs_size); 
            usize size = ((nsn_meta_t*)(nsn_mm_zone_get_ptr(endpoint->tx_meta_zone)) + bufs[i].index)->len; 

            if(post_send(data, size, IBV_SEND_SIGNALED, conn_p->qpx, conn->mr, bufs[i].index) < 0) {
                fprintf(stderr, "[rdma] post_send() failed for buf %d\n", (int)bufs[i].index);
                continue;
            }
            nb_tx++;

            // Get SEND completion
            // This slows down performance but ensures the receiver
            // confirms the reception of all data
            // Alternative: do not use SEND_SIGNALED and do not poll for completions.
            // But if you use SEND_SIGNALED, you must poll for completions.
            do {
                ret = ibv_poll_cq(conn_p->cq, 1, &wc);
                if (ret < 0) {
                    fprintf(stderr, "[rdma] failed polling cq: %d\n", ret);
                    continue;
                }
            } while (ret < 1);
            if (wc.status != IBV_WC_SUCCESS) {
                fprintf(stderr, "[rdma] failed WR: %s (%d) for wr_id %d\n", ibv_wc_status_str(wc.status),
                          wc.status, (int)wc.wr_id);
                continue;
            }
            
        }

        // Returns ALL the buffers to the free slots ring, regardless of the send status
        if(nsn_ringbuf_enqueue_burst(endpoint->free_slots, bufs, sizeof(bufs[0]), buf_count, NULL) < buf_count) {
            fprintf(stderr, "[tcpsock] Failed to enqueue descriptors\n");
        }
    }

    return nb_tx;
}

NSN_DATAPATH_RX(rdma)
{
    struct ibv_wc wc;
    int ret, nb_rx, valid;

    struct rdma_ep *conn = (struct rdma_ep *)endpoint->data;
    valid = 0;

    // We attempt to receive once per peer (1) 
    for (int p = 0; p < n_peers; p++) {
        struct rdma_conn *conn_p = &conn->conns[p];
        if (conn_p->remote_state.psn == 0 && conn_p->remote_state.qpn == 0) {
            // Not connected to this peer yet, skip
            continue;
        }

        // Check if there are any completions in the CQ
        ret = ibv_poll_cq(conn_p->cq, 1, &wc);
        if (ret < 0) {
            fprintf(stderr, "[rdma] ibv_poll_cq() failed: %s\n", strerror(errno));
            return -1;
        } else if (ret == 0) {
            // No completions, skip
            continue;
        }

        // Parse the WC to get the incoming buf_id (coded in wr_id)
        if ((ret = parse_single_wc(&wc, endpoint)) < 0) {
            fprintf(stderr, "[rdma] failed to parse WC\n");
            continue;
        }
        
        // The size is set in the parse_single_wc() function, if successful.
        // Here we just pass the buf_id returned by that funcion.
        bufs[valid].index = ret;
        *buf_count  = *buf_count - 1;
        valid++;
        
        // Post receive request
        nsn_buf_t buf;
        u32 np = nsn_ringbuf_dequeue_burst(endpoint->free_slots, &buf, sizeof(buf), 1, NULL);
        if (np == 0) {
            printf("[rdma] no free slots to receive from ring %p [%u]\n", endpoint->free_slots, nsn_ringbuf_count(endpoint->free_slots));
            continue;
        }
        char  *addr  = (char*)(nsn_mm_zone_get_ptr(endpoint->tx_zone)) + (buf.index * endpoint->io_bufs_size);    
        uint32_t max_size = (uint32_t)endpoint->io_bufs_size;
        int nb_rx = post_recv(buf.index, addr, max_size, conn_p->qp, conn->mr);
        if (nb_rx < 1) {
            fprintf(stderr, "[rdma] couldn't post receive (%d)\n", nb_rx);
            continue;
        }      
    }

    return valid;
}

NSN_DATAPATH_DEINIT(rdma)
{
    nsn_unused(ctx);
    
    int res = 0;
    struct ep_initializer *ep_in;
    list_for_each_entry(ep_in, endpoint_list, node) {
        res = rdma_datapath_update(ep_in->ep);
        if (res < 0) {
            fprintf(stderr, "[rdma] endpoint destruction failed\n");
            return res;
        }
    }
    ibv_close_device(context);
    nsn_thread_scratch_end(scratch);
    return res;
}
