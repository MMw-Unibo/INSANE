#include "nsn_types.h"

#include "nsn.h"
#include "nsn_ipc.h"
#include "nsn_memory.h"
#include "nsn_os.h"
#include "nsn_shm.h"
#include "nsn_zone.h"

// struct nsn_app_context
// {
//     int id;

//     // nsn_meminfo_t    info;
//     // nsn_meminfo_tx_t tx_info[2];

//     i32                ctrl_sockfd;
//     struct sockaddr_un req_addr;
//     struct sockaddr_un res_addr;
//     char               ctrl_path[IPC_MAX_PATH_SIZE];

//     // TODO: this should a list of memory pools or a single abstracted memory pool???
//     // /* Memory Pools */
//     // // DPDK
//     // struct rte_mempool *dpdk_pool;
//     // nsn_ioctx_dpdk_t   *dpdk_ctx;
//     // // Socket
//     // nsn_meminfo_t     *socket_pool;
//     // nsn_ioctx_socket_t socket_ctx;
// };


mem_arena_t *arena = NULL;
int app_id         = -1;
int sockfd         = -1;
struct sockaddr_un nsn_app_addr;
struct sockaddr_un nsnd_addr;
nsn_shm_t *shm            = NULL;
nsn_mutex_t nsn_app_mutex = NSN_OS_MUTEX_INITIALIZER;

// -----------------------------------------------------------------------------
int 
nsn_init()
{
    arena = mem_arena_alloc_default();

    temp_mem_arena_t temp = temp_mem_arena_begin(arena);

    // open a connection with the insance of the nsn daemon
    sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return -1;
    }

    nsn_app_addr.sun_family = AF_UNIX;
    
    app_id = nsn_os_get_process_id();

    char name[IPC_MAX_PATH_SIZE];
    snprintf(name, IPC_MAX_PATH_SIZE, "%s%d", NSND_TO_NSNAPP_IPC, app_id);

    if (bind(sockfd, (struct sockaddr *)&nsn_app_addr, sizeof(struct sockaddr_un)) < 0) {
        goto exit_error;
        return -1;
    }

    // set a timeout for the socket
    struct timeval tv;
    tv.tv_sec  = 0;
    tv.tv_usec = 5000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    // send a message to the daemon to create a new instance
    byte *cmsg = mem_arena_push_array(temp.arena, byte, 4096);

    nsn_cmsg_hdr_t *cmsghdr = (nsn_cmsg_hdr_t *)cmsg;
    cmsghdr->type   = NSN_CMSG_TYPE_CONNECT;
    cmsghdr->app_id = app_id;

    nsnd_addr.sun_family = AF_UNIX;
    strncpy(nsnd_addr.sun_path, NSNAPP_TO_NSND_IPC, sizeof(nsnd_addr.sun_path) - 1);

    sendto(sockfd, cmsg, sizeof(nsn_cmsg_hdr_t), 0, (struct sockaddr *)&nsnd_addr, sizeof(struct sockaddr_un));
    
    if (recvfrom(sockfd, cmsg, 4096, 0, NULL, NULL) == -1) {
        fprintf(stderr, "failed to connect to nsnd with error '%s', is it running?\n", strerror(errno));
        goto exit_error;
    }

    if (cmsghdr->type == NSN_CMSG_TYPE_ERROR) {
        int error = *(int *)(cmsg + sizeof(nsn_cmsg_hdr_t));
        fprintf(stderr, "failed to connect to nsnd with error '%d'\n", error); 
        goto exit_error;
    }

    nsn_cmsg_connect_t *resp = (nsn_cmsg_connect_t *)(cmsg + sizeof(nsn_cmsg_hdr_t));

    printf("connected to nsnd, the shm is at /dev/shm/%s, with size %zu\n", resp->shm_name, resp->shm_size);
    shm = nsn_shm_attach(arena, resp->shm_name, resp->shm_size);
    if (shm == NULL) {
        fprintf(stderr, "failed to attach to the shared memory segment\n");
        goto exit_error;
    }

    // i64 start_time = nsn_os_get_time_ns();
    // nsn_mm_zone_list_t *zones = (nsn_mm_zone_list_t *)(nsn_shm_rawdata(shm) + sizeof(fixed_mem_arena_t)); // TODO: this is a hack, we should have a proper way to get the zones
    // nsn_mm_zone_t *rx_bufs    = nsn_find_zone_by_name(zones, str_lit("rx_io_buffer_pool"));
    // if (rx_bufs == NULL) {
    //     log_error("failed to find the rx_io_buffer_pool zone\n");
    // } else {
    //     i64 end_time = nsn_os_get_time_ns();
    //     log_info("nsn_find_zone_by_name() took %.2f us\n", (end_time - start_time) / 1000.0);
    //     print_zone(rx_bufs);
    // } 
    
    // nsn_mm_zone_t *tx_bufs = nsn_find_zone_by_name(zones, str_lit("tx_io_buffer_pool"));
    // if (tx_bufs == NULL) {
    //     log_error("failed to find the tx_io_buffer_pool zone\n");
    // } else {
    //     print_zone(tx_bufs);
    // }

    temp_mem_arena_end(temp);
    return 0;

exit_error:
    temp_mem_arena_end(temp);
    mem_arena_release(arena);    

    return -1;
}

// -----------------------------------------------------------------------------
int
nsn_close()
{
    temp_mem_arena_t temp = temp_mem_arena_begin(arena);
    byte *cmsg = mem_arena_push_array(temp.arena, byte, 4096);

    nsn_cmsg_hdr_t *cmsghdr = (nsn_cmsg_hdr_t *)cmsg;
    cmsghdr->type           = NSN_CMSG_TYPE_DISCONNECT;
    cmsghdr->app_id         = app_id;

    sendto(sockfd, cmsg, sizeof(nsn_cmsg_hdr_t), 0, (struct sockaddr *)&nsnd_addr, sizeof(struct sockaddr_un));

    if (recvfrom(sockfd, cmsg, 4096, 0, NULL, NULL) == -1) {
        fprintf(stderr, "failed to disconnect from nsnd with error '%s', is it running?\n", strerror(errno));
    } else {
        if (cmsghdr->type == NSN_CMSG_TYPE_ERROR) {
            int error = *(int *)(cmsg + sizeof(nsn_cmsg_hdr_t));
            fprintf(stderr, "failed to disconnect from nsnd with error '%d'\n", error); 
        } else {
            printf("disconnected from nsnd\n");
        }
    }

    temp_mem_arena_end(temp);

    // close the connection with the daemon
    close(sockfd);
    unlink(nsn_app_addr.sun_path);

    // detach from the shared memory segment shared with the daemon
    nsn_shm_detach(shm);

    // release the memory arena
    mem_arena_release(arena);

    return 0;
}

// -----------------------------------------------------------------------------
nsn_stream_t
nsn_create_stream(nsn_options_t *opts)
{
    nsn_stream_t stream = NSN_INVALID_STREAM_HANDLE;

    if (opts == NULL) {
        // TODO(garbu): set default options
    }

    temp_mem_arena_t temp = temp_mem_arena_begin(arena);
    byte *cmsg = mem_arena_push_array(temp.arena, byte, 4096);

    nsn_cmsg_hdr_t *cmsghdr = (nsn_cmsg_hdr_t *)cmsg;
    cmsghdr->type   = NSN_CMSG_TYPE_CREATE_STREAM;
    cmsghdr->app_id = app_id;

    // TODO(garbu): where do we do the mapping between the request QoS and the technique used?

    sendto(sockfd, cmsg, sizeof(nsn_cmsg_hdr_t), 0, (struct sockaddr *)&nsnd_addr, sizeof(struct sockaddr_un));

    if (recvfrom(sockfd, cmsg, 4096, 0, NULL, NULL) == -1) {
        fprintf(stderr, "failed to create stream with error '%s', is it running?\n", strerror(errno));
    } else {
        if (cmsghdr->type == NSN_CMSG_TYPE_ERROR) {
            int error = *(int *)(cmsg + sizeof(nsn_cmsg_hdr_t));
            fprintf(stderr, "failed to create stream with error '%d'\n", error); 
        } else {
            // // TODO(garbu): get the stream handle from the daemon
            // stream = *(nsn_stream_t *)(cmsg + sizeof(nsn_cmsg_hdr_t));

            stream = 1;
            printf("created stream\n");
        }
    }

    temp_mem_arena_end(temp);

    return stream;
}

// -----------------------------------------------------------------------------
int 
nsn_destroy_stream(nsn_stream_t stream)
{
    if (stream == NSN_INVALID_STREAM_HANDLE) {
        fprintf(stderr, "invalid stream handle\n");
        return -1;
    }

    temp_mem_arena_t temp = temp_mem_arena_begin(arena);
    byte *cmsg = mem_arena_push_array(temp.arena, byte, 4096);

    nsn_cmsg_hdr_t *cmsghdr = (nsn_cmsg_hdr_t *)cmsg;
    cmsghdr->type   = NSN_CMSG_TYPE_DESTROY_STREAM;
    cmsghdr->app_id = app_id;

    sendto(sockfd, cmsg, sizeof(nsn_cmsg_hdr_t), 0, (struct sockaddr *)&nsnd_addr, sizeof(struct sockaddr_un));

    if (recvfrom(sockfd, cmsg, 4096, 0, NULL, NULL) == -1) {
        fprintf(stderr, "failed to destroy stream with error '%s', is it running?\n", strerror(errno));
    } else {
        if (cmsghdr->type == NSN_CMSG_TYPE_ERROR) {
            int error = *(int *)(cmsg + sizeof(nsn_cmsg_hdr_t));
            fprintf(stderr, "failed to destroy stream with error '%d'\n", error); 
        } else {
            printf("destroyed stream\n");
        }
    }

    temp_mem_arena_end(temp);

    return 0;
}