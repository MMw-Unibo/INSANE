#include "nsn.h"

#include "nsn_types.h"
#include "nsn_memory.h"
#include "nsn_ipc.h"

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
int sockfd = -1;
struct sockaddr_un nsn_app_addr;
struct sockaddr_un nsnd_addr;

int 
nsn_init()
{
    arena = mem_arena_alloc_default();
    // open a connection with the insance of the nsn daemon
    sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return -1;
    }

    nsn_app_addr.sun_family = AF_UNIX;
    
    int pid = nsn_os_get_process_id();
    // printf("application pid: %d\n", pid);

    char name[IPC_MAX_PATH_SIZE];
    snprintf(name, IPC_MAX_PATH_SIZE, "%s%d", NSND_TO_NSNAPP_IPC, pid);

    if (bind(sockfd, (struct sockaddr *)&nsn_app_addr, sizeof(struct sockaddr_un)) < 0) {
        return -1;
    }

    // set a timeout for the socket
    struct timeval tv;
    tv.tv_sec  = 0;
    tv.tv_usec = 1000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    // send a message to the daemon to create a new instance
    temp_mem_arena_t temp = temp_mem_arena_begin(arena);
    byte *cmsg = mem_arena_push_array(temp.arena, byte, 4096);

    nsn_cmsg_hdr_t *cmsghdr = (nsn_cmsg_hdr_t *)cmsg;
    cmsghdr->type   = nsn_cmsg_type_connect;
    cmsghdr->app_id = pid;

    nsnd_addr.sun_family = AF_UNIX;
    strncpy(nsnd_addr.sun_path, NSNAPP_TO_NSND_IPC, sizeof(nsnd_addr.sun_path) - 1);

    sendto(sockfd, cmsg, sizeof(nsn_cmsg_hdr_t), 0, (struct sockaddr *)&nsnd_addr, sizeof(struct sockaddr_un));
    
    if (recvfrom(sockfd, cmsg, 4096, 0, NULL, NULL) == -1) {
        fprintf(stderr, "failed to connect to nsnd with error '%s', is it running?\n", strerror(errno));
        goto exit_error;
    }

    if (cmsghdr->type == nsn_cmsg_type_error) {
        int error = *(int *)(cmsg + sizeof(nsn_cmsg_hdr_t));
        fprintf(stderr, "failed to connect to nsnd with error '%d'\n", error); 
        goto exit_error;
    }

    nsn_cmsg_connect_t *resp = (nsn_cmsg_connect_t *)(cmsg + sizeof(nsn_cmsg_hdr_t));

    printf("connected to nsnd, the shm is at /dev/shm/%s\n", resp->shm_name);

    temp_mem_arena_end(temp);

    return 0;

exit_error:
    mem_arena_release(arena);    

    return -1;
}

void
nsn_deinit()
{
    temp_mem_arena_t temp = temp_mem_arena_begin(arena);
    byte *cmsg = mem_arena_push_array(temp.arena, byte, 4096);

    nsn_cmsg_hdr_t *cmsghdr = (nsn_cmsg_hdr_t *)cmsg;
    cmsghdr->type   = nsn_cmsg_type_disconnect;
    cmsghdr->app_id = nsn_os_get_process_id();

    sendto(sockfd, cmsg, sizeof(nsn_cmsg_hdr_t), 0, (struct sockaddr *)&nsnd_addr, sizeof(struct sockaddr_un));

    if (recvfrom(sockfd, cmsg, 4096, 0, NULL, NULL) == -1) {
        fprintf(stderr, "failed to disconnect from nsnd with error '%s', is it running?\n", strerror(errno));
    } else {
        if (cmsghdr->type == nsn_cmsg_type_error) {
            int error = *(int *)(cmsg + sizeof(nsn_cmsg_hdr_t));
            fprintf(stderr, "failed to disconnect from nsnd with error '%d'\n", error); 
        } else {
            printf("disconnected from nsnd\n");
        }
    }

    temp_mem_arena_end(temp);

    close(sockfd);
    unlink(nsn_app_addr.sun_path);
    mem_arena_release(arena);
}