#include "nsn.h"

#include "nsn_types.h"
#include "nsn_arena.h"
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

int 
nsn_init()
{
    struct nsn_arena *arena = nsn_arena_alloc_default();
    // open a connection with the insance of the nsn daemon
    int sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return -1;
    }

    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, REQUEST_IPC_PATH, sizeof(addr.sun_path) - 1);

    // send a message to the daemon to create a new instance
    struct nsn_temp_arena temp = nsn_temp_arena_begin(arena);
    byte *msg = nsn_arena_push_array(temp.arena, byte, 1024);

    struct nsn_request *req = (struct nsn_request *)msg;
    req->type = nsn_msg_type_connect;
    req->id   = nsn_os_get_process_id();

    sendto(sockfd, msg, sizeof(struct nsn_request), 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));
    nsn_temp_arena_end(temp);

    // wait for the daemon to respond with the instance id
    // return ok or error

    nsn_arena_release(arena);
    return 0;
}