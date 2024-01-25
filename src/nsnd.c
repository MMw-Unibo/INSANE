// --- gax: Includes -----------------------------------------------------------
#include "nsn_types.h"
#include "nsn_arena.h"
#include "nsn_ipc.h"
#include "nsn_datapath.h"
#include "nsn_shm.h"

#define NSN_LOG_IMPLEMENTATION_H
#include "nsn_log.h"

// --- gax: c files ------------------------------------------------------------
#include "nsn_arena.c"
#include "nsn_shm.c"

#if defined(__linux__)
# include "nsn_os_linux.c"
#else
# error "Unsupported platform"
#endif

// #include "nsn_thread_pool.c"

/**
 * TODOs:
 *  - Each application that connects to the daemon should have a unique id.
 *  - Each application can create one or more stream, each stream should have a unique id.
 *  - Each stream have a single tx queue that is associated to a specific packet scheduler,
 *    e.g, a FIFO scheduler, a priority scheduler, a weighted fair queue scheduler, etc.
 *  - Each application can create one or more source and sink for each stream.
 *      - A source is associated to a specific tx queue, but because each stream have a single tx queue,
 *        no matter how many source are created, they will all be associated to the same tx queue.
 *      - A sink is associated to a specific rx queue, so each time a sink is created, a rx queue is created.
 *  - When the daemon is created it allocates a pool of rx queues and a number of tx queues equal to the number of schedulers.
 *  - Also when the daemon is created it allocates a pool of applications and a pool of threads.
 *  - Each thread in the pool can be used by one of the data plane tasks, e.g, DPDK, RDMA, etc.
 * 
 *  - In the receive path, the daemon should be able to receive packets from the data plane and forward them to the application.
 *    Because the application can retain the packet for a long time, the daemon should have a pool of receive buffers.
 */

// #include <rte_eal.h>

// static void 
// dpdk(void)
// {
//     char *rte_argv[] = {
//         "nsnd",
//         "-c 0x1",
//         "-n 4",
//         "--proc-type=auto",
//     };

//     size_t rte_argc = array_count(rte_argv);

//     int ret = rte_eal_init(rte_argc, rte_argv);

//     printf("hello %d\n", ret);

//     sleep(2);

//     printf("cleanup\n");

//     rte_eal_cleanup();
// }

struct nsn_app
{
    int id;
    int pid;

    void *rx_queue_slot;
};

struct nsn_app_node
{
    struct nsn_app *app;
    struct nsn_app_node *next;
};

struct nsn_app_pool
{
    struct nsn_arena *arena;

    struct nsn_app_node *head;
    
};

static volatile bool g_running = true;

void 
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        g_running = false;
    }
}

struct datapath_ops
{
    nsn_datapath_init *init;
    nsn_datapath_tx *tx;
    nsn_datapath_deinit *deinit;
};

int 
main(int argc, char *argv[])
{
    nsn_unused(argc);
    nsn_unused(argv);

    logger_init(NULL);
    logger_set_level(LOGGER_LEVEL_DEBUG);

    // init SIG_INT handler
    struct sigaction sa;
    memory_zero_struct(&sa);
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    struct nsn_arena *arena = nsn_arena_alloc(gigabytes(1));

    int sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        log_error("Failed to open socket: %s\n", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, REQUEST_IPC_PATH, sizeof(addr.sun_path) - 1);

    // bind the socket to the address
    unlink(REQUEST_IPC_PATH);
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) < 0) {
        log_error("Failed to bind socket: %s\n", strerror(errno));
        return -1;
    }

    // set the socket to non-blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    // while (g_running) 
    // {
    //     printf("waiting for a message\n");

    //     // send a message to the daemon to create a new instance
    //     struct nsn_temp_arena temp = nsn_temp_arena_begin(arena);
    
    //     byte *msg = nsn_arena_push_array(temp.arena, byte, 1024);
    //     socklen_t len = sizeof(struct sockaddr_un);
    
    //     isize bytes_recv = recvfrom(sockfd, msg, 1024, 0, (struct sockaddr *)&addr, &len);
    //     if (bytes_recv == -1) {
    //         if (errno == EAGAIN || errno == EWOULDBLOCK) {
    //             usleep(1000 * 1000);
    //             continue;
    //         }
    //         else {
    //             // TODO: handle error
    //             printf("error: %s\n", strerror(errno));
    //             break;
    //         }
    //     }

    //     struct nsn_request *req = (struct nsn_request *)msg;
    //     printf("type: %d, id: %d\n", req->type, req->id);
    //     nsn_temp_arena_end(temp);

    // }

    struct nsn_shm *shm = nsn_shm_alloc("nsn_datamem", kilobytes(4) * 1024);
    if (!shm) {
        log_error("Failed to create shared memeory\n");
        exit(1);
    }

    struct nsn_os_module module = nsn_os_load_library("./datapaths/libdpdk.so", 0);
    if (module.handle == NULL) {
        log_error("Failed to load library: %s\n", strerror(errno));
        // return -1;
    }

    // TODO: dpdk example, in the final code the string "dpdk" should be replaced by the name of the datapath
    // and has to be done in a parameterized way. 
    struct datapath_ops ops = {
        .init   = nsn_os_get_proc_address(module, "dpdk_datapath_init"),
        .tx     = nsn_os_get_proc_address(module, "dpdk_datapath_tx"),
        .deinit = nsn_os_get_proc_address(module, "dpdk_datapath_deinit"),
    };

    void *rawdata = nsn_shm_rawdata(shm);
    log_debug("%p == %p", (void*)shm->base, rawdata);

    struct nsn_datapath_ctx ctx = {
        .running          = 1,
        .data_memory      = rawdata,
        .data_memory_size = nsn_shm_size(shm),
    };

    log_debug("init: %d\n", ops.init(&ctx));
    log_debug("tx: %d\n", ops.tx(NULL));

    sleep(1);
    printf("simulating work\n");
    sleep(1);
    log_debug("deinit: %d\n", ops.deinit(NULL));

    nsn_os_unload_library(module);

    // cleanup
    close(sockfd);
    unlink(REQUEST_IPC_PATH);
    nsn_shm_release(shm);
    nsn_arena_release(arena);

    log_debug("done\n");

    return 0;
}
