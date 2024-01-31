// --- gax: Includes -----------------------------------------------------------
#include "nsn_memory.h"
#include "nsn_config.h"
#include "nsn_datapath.h"
#include "nsn_ipc.h"
#include "nsn_shm.h"
#include "nsn_string.h"
#include "nsn_types.h"

#define NSN_LOG_IMPLEMENTATION_H
#include "nsn_log.h"

// --- gax: c files ------------------------------------------------------------
#include "nsn_config.c"
#include "nsn_memory.c"
#include "nsn_os_inc.c"
#include "nsn_shm.c"
#include "nsn_string.c"

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

typedef struct nsn_app nsn_app_t;
struct nsn_app
{
    int app_id;
};

typedef struct nsn_app_pool nsn_app_pool_t;
struct nsn_app_pool
{
    mem_arena_t *arena;
    nsn_app_t   *apps;
    bool        *free_apps_slots;
    usize        count;
    usize        used;
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

////////
// insane daemon state

int instance_id     = 0;
bool is_main_thread = false;
// nsn_thread_local nsn_thread_ctx *thread_ctx = NULL;
mem_arena_t *scratch_arena = NULL;
nsn_app_pool_t app_pool = {0};

string_list_t arg_list = {0};
nsn_config_t *config   = NULL;
////////

typedef struct nsn_datapath_memory nsn_datapath_memory_t;
struct nsn_datapath_memory
{
    fixed_mem_arena_t *arena;
    nsn_shm_t         *shm;
};

nsn_datapath_memory_t *
nsn_datapath_memory_create(mem_arena_t *arena, string_t name, usize size)
{
    // TODO(garbu): create a shared memory for the data plane using the config 
    //              to determine the size of the shared memory. 
    //              In the shared memory, we have both the memory buffer and the
    //              ring buffers used for the receive and transmit queues.
    nsn_shm_t *shm = nsn_shm_alloc(arena, to_cstr(name), size);
    if (!shm) {
        log_error("Failed to create shared memeory\n");
        return NULL;
    }

    fixed_mem_arena_t *fixed_arena = fixed_mem_arena_alloc(shm->base, shm->size);

    nsn_datapath_memory_t *mem = mem_arena_push_struct(arena, nsn_datapath_memory_t);
    mem->arena = fixed_arena;
    mem->shm   = shm;

    return mem;
}

void
nsn_datapath_memory_destroy(nsn_datapath_memory_t *mem)
{
    nsn_shm_release(mem->shm);
}

int 
main(int argc, char *argv[])
{
    nsn_unused(argc);
    nsn_unused(argv);

    logger_init(NULL);
    logger_set_level(LOGGER_LEVEL_TRACE);

    instance_id    = nsn_os_get_process_id();
    is_main_thread = true;
    scratch_arena  = mem_arena_alloc(gigabytes(1));

    for (int i = 0; i < argc; i++)
        str8_list_push(scratch_arena, &arg_list, str8_cstr(argv[i]));

    string_t config_filename = str8_lit("nsnd.cfg");
    for (string_node_t *node = arg_list.head; node; node = node->next) {
        if (str8_match(str8_lit("--config"), node->string) || str8_match(str8_lit("-c"), node->string)) {
            if (node->next) {
                config_filename = node->next->string;
            }
        }
    }

    config = nsn_load_config(scratch_arena, config_filename);
    if (!config) {
        log_error("Failed to load config file: %*.s\n", str8_arg(config_filename));
        exit(1);
    }
 
    log_debug("instance id: %d\n", instance_id);

    // init the memory arena
    mem_arena_t *arena = mem_arena_alloc(gigabytes(1));
    app_pool.count           = 64;
    app_pool.apps            = mem_arena_push_array(arena, nsn_app_t, app_pool.count);
    app_pool.free_apps_slots = mem_arena_push_array(arena, bool, app_pool.count);
    for (usize i = 0; i < app_pool.count; i++)    app_pool.free_apps_slots[i] = true;

    // init SIG_INT handler
    struct sigaction sa;
    memory_zero_struct(&sa);
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);


    // create the shared memory
    nsn_datapath_memory_t *mem = nsn_datapath_memory_create(arena, str8_lit("nsnd_datamem"), megabytes(8));
    if (!mem) {
        log_error("Failed to create shared memory\n");
        exit(1);
    }

    // create the control socket
    int sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        log_error("Failed to open socket: %s\n", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, NSNAPP_TO_NSND_IPC, sizeof(addr.sun_path) - 1);

    // bind the socket to the address
    unlink(NSNAPP_TO_NSND_IPC);
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) < 0) {
        log_error("Failed to bind socket: %s\n", strerror(errno));
        return -1;
    }

    // set the socket to non-blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    while (g_running) 
    {
        // send a message to the daemon to create a new instance
        temp_mem_arena_t temp_arena = temp_mem_arena_begin(arena);
    
        usize bufflen = 4096;
        byte *buffer  = mem_arena_push_array(temp_arena.arena, byte, bufflen);
    
        struct sockaddr_un temp_addr;
        socklen_t temp_len = sizeof(struct sockaddr_un);
        isize bytes_recv   = recvfrom(sockfd, buffer, bufflen, 0, (struct sockaddr *)&temp_addr, &temp_len);
        if (bytes_recv == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1);
                goto clean_and_next;
            }
            else {
                // TODO: handle error
                printf("error: %s\n", strerror(errno));
                break;
            }
        }

        bool send_reply         = true;
        usize reply_len         = 0;
        nsn_cmsg_hdr_t *cmsghdr = (nsn_cmsg_hdr_t *)buffer;
        int app_id              = cmsghdr->app_id;
        switch (cmsghdr->type)
        {
            case nsn_cmsg_type_connect:
            {
                // check if there are free slots in the app pool
                int slot = -1;
                for (usize i = 0; i < app_pool.count; i++) {
                    if (app_pool.free_apps_slots[i]) {
                        slot = i;                
                        break;
                    }
                        
                }

                if (slot == -1) {
                    cmsghdr->type   = nsn_cmsg_type_error;
                    int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                    *error_code     = 1;
                    reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int); 
                } else {                    
                    log_debug("app %d connected\n", app_id);
                    app_pool.used                  += 1;
                    app_pool.free_apps_slots[slot]  = false;
                    app_pool.apps[slot].app_id      = app_id;                    
                    nsn_cmsg_connect_t *reply = (nsn_cmsg_connect_t *)(buffer + sizeof(nsn_cmsg_hdr_t));
                    snprintf(reply->shm_name, NSN_MAX_PATH_SIZE, "nsnd_datamem");
                    cmsghdr->type = nsn_cmsg_type_connected;
                    reply_len     = sizeof(nsn_cmsg_hdr_t) + sizeof(nsn_cmsg_connect_t);
                }
            } break;        
            case nsn_cmsg_type_disconnect:
            {
                log_debug("received disconnect message from app %d\n", app_id);

                // check if the app is in the pool
                bool found = false;
                for (usize i = 0; i < app_pool.count; i++) {
                    if (app_pool.apps[i].app_id == app_id) {
                        log_trace("found app %d in slot %d\n", app_id, i);
                        app_pool.free_apps_slots[i]  = true;
                        app_pool.used               -= 1;
                        found                        = true;
                        break;
                    }
                }

                if (!found) {
                    cmsghdr->type   = nsn_cmsg_type_error;
                    int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                    *error_code     = 2;
                    reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
                } else {
                    log_debug("app %d disconnected\n", app_id);
                    cmsghdr->type = nsn_cmsg_type_disconnected;
                    reply_len     = sizeof(nsn_cmsg_hdr_t);
                }

            } break;
            default:
            {
                printf("unknown message from '%d' type: %d\n", app_id, cmsghdr->type);
                send_reply = false;
            } break;
        }

        if (send_reply) { 
            sendto(sockfd, cmsghdr, reply_len, 0, (struct sockaddr *)&temp_addr, temp_len);        
        }
clean_and_next: 
        temp_mem_arena_end(temp_arena);
    }

    // struct nsn_os_module module = nsn_os_load_library("./datapaths/libdpdk.so", 0);
    // if (module.handle == NULL) {
    //     log_error("Failed to load library: %s\n", strerror(errno));
    //     // return -1;
    // }

    // // TODO: dpdk example, in the final code the string "dpdk" should be replaced by the name of the datapath
    // // and has to be done in a parameterized way. 
    // struct datapath_ops ops = {
    //     .init   = (nsn_datapath_init*)  nsn_os_get_proc_address(module, "dpdk_datapath_init"),
    //     .tx     = (nsn_datapath_tx*)    nsn_os_get_proc_address(module, "dpdk_datapath_tx"),
    //     .deinit = (nsn_datapath_deinit*)nsn_os_get_proc_address(module, "dpdk_datapath_deinit"),
    // };

    // void *rawdata = nsn_shm_rawdata(shm);
    // log_debug("%p == %p", (void*)shm->base, rawdata);

    // struct nsn_datapath_ctx ctx = {
    //     .running          = 1,
    //     .data_memory      = rawdata,
    //     .data_memory_size = nsn_shm_size(shm),
    // };

    // log_debug("init: %d\n", ops.init(&ctx));
    // log_debug("tx: %d\n", ops.tx(NULL));

    // log_debug("deinit: %d\n", ops.deinit(NULL));
    // nsn_os_unload_library(module);

    // cleanup
    close(sockfd);
    unlink(NSNAPP_TO_NSND_IPC);
    nsn_shm_release(mem->shm);
    mem_arena_release(scratch_arena);
    mem_arena_release(arena);

    log_debug("done\n");

    return 0;
}
