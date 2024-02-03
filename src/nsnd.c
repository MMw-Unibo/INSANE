// --- gax: Includes -----------------------------------------------------------
#include "nsn_memory.h"
#include "nsn_config.h"
#include "nsn_datapath.h"
#include "nsn_ipc.h"
#include "nsn_ringbuf.h"
#include "nsn_shm.h"
#include "nsn_string.h"
#include "nsn_thread_ctx.h"
#include "nsn_types.h"
#include "nsn_zone.h"

#define NSN_LOG_IMPLEMENTATION_H
#include "nsn_log.h"

// --- gax: c files ------------------------------------------------------------
#include "nsn_config.c"
#include "nsn_memory.c"
#include "nsn_os_inc.c"
#include "nsn_ringbuf.c"
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
mem_arena_t *scratch_arena = NULL;
nsn_app_pool_t app_pool = {0};

string_list_t arg_list = {0};
nsn_cfg_t *config   = NULL;
////////

// --- Memory Manager --------------------------------------------------

typedef struct nsn_mem_manager_cfg nsn_mem_manager_cfg_t;
struct nsn_mem_manager_cfg
{
    string_t     shm_name;
    usize        shm_size;
    usize        io_buffer_pool_size;
    usize        io_buffer_size;
};

// --- Memory Manager ---------------------------------------------------------
//  The memory manager is responsible for creating and managing the shared memory.
//  It uses a Page Allocator to allocate memory from the shared memory.
//  In particular, the manged memory is used to store:
//   - The io buffer pools: used to store the packets received and transmitted 
//     from and to the data plane and the applications
//   - The ring buffers: use to exchange the pointers to the io buffers between 
//     the data plane and the applications
typedef struct nsn_mem_manager nsn_mem_manager_t;
struct nsn_mem_manager
{
    nsn_shm_t           *shm;
    fixed_mem_arena_t   *shm_arena;
    // The list of zones is the first block of the shared memory
    nsn_mm_zone_list_t  *zones;
};

nsn_mm_zone_t *nsn_memory_manager_create_zone(nsn_mem_manager_t *mem, string_t name, usize size, usize type);

nsn_mem_manager_t *
nsn_memory_manager_create(mem_arena_t *arena, nsn_mem_manager_cfg_t *cfg)
{
    // TODO(garbu): create a shared memory for the data plane using the config 
    //              to determine the size of the shared memory. 
    //              In the shared memory, we have both the memory buffer and the
    //              ring buffers used for the receive and transmit queues.
    nsn_shm_t *shm = nsn_shm_alloc(arena, to_cstr(cfg->shm_name), cfg->shm_size);
    if (!shm) {
        log_error("Failed to create shared memeory\n");
        return NULL;
    }

    // Create the memory manager
    nsn_mem_manager_t *mem = mem_arena_push_struct(arena, nsn_mem_manager_t);
    mem->shm       = shm;
    mem->shm_arena = fixed_mem_arena_alloc(nsn_shm_rawdata(shm), nsn_shm_size(shm));
    mem->zones     = fixed_mem_arena_push_struct(mem->shm_arena, nsn_mm_zone_list_t);
    
    // The data in the shared memory will be allocated using a list of zones
    // each zone will have a header with the size of the zone, the name of the zone, the type of the zone, 
    // the pointer to the next zone, the pointer to the previous zone, and the pointer to the first block of the zone.

    usize io_buf_pool_size = cfg->io_buffer_pool_size * cfg->io_buffer_size;
    nsn_memory_manager_create_zone(mem, str_lit("rx_io_buffer_pool"), io_buf_pool_size, NSN_MM_ZONE_TYPE_IO_BUFFER_POOL);
    nsn_memory_manager_create_zone(mem, str_lit("tx_io_buffer_pool"), io_buf_pool_size, NSN_MM_ZONE_TYPE_IO_BUFFER_POOL);

    return mem;
}

void
nsn_memory_manager_destroy(nsn_mem_manager_t *mem)
{
    at_fadd(&mem->shm->ref_count, -1, mo_rlx);
    nsn_shm_release(mem->shm);
}

// The zone is created in the shared memory and the pointer to the zone is returned.
// The shared memory works as a linear memory, so the zone is created at the end of the memory, after the last zone.
// Zone are rounded to the next multiple of the page size.
nsn_mm_zone_t *
nsn_memory_manager_create_zone(nsn_mem_manager_t *mem, string_t name, usize size, usize type)
{
    if (nsn_zone_exists(mem->zones, name)) {
        log_warn("zone with name " str_fmt " already exists\n", str_varg(name));
        return NULL; 
    }

    // round the size to the next multiple of the page size
    usize page_size = 4096; // TODO: get the page size from the system
    usize zone_size = align_to(size + sizeof(nsn_mm_zone_t), page_size);

    // create the zone in the shared memory
    usize base_offset = mem->shm_arena->pos;
    nsn_mm_zone_t *zone = fixed_mem_arena_push_struct(mem->shm_arena, nsn_mm_zone_t);
    if (!zone) {
        return NULL;
    }

    // initialize the zone

    zone->base_offset        = base_offset;
    zone->total_size         = zone_size;
    zone->size               = zone->total_size - sizeof(nsn_mm_zone_t);
    zone->type               = type;
    zone->first_block_offset = base_offset + sizeof(nsn_mm_zone_t);
    strncpy(zone->name, to_cstr(name), 63);

    // add the zone to the list of zones
    nsn_zone_list_add_tail(mem->zones, zone);

    return zone;
}

// --- Main -------------------------------------------------------------------

int 
main_thread_control_ipc(int sockfd, nsn_mem_manager_cfg_t mem_cfg)
{
    // send a message to the daemon to create a new instance
    int res = 0;
    temp_mem_arena_t temp_arena = nsn_thread_scratch_begin(NULL, 0);

    usize bufflen = 4096;
    byte *buffer  = mem_arena_push_array(temp_arena.arena, byte, bufflen);

    struct sockaddr_un temp_addr;
    socklen_t temp_len = sizeof(struct sockaddr_un);
    isize bytes_recv   = recvfrom(sockfd, buffer, bufflen, 0, (struct sockaddr *)&temp_addr, &temp_len);
    if (bytes_recv == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            goto clean_and_next;
        }
        else {
            // TODO: handle error
            printf("error: %s\n", strerror(errno));
            res = -1;
            goto clean_and_next;
        }
    }

    bool send_reply         = true;
    usize reply_len         = 0;
    nsn_cmsg_hdr_t *cmsghdr = (nsn_cmsg_hdr_t *)buffer;
    int app_id              = cmsghdr->app_id;
    switch (cmsghdr->type)
    {
        case NSN_CMSG_TYPE_CONNECT:
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
                cmsghdr->type   = NSN_CMSG_TYPE_ERROR;
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
                reply->shm_size = mem_cfg.shm_size;
                cmsghdr->type = NSN_CMSG_TYPE_CONNECTED;
                reply_len     = sizeof(nsn_cmsg_hdr_t) + sizeof(nsn_cmsg_connect_t);
            }
        } break;        
        case NSN_CMSG_TYPE_CREATE_STREAM:
        {
            log_debug("received new stream message from app %d\n", app_id);
        } break;
        case NSN_CMSG_TYPE_DESTROY_STREAM:
        {
            log_debug("received destroy stream message from app %d\n", app_id);
        } break;
        case NSN_CMSG_TYPE_DISCONNECT:
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
                cmsghdr->type   = NSN_CMSG_TYPE_ERROR;
                int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                *error_code     = 2;
                reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
            } else {
                log_debug("app %d disconnected\n", app_id);
                cmsghdr->type = NSN_CMSG_TYPE_DISCONNECTED;
                reply_len     = sizeof(nsn_cmsg_hdr_t);
            }

        } break;
        default:
        {
            printf("unknown message from '%d' type: %d\n", app_id, cmsghdr->type);
            send_reply = false;
        } break;
    }

    if (send_reply)
        sendto(sockfd, cmsghdr, reply_len, 0, (struct sockaddr *)&temp_addr, temp_len);        

clean_and_next: 
    nsn_thread_scratch_end(temp_arena);

    return res;
}

int 
main(int argc, char *argv[])
{
    nsn_unused(argc);
    nsn_unused(argv);

    nsn_thread_ctx_t main_thread = nsn_thread_ctx_alloc();
    main_thread.is_main_thread   = true;
    nsn_thread_set_ctx(&main_thread);

    logger_init(NULL);
    logger_set_level(LOGGER_LEVEL_TRACE);

    log_info("sizeof nsn_ringbuffer_t: %zu\n", sizeof(nsn_ringbuf_t));

    instance_id    = nsn_os_get_process_id();
    scratch_arena  = mem_arena_alloc(gigabytes(1));

    for (int i = 0; i < argc; i++)
        str_list_push(scratch_arena, &arg_list, str_cstr(argv[i]));

    string_t config_filename = str_lit("nsnd.cfg");
    for (string_node_t *node = arg_list.head; node; node = node->next) {
        if (str_eq(str_lit("--config"), node->string) || str_eq(str_lit("-c"), node->string)) {
            if (node->next) {
                config_filename = node->next->string;
            }
        }
    }

    config = nsn_load_config(scratch_arena, config_filename);
    if (!config) {
        log_error("Failed to load config file: " str_fmt "\n", str_varg(config_filename));
        exit(1);
    }
 
    log_debug("instance id: %d\n", instance_id);

    int app_num      = 64;
    int io_bufs_num  = 0;
    int io_bufs_size = 1024;   
    int shm_size     = 64; // in MB
    
    nsn_config_get_int(config, str_lit("global"), str_lit("app_num"), &app_num);      
    nsn_config_get_int(config, str_lit("global"), str_lit("io_bufs_num"), &io_bufs_num);
    nsn_config_get_int(config, str_lit("global"), str_lit("io_bufs_size"), &io_bufs_size);
    nsn_config_get_int(config, str_lit("global"), str_lit("shm_size"), &shm_size);

    // init the memory arena
    mem_arena_t *arena = mem_arena_alloc(gigabytes(1));
    app_pool.count           = app_num;
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
    nsn_mem_manager_cfg_t mem_cfg = {
        .shm_name            = str_lit("nsnd_datamem"),
        .shm_size            = megabytes(shm_size),
        .io_buffer_pool_size = io_bufs_num,
        .io_buffer_size      = io_bufs_size,
    };
    nsn_mem_manager_t *mem = nsn_memory_manager_create(arena, &mem_cfg);
    if (!mem) {
        log_error("Failed to create shared memory\n");
        goto quit;
    }

    // create the control socket
    int sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        log_error("Failed to open socket: %s\n", strerror(errno));
        goto clear_and_quit;
    }

    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, NSNAPP_TO_NSND_IPC, sizeof(addr.sun_path) - 1);

    // bind the socket to the address
    unlink(NSNAPP_TO_NSND_IPC);
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) < 0) {
        log_error("Failed to bind socket: %s\n", strerror(errno));
        goto clear_and_quit;
    }

    // set the socket to non-blocking
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    while (g_running) 
    {
        if (main_thread_control_ipc(sockfd, mem_cfg) < 0)
            log_warn("Failed to handle control ipc\n");

        usleep(1);
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
clear_and_quit:
    if (sockfd != -1) close(sockfd);
    unlink(NSNAPP_TO_NSND_IPC);
    nsn_memory_manager_destroy(mem);
quit:
    mem_arena_release(scratch_arena);
    mem_arena_release(arena);

    log_debug("done\n");

    return 0;
}
