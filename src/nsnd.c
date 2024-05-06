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

// --- gax: deps ---------------------------------------------------------------

#define NSN_DEFAULT_CONFIG_FILE     "nsnd.cfg"

#define NSN_CFG_DEFAULT_SECTION                 "global"
#define NSN_CFG_DEFAULT_SHM_NAME                "nsnd_datamem"
#define NSN_CFG_DEFAULT_IO_BUFS_NUM             1024
#define NSN_CFG_DEFAULT_IO_BUFS_SIZE            2048
#define NSN_CFG_DEFAULT_SHM_SIZE                64      // in MB
#define NSN_CFG_DEFAULT_TX_IO_BUFS_NAME         "tx_io_buffer_pool"
#define NSN_CFG_DEFAULT_RX_IO_BUFS_NAME         "rx_io_buffer_pool"
#define NSN_CFG_DEFAULT_RINGS_ZONE_NAME         "rings_zone"
#define NSN_CFG_DEFAULT_TX_RING_CONS_NAME       "tx_ring_cons"
#define NSN_CFG_DEFAULT_TX_RING_PROD_NAME       "tx_ring_prod"

static i64 cpu_hz = -1;

// #include "nsn_thread_pool.c"

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

bool 
app_pool_try_alloc_slot(nsn_app_pool_t *pool, int app_id)
{
    for (usize i = 0; i < pool->count; i++) {
        if (pool->free_apps_slots[i]) {
            pool->free_apps_slots[i]  = false;
            pool->apps[i].app_id      = app_id;
            pool->used               += 1;
            return true;
        }
    }
    return false;
}


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
    nsn_datapath_init       *init;
    nsn_datapath_tx         *tx;
    nsn_datapath_rx         *rx;
    nsn_datapath_deinit     *deinit;
};

////////
// insane daemon state

int instance_id          = 0;
mem_arena_t *state_arena = NULL;
nsn_app_pool_t app_pool  = {0};

string_list_t arg_list = {0};
nsn_cfg_t *config      = NULL;
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


typedef struct nsn_ringbuf_pool nsn_ringbuf_pool_t;
struct nsn_ringbuf_pool
{
    nsn_mm_zone_t *zone;
    char           name[32];            // the name of the pool
    usize          count;               // the number of ring buffers in the pool
    usize          esize;               // the size of the elements in the ring buffer
    usize          ecount;              // the number of elements in the ring buffer    
    usize         *free_slots;          // if free_slots[i] == 0, then the slot is free
    usize          free_slots_count;
} nsn_cache_aligned;

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

nsn_ringbuf_pool_t *
nsn_ringbuf_pool_create(nsn_mem_manager_t *mem, string_t name, usize count, usize esize, usize ecount)
{
    usize zone_size = sizeof(nsn_ringbuf_pool_t)           // the size of the pool header
                    + (count * sizeof(usize))              // the size of the free slots
                    + sizeof(nsn_ringbuf_t) * count        // the size of the ring buffers
                    + (esize * ecount) * count;            // the size of the elements in the ring buffers

    nsn_mm_zone_t *zone = nsn_memory_manager_create_zone(mem, name, zone_size, NSN_MM_ZONE_TYPE_RINGS);
    if (!zone) {
        log_error("Failed to create zone for ring buffer pool\n");
        return NULL;
    }

    nsn_ringbuf_pool_t *pool = (nsn_ringbuf_pool_t *)nsn_mm_zone_get_ptr(mem->shm_arena->base, zone);
    pool->zone             = zone;
    pool->count            = count;
    pool->esize            = esize;
    pool->ecount           = ecount;
    pool->free_slots       = (usize *)(pool + 1);
    pool->free_slots_count = count;
    strncpy(pool->name, to_cstr(name), sizeof(pool->name) - 1);

    return pool;
}

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
    nsn_memory_manager_create_zone(mem, str_lit(NSN_CFG_DEFAULT_TX_IO_BUFS_NAME), io_buf_pool_size, NSN_MM_ZONE_TYPE_IO_BUFFER_POOL);
    nsn_memory_manager_create_zone(mem, str_lit(NSN_CFG_DEFAULT_RX_IO_BUFS_NAME), io_buf_pool_size, NSN_MM_ZONE_TYPE_IO_BUFFER_POOL);

    // Create a pool of ring buffers inside the ring zone
    nsn_ringbuf_pool_create(mem, str_lit("rings_zone"), 16, sizeof(usize), cfg->io_buffer_pool_size);

    // Create the two tx ring buffers, one for the consumer(s) (applications) and one for the producer (the daemon)
    //  - The applications are consumers because they ask for a pointer to the io buffer to fill with data
    //  - The daemon is the producer because it provides the pointers to free io buffers


    // Fill the ring buffer with the pointers to the io buffers, the pointers are actually the offset from the start of the zone
    // u64 table[16];
    // for (usize i = 0; i < nsn_ringbuf_get_size(mem->tx_ring); i++) {
    //     table[0] = i;
    //     nsn_ringbuf_enqueue_burst(mem->tx_ring, &table, sizeof(u64), 1, NULL);
    // } 

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
    usize base_offset   = mem->shm_arena->pos;
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
    strncpy(zone->name, to_cstr(name), sizeof(zone->name) - 1);

    // add the zone to the list of zones
    nsn_zone_list_add_tail(mem->zones, zone);

    return zone;
}

// --- Data Plane Thread -------------------------------------------------------

enum nsn_dataplane_thread_state
{
    NSN_DATAPLANE_THREAD_STATE_WAIT,
    NSN_DATAPLANE_THREAD_STATE_RUNNING,
    NSN_DATAPLANE_THREAD_STATE_STOP,
};

const char *nsn_dataplane_thread_state_str[] = {
    "WAIT",
    "RUNNING",
    "STOP",
};

struct nsn_dataplane_thread_args
{
    nsn_mem_manager_t *mm;
    atu32              state;
    string_t           datapath_name;
};

void *
dataplane_thread_proc(void *arg)
{
    struct nsn_dataplane_thread_args *args = (struct nsn_dataplane_thread_args *)arg;
    nsn_mem_manager_t *mem = args->mm;
    nsn_unused(mem);

    nsn_thread_ctx_t this_thread = nsn_thread_ctx_alloc();
    this_thread.is_main_thread   = false;
    nsn_thread_set_ctx(&this_thread);

    int self = nsn_os_current_thread_id();
    u32 state;

wait: 
    log_debug("[thread %d] waiting for a message\n", self);
    while ((state = at_load(&args->state, mo_rlx)) == NSN_DATAPLANE_THREAD_STATE_WAIT) {
        usleep(10);
    } 

    if (state == NSN_DATAPLANE_THREAD_STATE_STOP) {
        log_debug("[thread %d] stopping\n", self);
        return NULL;
    }

    // Load the datapath plugin
    string_t datapath_name = args->datapath_name;
    log_debug("[thread %d] dataplane thread started for datapath: " str_fmt "\n", self, str_varg(datapath_name));                 
    char datapath_lib[256];
    snprintf(datapath_lib, sizeof(datapath_lib), "./datapaths/lib%s.so", to_cstr(datapath_name));
    struct nsn_os_module module = nsn_os_load_library(datapath_lib, NsnOsLibraryFlag_Now);
    if (module.handle == NULL) {
        log_error("[thread %d] Failed to load library: %s\n", self, datapath_lib);
        goto quit;
    }

    char fn_name[256];

    struct datapath_ops ops;
    memory_zero_struct(&ops);
    snprintf(fn_name, sizeof(fn_name), "%s_datapath_init", to_cstr(datapath_name));
    ops.init   = (nsn_datapath_init*)nsn_os_get_proc_address(module, fn_name);
    snprintf(fn_name, sizeof(fn_name), "%s_datapath_tx", to_cstr(datapath_name));
    ops.tx     = (nsn_datapath_tx*)nsn_os_get_proc_address(module, fn_name);
    snprintf(fn_name, sizeof(fn_name), "%s_datapath_rx", to_cstr(datapath_name));
    ops.rx     = (nsn_datapath_rx*)nsn_os_get_proc_address(module, fn_name);
    snprintf(fn_name, sizeof(fn_name), "%s_datapath_deinit", to_cstr(datapath_name));
    ops.deinit = (nsn_datapath_deinit*)nsn_os_get_proc_address(module, fn_name);

    nsn_datapath_ctx_t ctx;
    memory_zero_struct(&ctx);
 
    string_t socket_ip;
    int socket_port;
    nsn_config_get_string(config, str_lit("global"), str_lit("socket_ip"), &socket_ip);
    nsn_config_get_int(config, str_lit("global"), str_lit("socket_port"), &socket_port);
    snprintf(ctx.configs, sizeof(ctx.configs) - 1, "%.*s:%d", (int)socket_ip.len, to_cstr(socket_ip), socket_port);

    ops.init(&ctx);

    while ((state = at_load(&args->state, mo_rlx)) == NSN_DATAPLANE_THREAD_STATE_RUNNING) {
        // TODO: dpdk example, in the final code the string "dpdk" should be replaced by the name of the datapath
        // and has to be done in a parameterized way. 

        // TODO: check if there are io buffers that can be freed
        //  - in order to be freed, an io buffer must not be referenced by any ring buffer
        //  - how do we know if an io buffer is referenced by a ring buffer?

        // TODO: get an array of pointers to the io buffers that can be used to store the received packets
        // ops.rx(&ctx);

        nsn_buf_t io_buffs[] = {
            { .data = "hello\n", .size = 6 },
            { .data = "world\n", .size = 6 },
        };
        int tx_count = ops.tx(io_buffs, array_count(io_buffs));
        if (tx_count < 0) {
            log_error("[thread %d] Failed to transmit\n", self);
        } 

        // check if there are local sinks that need to be notified
        //  - the local sinks are the applications that are connected to the daemon

        // for_each_io_buffer(io_buff) {
        //     bool is_free = true;
        //     for_each_local_sink(sink) {
        //         if (io_buff.source_id == sink->source_id) {
        //             nsn_ringbuf_enqueue_burst(sink->rx_ring, io_buff);
        //             is_free = false;
        //         }
        //     }
        

        //     if (is_free) {
        //         io_buff_free(io_buff);
        //     }
        // }
    }

    log_debug("[thread %d] deinit\n", self);
    if (ops.deinit(NULL)) {
        log_error("[thread %d] Failed to deinit\n", self);
    }

    log_debug("[thread %d] unloading library\n", self);
    nsn_os_unload_library(module);

    state = at_load(&args->state, mo_rlx);
    log_debug("[thread %d] state: %s (%d)\n", self, nsn_dataplane_thread_state_str[state], state);

    if (state == NSN_DATAPLANE_THREAD_STATE_WAIT)
    {
        log_debug("[thread %d] moving to wait state\n", self);
        goto wait;
    }

quit:
    log_info("[thread %d] done\n", self);
    return NULL;
}

// --- Test Application Thread --------------------------------------------------

typedef struct test_app_thread_args test_app_thread_args_t;
struct test_app_thread_args
{
    nsn_mem_manager_t *mm;
};

void *
test_app_thread_proc(void *arg)
{
    test_app_thread_args_t *args = (test_app_thread_args_t *)arg;
    nsn_mem_manager_t *mem = args->mm;
    nsn_unused(mem);

    log_info("thread [test app] started\n");

    i64 cycles_start = nsn_os_get_cycles();
    // for (usize i = 0; i < 100; i++) {
    //     u64 table[16];
    //     nsn_ringbuf_dequeue_burst(mem->tx_ring, table, sizeof(u64), 1, NULL);
    // }
    i64 cycles_end = nsn_os_get_cycles();
    f64 elapsed_ns = (cycles_end - cycles_start) / (f64)(cpu_hz / 1000000000.0);
    log_info("nsn_ringbuf_dequeue_burst() took %f ns (%ld cycles)\n", elapsed_ns / 100, cycles_end - cycles_start);

    return NULL;
}

// --- Main -------------------------------------------------------------------

int 
main_thread_control_ipc(int sockfd, nsn_mem_manager_cfg_t mem_cfg, 
    struct nsn_dataplane_thread_args *dp_args, usize dp_args_count)
{
    nsn_unused(dp_args_count);

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
            if (app_pool_try_alloc_slot(&app_pool, app_id)) {
                log_debug("app %d connected\n", app_id);

                cmsghdr->type             = NSN_CMSG_TYPE_CONNECTED;
                nsn_cmsg_connect_t *reply = (nsn_cmsg_connect_t *)(cmsghdr + 1);
                reply->shm_size           = mem_cfg.shm_size;
                snprintf(reply->shm_name, NSN_MAX_PATH_SIZE, "nsnd_datamem");
                
                reply_len = sizeof(nsn_cmsg_hdr_t) + sizeof(nsn_cmsg_connect_t);
            } else {
                cmsghdr->type   = NSN_CMSG_TYPE_ERROR;
                int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                *error_code     = 1;

                reply_len = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
            }
        } break;        
        case NSN_CMSG_TYPE_CREATE_STREAM:
        {
            log_debug("received new stream message from app %d\n", app_id);

            // start the first data plane thread
            at_store(&dp_args[0].state, NSN_DATAPLANE_THREAD_STATE_RUNNING, mo_rlx);

        } break;
        case NSN_CMSG_TYPE_DESTROY_STREAM:
        {
            log_debug("received destroy stream message from app %d\n", app_id);

            // stop the first data plane thread
            at_store(&dp_args[0].state, NSN_DATAPLANE_THREAD_STATE_WAIT, mo_rlx);

        } break;
        case NSN_CMSG_TYPE_CREATE_SOURCE:
        {
            log_debug("received new source message from app %d\n", app_id);

        } break;
        case NSN_CMSG_TYPE_CREATE_SINK:
        {
            log_debug("received new sink message from app %d\n", app_id);

            // allocate a new rx ring buffer

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


// --- Os Initialization --------------------------------------------------------

void
os_init(void)
{
    // read the file /proc/cpuinfo to get the cpu MHz
    nsn_file_t file = nsn_os_file_open(str_lit("/proc/cpuinfo"), NsnFileFlag_Read);
    if (!nsn_file_valid(file)) {
        log_error("Failed to open /proc/cpuinfo\n");
        return;
    }

    temp_mem_arena_t temp = nsn_thread_scratch_begin(NULL, 0);
    string_t cpuinfo      = nsn_os_read_entire_pseudofile(temp.arena, file);

    string_t delims[]   = { str_lit("\n") };
    string_list_t lines = str_split(temp.arena, cpuinfo, delims, array_count(delims));

    u64 cpu_mhz    = 0;
    string_t match = str_lit("cpu MHz"); 
    for (string_node_t *node = lines.head; node; node = node->next) {
        if (str_contains(node->string, match)) {
            log_debug("found match: " str_fmt "\n", str_varg(node->string));

            string_t delims[]   = { str_lit(":") };   
            string_list_t parts = str_split(temp.arena, node->string, delims, array_count(delims));
            
            // take the key and the value
            // string_t key   = parts.head->string;
            string_t value = str_trim(parts.head->next->string);
            cpu_mhz        = f64_from_str(value);

            break;
        }
    }
    
    nsn_thread_scratch_end(temp);

    nsn_os_file_close(file);

    cpu_hz = (i64)(cpu_mhz * 1000000);
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

    os_init();
    printf("### INSANE stats:\n"
           "  - CPU frequency: %ld\n"
           "  - sizeof(nsn_zone): %ld\n"
           "  - sizeof(nsn_ringbuf): %ld\n"
           "  - sizeof(nsn_ringbuf_pool): %ld\n",
           cpu_hz, sizeof(nsn_mm_zone_t), sizeof(nsn_ringbuf_t), sizeof(nsn_ringbuf_pool_t));

    instance_id   = nsn_os_get_process_id();
    state_arena = mem_arena_alloc(gigabytes(1));

    for (int i = 0; i < argc; i++)
        str_list_push(state_arena, &arg_list, str_cstr(argv[i]));

    string_t config_filename = str_lit(NSN_DEFAULT_CONFIG_FILE);
    for (string_node_t *node = arg_list.head; node; node = node->next) {
        if (str_eq(str_lit("--config"), node->string) || str_eq(str_lit("-c"), node->string)) {
            if (node->next) {
                config_filename = node->next->string;
            }
        }
    }

    config = nsn_load_config(state_arena, config_filename);
    if (!config) {
        log_error("Failed to load config file: " str_fmt "\n", str_varg(config_filename));
        exit(1);
    }
 
    int app_num      = 64;
    int io_bufs_num  = NSN_CFG_DEFAULT_IO_BUFS_NUM;
    int io_bufs_size = NSN_CFG_DEFAULT_IO_BUFS_SIZE;   
    int shm_size     = NSN_CFG_DEFAULT_SHM_SIZE;
    
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
        .shm_name            = str_lit(NSN_CFG_DEFAULT_SHM_NAME),
        .shm_size            = megabytes(shm_size),
        .io_buffer_pool_size = (usize)io_bufs_num,
        .io_buffer_size      = (usize)io_bufs_size,
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

    // --- Create the thread pool. Currently, one thread only, bound to the udpsock datapath plugin.
    struct nsn_dataplane_thread_args dp_args[2] = {
        { .mm = mem, .state = NSN_DATAPLANE_THREAD_STATE_WAIT, .datapath_name = str_lit_compound("udpsock") },
        { .mm = mem, .state = NSN_DATAPLANE_THREAD_STATE_WAIT, .datapath_name = str_lit_compound("udpsock") }
    };

    nsn_os_thread_t threads[1];
    for (usize i = 0; i < array_count(threads); i++) {
        log_trace("creating thread %d\n", i);
        threads[i] = nsn_os_thread_create(dataplane_thread_proc, &dp_args[i]);
    }

    //--- This is a test, to be removed
    nsn_os_thread_t test_app_thread;
    test_app_thread_args_t test_args = { .mm = mem };
    test_app_thread = nsn_os_thread_create(test_app_thread_proc, &test_args);
    //---

    while (g_running) 
    {
        if (main_thread_control_ipc(sockfd, mem_cfg, dp_args, array_count(dp_args)) < 0)
            log_warn("Failed to handle control ipc\n");

        usleep(1);
    }

    // Tell the threads to stop
    for (usize i = 0; i < array_count(threads); i++) {
        at_store(&dp_args[i].state, NSN_DATAPLANE_THREAD_STATE_STOP, mo_rlx);
    }

    for (usize i = 0; i < array_count(threads); i++) {
        nsn_os_thread_join(threads[i]);
    }

    nsn_os_thread_join(test_app_thread);

    // cleanup
clear_and_quit:
    if (sockfd != -1) close(sockfd);
    unlink(NSNAPP_TO_NSND_IPC);
    nsn_memory_manager_destroy(mem);
quit:
    mem_arena_release(state_arena);
    mem_arena_release(arena);

    log_debug("done\n");

    return 0;
}
