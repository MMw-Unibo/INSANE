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
#define NSN_CFG_DEFAULT_FREE_SLOTS_RING_NAME    "free_slots"
#define NSN_CFG_DEFAULT_TX_RING_SIZE            4096
#define NSN_CFG_DEFAULT_RX_RING_SIZE            4096
#define NSN_CFG_DEFAULT_MAX_THREADS_PER_PLUGIN  2

static i64 cpu_hz = -1;

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
//  In particular, the managed memory is used to store:
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
nsn_memory_manager_create_ringbuf_pool(nsn_mem_manager_t *mem, string_t name, usize count, usize esize, usize ecount)
{
    usize zone_size = sizeof(nsn_ringbuf_pool_t)           // the size of the pool header
                    + (count * sizeof(bool))               // keeps track of the free slots
                    + sizeof(nsn_ringbuf_t) * count        // the number of ring buffers
                    + (esize * ecount) * count;            // the size of the elements in the ring buffers

    nsn_mm_zone_t *zone = nsn_memory_manager_create_zone(mem, name, zone_size, NSN_MM_ZONE_TYPE_RINGS);
    if (!zone) {
        log_error("Failed to create zone for ring buffer pool\n");
        return NULL;
    }

    nsn_ringbuf_pool_t *pool = (nsn_ringbuf_pool_t *)nsn_mm_zone_get_ptr(mem->shm_arena->base, zone);
    pool->zone              = zone;
    pool->count             = count;
    pool->esize             = esize;
    pool->ecount            = ecount;
    pool->free_slots_count  = count;
    strncpy(pool->name, to_cstr(name), sizeof(pool->name) - 1);

    return pool;
}

nsn_ringbuf_pool_t* nsn_memory_manager_get_ringbuf_pool(nsn_mem_manager_t* mem) {
    nsn_mm_zone_t* zone = nsn_find_zone_by_name(mem->zones, str_lit("rings_zone"));
    if (!zone) {
        log_error("Zone \"rings_zone\" not found\n");
        return NULL;
    }

    return (nsn_ringbuf_pool_t*)nsn_mm_zone_get_ptr(mem->shm_arena->base, zone);
}

// @param pool: the pool of ring buffers
// @param ring_name: the name of the ring buffer
// @param count: the number of elements in the ring buffer
// @return: a pointer to the ring buffer
nsn_ringbuf_t * 
nsn_memory_manager_create_ringbuf(nsn_ringbuf_pool_t* pool, string_t ring_name, u32 count) {

    if(pool->free_slots_count == 0) {
        log_error("No more free slots in the ring buffer pool\n");
        return NULL;
    }

    // check which slots are free
    bool* ring_tracker = (bool*)(pool + 1);

    // find a free slot
    int slot = -1;
    for (usize i = 0; i < pool->count; ++i) {
        if (ring_tracker[i] == false) {
            ring_tracker[i] = true;
            slot = i;
            break;
        }
    }

    // create the ring buffer in the shared memory
    char* ring_data = (char*)(ring_tracker + pool->count);  
    usize ring_size = sizeof(nsn_ringbuf_t) + (pool->ecount * pool->esize);
    nsn_ringbuf_t* ring = nsn_ringbuf_create(&ring_data[slot*ring_size], ring_name, count);

    // fill in the descriptorsfor this ring in the pool    
    pool->free_slots_count--;

    log_info("Ring buffer %.*s created at %p\n", str_varg(ring_name), ring);
    return ring;
}

// @param mem: the memory manager
// @param ring_name: the name of the ring buffer to retrieve
// @return: a pointer to the ring buffer, NULL if the ring buffer was not found
nsn_ringbuf_t *
nsn_memory_manager_lookup_ringbuf(nsn_mem_manager_t* mem, string_t ring_name) {
    nsn_ringbuf_pool_t* pool = nsn_memory_manager_get_ringbuf_pool(mem);
    if (!pool) {
        log_error("Failed to get the ring buffer pool\n");
        return NULL;
    }
    
    // check which slots are free
    bool* ring_tracker = (bool*)(pool + 1);
    char* ring_data = (char*)(ring_tracker + pool->count);  
    usize ring_size = sizeof(nsn_ringbuf_t) + (pool->ecount * pool->esize);

    // find the ring buffer to destroy
    nsn_ringbuf_t* ring = 0;
    for (usize i = 0; i < pool->count; i++) {
        if (ring_tracker[i] == true) {
            ring = (nsn_ringbuf_t*)(&ring_data[i*ring_size]);
            if (strcmp(ring->name, to_cstr(ring_name)) == 0) {
                break;
            } else {
                ring = NULL;
            }
        }
    }

    if (!ring) {
        log_error("Lookup: Ring buffer %.*s not found\n", str_varg(ring_name));
        return NULL;
    }

    return ring;
}

// @param pool: the pool of ring buffers
// @param ring_name: the name of the ring buffer to destroy
// @return: 0 if the ring buffer was destroyed, <0 otherwise (errno value)
int 
nsn_memory_manager_destroy_ringbuf(nsn_ringbuf_pool_t* pool, string_t ring_name) {
    if (!pool) {
        log_error("Invalid ring buffer pool\n");
        return -1;
    }

    // check which slots are free
    bool* ring_tracker = (bool*)(pool + 1);
    char* ring_data = (char*)(ring_tracker + pool->count);  
    usize ring_size = sizeof(nsn_ringbuf_t) + (pool->ecount * pool->esize);

    // find the ring buffer to destroy
    nsn_ringbuf_t* ring = 0;
    for (usize i = 0; i < pool->count; i++) {
        if (ring_tracker[i] == true) {
            ring = (nsn_ringbuf_t*)(&ring_data[i*ring_size]);
            if (strcmp(ring->name, to_cstr(ring_name)) == 0) {
                break;
            } else {
                ring = NULL;
            }
        }
    }

    if (!ring) {
        log_error("Lookup: Ring buffer %.*s not found\n", str_varg(ring_name));
        return -1;
    }

    // destroy the ring buffer
    int error = nsn_ringbuf_destroy(ring);
    if (!error) {
        pool->free_slots_count++;
    }

    return -error;
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
        log_error("Failed to create shared memory\n");
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

    usize total_zone_size = cfg->io_buffer_pool_size * cfg->io_buffer_size;
    nsn_mm_zone_t *tx_zone = nsn_memory_manager_create_zone(mem, str_lit(NSN_CFG_DEFAULT_TX_IO_BUFS_NAME), total_zone_size, NSN_MM_ZONE_TYPE_IO_BUFFER_POOL);
    if (!tx_zone) {
        log_error("failed to create the tx_zone\n");
        return NULL;
    }
    // nsn_mm_zone_t *rx_zone = nsn_memory_manager_create_zone(mem, str_lit(NSN_CFG_DEFAULT_RX_IO_BUFS_NAME), total_zone_size, NSN_MM_ZONE_TYPE_IO_BUFFER_POOL);

    // Create a pool of ring buffers inside the ring zone
    usize max_rings = 16;
    nsn_ringbuf_pool_t *ring_pool = nsn_memory_manager_create_ringbuf_pool(mem, str_lit(NSN_CFG_DEFAULT_RINGS_ZONE_NAME), max_rings, sizeof(usize), cfg->io_buffer_pool_size);

    // Create the ring that keeps the free slot descriptors.
    // TODO: The free_slots can be split into a tx/rx couple of rings, if we decide to keep both the tx and rx memory areas separated. Now we keep 1 zone for slots (tx_zone) and 1 ring for its indexing (NSN_CFG_DEFAULT_FREE_SLOTS_RING_NAME).
    usize total_free_slots = 2 * cfg->io_buffer_pool_size;
    nsn_ringbuf_t *free_slots_ring = nsn_memory_manager_create_ringbuf(ring_pool, str_lit(NSN_CFG_DEFAULT_FREE_SLOTS_RING_NAME), total_free_slots);
    if (!free_slots_ring) {
        log_error("Failed to create the free_slots ring\n");
        // TODO: Should we clean the things we created so far? E.g., zones etc?
        return NULL;
    }
    log_trace("Successfully created the free_slots ring at %p with name %s\n", free_slots_ring, free_slots_ring->name);
    
    // Fill the ring buffer with the index of the tx slots 
    for (usize i = 0; i < total_free_slots; i+=cfg->io_buffer_size) {
        nsn_ringbuf_enqueue_burst(free_slots_ring, &i, sizeof(u64), 1, NULL);
    } 

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

// Return the offset of a managed element with respect to the memory arena base address.
usize
nsn_memory_manager_offset_of(nsn_mem_manager_t *mem, void* element) {
    log_info("element: %p\n", (char*)element);
    log_info("shm->data: %p\n", mem->shm->data);
    return (usize)element - (usize)mem->shm->data;
}

typedef struct nsn_app nsn_app_t;
struct nsn_app
{
    int app_id;
    mem_arena_t *arena;
    nsn_mem_manager_t* mem;
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
app_pool_init_slot(nsn_app_pool_t *pool, int app_slot, nsn_mem_manager_cfg_t* mem_cfg)
{
    if (app_slot < 0) {
        return false;
    }
    // TODO: maybe restrict the access permissions to those two processes with mprotect?)
    nsn_app_t *app = &pool->apps[app_slot];
    app->arena = mem_arena_alloc(megabytes(500));
    if (!app->arena) {
        log_error("Failed to create memory arena for app %d\n", app->app_id);
        return false;
    }

    log_debug("Created memory arena for app %d at %p\n base %u (%p)\n pos %u\n com_pos %u\n", app->app_id, app->arena, 
        app->arena->base, (char*)app->arena->base,
        app->arena->pos,
        app->arena->com_pos);

    char shm_name_app[NSN_MAX_PATH_SIZE];
    snprintf(shm_name_app, NSN_MAX_PATH_SIZE, "%s_%d", mem_cfg->shm_name.data, app->app_id);
    mem_cfg->shm_name = str_lit(shm_name_app);

    app->mem = nsn_memory_manager_create(app->arena, mem_cfg);
    if (!app->mem) {
        log_error("Failed to create shared memory for app \n");
        return false;
    }
    return true;
}

int 
app_pool_try_alloc_slot(nsn_app_pool_t *pool, int app_id)
{
    for (usize i = 0; i < pool->count; i++) {
        if (pool->free_apps_slots[i]) {
            pool->free_apps_slots[i]  = false;
            pool->apps[i].app_id      = app_id;
            pool->used               += 1;
            return (int)i;
        }
    }
    return -1;
}

bool 
app_pool_try_alloc_and_init_slot(nsn_app_pool_t *pool, int app_id, nsn_mem_manager_cfg_t mem_cfg)
{
    int slot = app_pool_try_alloc_slot(pool, app_id);
    if (slot < 0) {
        return false;
    }
    return app_pool_init_slot(pool, slot, &mem_cfg);
}

typedef struct nsn_plugin nsn_plugin_t;
struct nsn_plugin
{
    string_t name;
    nsn_os_thread_t* threads;
    usize thread_count;
    usize active_channels;    
};

typedef struct nsn_plugin_set nsn_plugin_set_t;
struct nsn_plugin_set 
{
    nsn_plugin_t *plugins;
    usize         count;
};

// --- Thread Pool -------------------------------------------------------

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
    // nsn_mem_manager_t *mm;
    atu32              state;
    string_t           datapath_name;
};

typedef struct nsn_thread_pool nsn_thread_pool_t;
struct nsn_thread_pool
{
    nsn_os_thread_t *threads;
    struct nsn_dataplane_thread_args *thread_args;
    usize            count;
};

////////
// --- INSANE daemon state ----------------------------------------------------

int instance_id          = 0;
mem_arena_t *state_arena = NULL;
nsn_app_pool_t app_pool  = {0};
nsn_plugin_set_t plugin_set = {0};
nsn_thread_pool_t thread_pool = {0};

string_list_t arg_list = {0};
nsn_cfg_t *config      = NULL;
////////

void *
dataplane_thread_proc(void *arg)
{
    struct nsn_dataplane_thread_args *args = (struct nsn_dataplane_thread_args *)arg;
    // nsn_mem_manager_t *mem = args->mm;
    // nsn_unused(mem);

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

// // --- Test Application Thread --------------------------------------------------

// typedef struct test_app_thread_args test_app_thread_args_t;
// struct test_app_thread_args
// {
//     nsn_mem_manager_t *mm;
// };

// void *
// test_app_thread_proc(void *arg)
// {
//     test_app_thread_args_t *args = (test_app_thread_args_t *)arg;
//     nsn_mem_manager_t *mem = args->mm;
//     nsn_unused(mem);

//     log_info("thread [test app] started\n");

//     i64 cycles_start = nsn_os_get_cycles();
//     // for (usize i = 0; i < 100; i++) {
//     //     u64 table[16];
//     //     nsn_ringbuf_dequeue_burst(mem->tx_ring, table, sizeof(u64), 1, NULL);
//     // }
//     i64 cycles_end = nsn_os_get_cycles();
//     f64 elapsed_ns = (cycles_end - cycles_start) / (f64)(cpu_hz / 1000000000.0);
//     log_info("nsn_ringbuf_dequeue_burst() took %f ns (%ld cycles)\n", elapsed_ns / 100, cycles_end - cycles_start);

//     return NULL;
// }

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

    // TODO: except from the CONNECT case, we should check that the app_id is valid.
    // and, if not, we should TERMINATE the application issuing the request.
    // We should also introduce some mechanism to ensure that no app is sending us a different
    // app_id than the one it was assigned. It would be a big security issue.

    switch (cmsghdr->type)
    {
        case NSN_CMSG_TYPE_CONNECT:
        {
            if (app_pool_try_alloc_and_init_slot(&app_pool, app_id, mem_cfg)) {
                log_debug("app %d connected\n", app_id);

                // Complete the reply
                cmsghdr->type             = NSN_CMSG_TYPE_CONNECTED;
                nsn_cmsg_connect_t *reply = (nsn_cmsg_connect_t *)(cmsghdr + 1);
                reply->shm_size           = mem_cfg.shm_size;
                strcpy(reply->free_slots_ring, NSN_CFG_DEFAULT_FREE_SLOTS_RING_NAME);
                snprintf(reply->shm_name, NSN_MAX_PATH_SIZE, "nsnd_datamem_%d", app_id);
                
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
            
            // Check that the app_id exists
            uint32_t app_idx = UINT32_MAX;
            for (usize i = 0; i < app_pool.count; i++) {
                if (app_pool.apps[i].app_id == app_id) {
                    app_idx = (uint32_t)i;
                    break;
                }
            }
            if(app_idx > app_pool.count) {
                log_error("app %d not found in the pool\n", app_id);
                cmsghdr->type = NSN_CMSG_TYPE_ERROR;
                int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                *error_code     = 2;
                reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
                break;
            }

            // TODO(lr): Here we should put the logic for the QoS-to-plugin mapping.
            // For the moment, just use the first one
            uint16_t stream_idx = 0;

            // Return the index of the plugin as stream handler
            nsn_cmsg_create_stream_t *reply = (nsn_cmsg_create_stream_t*)(cmsghdr + 1);
            reply->stream_idx = stream_idx;

            // Create the ring buffers, where the consumer and producer definitions are relative to the application.
            // The tx_cons and the rx_prod are the same ring, the free_slots ring, which is already available to the app.
            // The tx_prod is created here for this plugin, allowing the app to send data to the plugin.
            snprintf(reply->tx_prod, NSN_CFG_RINGBUF_MAX_NAME_SIZE, "tx_prod_%u", stream_idx);
            // The rx_cons is created here for this plugin, allowing the app to receive data from the plugin.
            snprintf(reply->rx_cons, NSN_CFG_RINGBUF_MAX_NAME_SIZE, "rx_cons_%u", stream_idx);
            
            nsn_ringbuf_pool_t *ring_pool = nsn_memory_manager_get_ringbuf_pool(app_pool.apps[app_idx].mem);
            nsn_ringbuf_t *tx_prod_ring = nsn_memory_manager_create_ringbuf(ring_pool, str_lit(reply->tx_prod), NSN_CFG_DEFAULT_TX_RING_SIZE);
            if (!tx_prod_ring) {
                log_error("Failed to create the tx_prod ring\n", tx_prod_ring);
                cmsghdr->type = NSN_CMSG_TYPE_ERROR;
                int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                *error_code     = 3;
                reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
                break;
            }

            nsn_ringbuf_t *rx_cons_ring = nsn_memory_manager_create_ringbuf(ring_pool, str_lit(reply->rx_cons), NSN_CFG_DEFAULT_RX_RING_SIZE);
            if (!rx_cons_ring) {
                log_error("Failed to create the rx_cons ring\n", rx_cons_ring);
                cmsghdr->type = NSN_CMSG_TYPE_ERROR;
                int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                *error_code     = 3;
                reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
                break;
            }

            // TODO: Where do we put this ring? We should make the plugin thread aware of it. HOW?
           
            // Successful operation: return success
            cmsghdr->type = NAN_CSMG_TYPE_CREATED_STREAM;
            reply_len = sizeof(nsn_cmsg_hdr_t) + sizeof(nsn_cmsg_create_stream_t);

        } break;
        case NSN_CMSG_TYPE_DESTROY_STREAM:
        {
            log_debug("received destroy stream message from app %d\n", app_id);

            // Check that the app_id exists
            uint32_t app_idx = UINT32_MAX;
            for (usize i = 0; i < app_pool.count; i++) {
                if (app_pool.apps[i].app_id == app_id) {
                    app_idx = (uint32_t)i;
                    break;
                }
            }
            if(app_idx > app_pool.count) {
                log_error("app %d not found in the pool\n", app_id);
                cmsghdr->type = NSN_CMSG_TYPE_ERROR;
                int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                *error_code     = 2;
                reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
                break;
            }

            // Check that the stream index is valid
            nsn_cmsg_create_source_t *reply = (nsn_cmsg_create_source_t *)(cmsghdr + 1);
            uint32_t stream_idx = (uint32_t)reply->stream_idx;
            if (stream_idx >= plugin_set.count) {
                log_error("stream index %d is out of bounds\n", stream_idx);
                cmsghdr->type = NSN_CMSG_TYPE_ERROR;
                int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                *error_code     = 2;
                reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
                break;
            }

            // check that no channel is active for this stream
            if (plugin_set.plugins[stream_idx].active_channels > 0) {
                log_error("stream %d has active channels (src/snk)\n", stream_idx);
                cmsghdr->type = NSN_CMSG_TYPE_ERROR;
                int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                *error_code     = 3;
                reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
                break;
            }

            // 3) [Future Work] Detach the thread(s) associated with this stream. Here, or proactively at channel destruction.

            // 4) destroy the tx/rx rings
            nsn_ringbuf_pool_t *ring_pool = nsn_memory_manager_get_ringbuf_pool(app_pool.apps[app_idx].mem);
            char tx_prod_ring_name[NSN_CFG_RINGBUF_MAX_NAME_SIZE];
            snprintf(tx_prod_ring_name, NSN_CFG_RINGBUF_MAX_NAME_SIZE, "tx_prod_%u", stream_idx);
            int err = nsn_memory_manager_destroy_ringbuf(ring_pool, str_lit(tx_prod_ring_name));
            if (err < 0) {
                log_error("Failed to destroy the tx_prod ring\n");
                cmsghdr->type = NSN_CMSG_TYPE_ERROR;
                int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                *error_code     = 4;
                reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
                break;
            }

            // 5) destroy the rx_cons ring
            char rx_cons_ring_name[NSN_CFG_RINGBUF_MAX_NAME_SIZE];
            snprintf(rx_cons_ring_name, NSN_CFG_RINGBUF_MAX_NAME_SIZE, "rx_cons_%u", stream_idx);
            err = nsn_memory_manager_destroy_ringbuf(ring_pool, str_lit(rx_cons_ring_name));
            if (err < 0) {
                log_error("Failed to destroy the rx_cons ring\n");
                cmsghdr->type = NSN_CMSG_TYPE_ERROR;
                int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                *error_code     = 4;
                reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
                break;
            }

            // Return success
            cmsghdr->type = NSN_CMSG_TYPE_DESTROYED_STREAM;
            reply_len = sizeof(nsn_cmsg_hdr_t);

        } break;
        case NSN_CMSG_TYPE_CREATE_SOURCE:
        {
            log_debug("received new source message from app %d\n", app_id);

            // Check that the app_id exists
            uint32_t app_idx = UINT32_MAX;
            for (usize i = 0; i < app_pool.count; i++) {
                if (app_pool.apps[i].app_id == app_id) {
                    app_idx = (uint32_t)i;
                    break;
                }
            }
            if(app_idx > app_pool.count) {
                log_error("app %d not found in the pool\n", app_id);
                cmsghdr->type = NSN_CMSG_TYPE_ERROR;
                int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                *error_code     = 2;
                reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
                break;
            }

            // Check that the stream index is valid
            nsn_cmsg_create_source_t *reply = (nsn_cmsg_create_source_t *)(cmsghdr + 1);
            uint32_t stream_idx = (uint32_t)reply->stream_idx;
            if (stream_idx >= plugin_set.count) {
                log_error("stream index %d is out of bounds\n", stream_idx);
                cmsghdr->type = NSN_CMSG_TYPE_ERROR;
                int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                *error_code     = 2;
                reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
                break;
            }
          
            // if this is the first src/snk (=channel) in the stream, start the first 
            // data plane thread. In the future, this will be delegated to a thread pool manager.
            if (plugin_set.plugins[stream_idx].active_channels == 0) {
                // Currenlty, we just consider that thread j is assigned to plugin j.
                uint32_t thread_idx = stream_idx;
                struct nsn_dataplane_thread_args *dp_args = &thread_pool.thread_args[thread_idx];
                // It might be the case that the thread is already associated with the plugin,
                // until we implement a thread pool manager. In this case, no need to add a 
                // thread to the plugin; just start the existing one.
                if (plugin_set.plugins[stream_idx].thread_count == 0) {
                    // Keep a pointer to the thread in the plugin
                    plugin_set.plugins[stream_idx].threads[plugin_set.plugins[stream_idx].thread_count] 
                                                = thread_pool.threads[thread_idx];
                    plugin_set.plugins[stream_idx].thread_count++;
                    // Assign the plugin to the thread
                    dp_args->datapath_name = plugin_set.plugins[stream_idx].name;
                }
                // start the thread
                at_store(&dp_args->state, NSN_DATAPLANE_THREAD_STATE_RUNNING, mo_rlx);
            }

            // Ref count of the channels (src/snk) active in the stream
            plugin_set.plugins[stream_idx].active_channels++;

            // finalize the answer
            cmsghdr->type = NSN_CMSG_TYPE_CREATED_SOURCE;
            reply_len = sizeof(nsn_cmsg_hdr_t) + sizeof(nsn_cmsg_create_source_t);
        } break;
        case NSN_CMSG_TYPE_DESTROY_SOURCE: 
        {
            log_debug("received destroy source message from app %d\n", app_id);

            // Check that the app_id exists
            uint32_t app_idx = UINT32_MAX;
            for (usize i = 0; i < app_pool.count; i++) {
                if (app_pool.apps[i].app_id == app_id) {
                    app_idx = (uint32_t)i;
                    break;
                }
            }
            if(app_idx > app_pool.count) {
                log_error("app %d not found in the pool\n", app_id);
                cmsghdr->type = NSN_CMSG_TYPE_ERROR;
                int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                *error_code     = 2;
                reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
                break;
            }

            // Check that the stream index is valid
            nsn_cmsg_create_source_t *reply = (nsn_cmsg_create_source_t *)(cmsghdr + 1);
            uint32_t stream_idx = (uint32_t)reply->stream_idx;
            if (stream_idx >= plugin_set.count) {
                log_error("stream index %d is out of bounds\n", stream_idx);
                cmsghdr->type = NSN_CMSG_TYPE_ERROR;
                int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                *error_code     = 2;
                reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
                break;
            }

            // if the stream has no more active channels, stop the data plane thread 
            // (which remains attached to the plugin, until we implement a thread pool manager)
            // (ideally, the thread should go back into the pool)
            // Currently, we just consider that thread j is assigned to plugin j.
            uint32_t thread_idx = stream_idx;
            struct nsn_dataplane_thread_args *dp_args = &thread_pool.thread_args[thread_idx];
            at_store(&dp_args->state, NSN_DATAPLANE_THREAD_STATE_WAIT, mo_rlx);

            // Ref count of the channels (src/snk) active in the stream
            plugin_set.plugins[stream_idx].active_channels--;

            reply_len = sizeof(nsn_cmsg_hdr_t);

        } break;
        case NSN_CMSG_TYPE_CREATE_SINK:
        {
            log_debug("received new sink message from app %d\n", app_id);

            // if first ch in the stream, start the first data plane thread
            at_store(&dp_args[0].state, NSN_DATAPLANE_THREAD_STATE_RUNNING, mo_rlx);

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

                    // Release the memory shared with the app.
                    // This will destroy whatever is in the shared memory,
                    // including the ring buffers, the zones, etc.
                    nsn_memory_manager_destroy(app_pool.apps[i].mem);
                    mem_arena_release(app_pool.apps[i].arena);

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
    state_arena = mem_arena_alloc(megabytes(1));

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
    mem_arena_t *arena = mem_arena_alloc(megabytes(1));
    app_pool.count           = app_num;
    app_pool.apps            = mem_arena_push_array(arena, nsn_app_t, app_pool.count);
    app_pool.free_apps_slots = mem_arena_push_array(arena, bool, app_pool.count);
    for (usize i = 0; i < app_pool.count; i++)    app_pool.free_apps_slots[i] = true;

    // TODO: Automatically detect which plugins are available and can be used by the daemon.
    // Currently, we only consider 1 as available (make it the "udpsock" plugin).
    plugin_set.plugins = mem_arena_push_array(arena, nsn_plugin_t, 1);
    plugin_set.count   = 1;
    for (usize i = 0; i < plugin_set.count; i++) {
        plugin_set.plugins[i].name = str_lit("udpsock");
        plugin_set.plugins[i].thread_count = 0;
        plugin_set.plugins[i].threads = mem_arena_push_array(arena, nsn_os_thread_t,
                                                    NSN_CFG_DEFAULT_MAX_THREADS_PER_PLUGIN);
        plugin_set.plugins[i].active_channels = 0;
    }

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

    // --- Init the thread pool. Currently, one thread only. We do not set here the dp_args.name, 
    // as the thread pool exists independently of the associated plugin. However, it is important that
    // the name is set when the thread moves to the RUNNING state, as it will try to load the dll.
    // The association is done when a new stream for a new plugin is set, and currently is permanent.
    // Future work will include a way to dynamically attach/detach threads to/from plugins.
    thread_pool.count = 1;
    thread_pool.threads = mem_arena_push_array(arena, nsn_os_thread_t, thread_pool.count);
    thread_pool.thread_args = mem_arena_push_array(arena, struct nsn_dataplane_thread_args, 
                                                        thread_pool.count);
    for (usize i = 0; i < thread_pool.count; i++) {
        log_trace("creating thread %d\n", i);
        thread_pool.thread_args[i] = 
            (struct nsn_dataplane_thread_args){ .state = NSN_DATAPLANE_THREAD_STATE_WAIT};
        thread_pool.threads[i] = nsn_os_thread_create(dataplane_thread_proc, &thread_pool.thread_args[i]);
        if (thread_pool.threads[i].handle == 0) {
            log_error("Failed to create thread %d\n", i);
            goto clear_and_quit;
        }
    }

    // Control path
    struct nsn_dataplane_thread_args cp_args = { .state = NSN_DATAPLANE_THREAD_STATE_WAIT  };
    while (g_running) 
    {
        if (main_thread_control_ipc(sockfd, mem_cfg, &cp_args, 1) < 0)
            log_warn("Failed to handle control ipc\n");

        usleep(1);
    }

    // Stop the threads in the thread pool
    for (usize i = 0; i < thread_pool.count; i++) {
        at_store(&thread_pool.thread_args[i].state, NSN_DATAPLANE_THREAD_STATE_STOP, mo_rlx);
    }

    for (usize i = 0; i < thread_pool.count; i++) {
        nsn_os_thread_join(thread_pool.threads[i]);
    }

    // cleanup
clear_and_quit:
    if (sockfd != -1) close(sockfd);
    unlink(NSNAPP_TO_NSND_IPC);
// quit:
    mem_arena_release(state_arena);
    mem_arena_release(arena);

    log_debug("done\n");

    return 0;
}
