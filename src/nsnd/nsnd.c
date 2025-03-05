////////////////////////////////////////////////////////////////////////////////
// @Includes 
#include "base/nsn_memory.h"
#include "base/nsn_shm.h"
#include "base/nsn_string.h"
#include "base/nsn_thread_ctx.h"
#include "base/nsn_types.h"

#include "nsn_datapath.h"

#include "common/nsn_config.h"
#include "common/nsn_ipc.h"
#include "common/nsn_ringbuf.h"
#include "common/nsn_temp.h"
#include "common/nsn_zone.h"

// Daemon specific includes
#include "nsn_app_inner.h"
#include "nsn_mm.h"

#define NSN_LOG_IMPLEMENTATION
#include "common/nsn_log.h"

////////////////////////////////////////////////////////////////////////////////
// @CFiles 
#include "base/nsn_memory.c"
#include "base/nsn_os_inc.c"
#include "base/nsn_shm.c"
#include "base/nsn_string.c"

#include "common/nsn_config.c"
#include "common/nsn_ringbuf.c"

// Daemon specific implementations
#include "nsn_app_inner.c"
#include "nsn_mm.c"

////////////////////////////////////////////////////////////////////////////////
// @Defines 
#define NSN_DEFAULT_CONFIG_FILE     "nsnd.cfg"

#define NSN_CFG_DEFAULT_SECTION                     "global"
#define NSN_CFG_DEFAULT_SHM_NAME                    "nsnd_datamem"
#define NSN_CFG_DEFAULT_IO_BUFS_NUM                 1024
#define NSN_CFG_DEFAULT_IO_BUFS_SIZE                2048
#define NSN_CFG_DEFAULT_SHM_SIZE                    64      // in MB
#define NSN_CFG_DEFAULT_MAX_TX_BURST                32
#define NSN_CFG_DEFAULT_MAX_RX_BURST                32
#define NSN_CFG_DEFAULT_TX_IO_BUFS_NAME             "tx_io_buffer_pool"
#define NSN_CFG_DEFAULT_RX_IO_BUFS_NAME             "rx_io_buffer_pool"
#define NSN_CFG_DEFAULT_RINGS_ZONE_NAME             "rings_zone"
#define NSN_CFG_DEFAULT_FREE_SLOTS_RING_NAME        "free_slots"
#define NSN_CFG_DEFAULT_TX_RING_SIZE                4096
#define NSN_CFG_DEFAULT_RX_RING_SIZE                4096
#define NSN_CFG_DEFAULT_MAX_THREADS_PER_PLUGIN      2



// --- Plugin, Streams, Endpoints, Sinks -------------------------------------------------

// Sink: needed to dispatch data to the right sink
typedef struct nsn_inner_sink nsn_inner_sink_t;
struct nsn_inner_sink
{
    list_head_t   node;
    nsn_ringbuf_t *rx_cons;
    u32           sink_id;
};

// Sink: needed to dispatch data to the right sink
typedef struct nsn_inner_source nsn_inner_source_t;
struct nsn_inner_source
{
    list_head_t   node;
    u32           src_id;
};

// Stream: state for a specific plugin for a specific app_id
typedef struct nsn_inner_stream nsn_inner_stream_t;
struct nsn_inner_stream
{
    list_head_t         node;
    u32                 plugin_idx; // Shortcut to the plugin
    u32                 idx;        // Index of this stream

    // tx ring from srcs to the plugin
    nsn_ringbuf_t*      tx_prod;
    list_head_t         sources;
    atu32               n_srcs;

    // tx ring - packets that need a retry send
    nsn_ringbuf_t*      tx_pending;

    // Sinks active for this stream
    list_head_t        sinks; 
    nsn_mutex_t        sinks_lock;
    atu32              n_sinks;

    // Endpoint info (for the plugin)
    nsn_endpoint_t          ep;
};

typedef struct nsn_plugin nsn_plugin_t;
struct nsn_plugin
{
    string_t                  name;    // The name of the plugin
    nsn_os_thread_t*          threads; // The threads that run the plugin
    usize                     thread_count; // The number of those threads
    u32                       active_channels; // No. of total src+snk
    list_head_t               streams; // List of streams that use this plugin
    nsn_mutex_t               streams_lock; // Lock for the streams list   
    u32                       stream_id_cnt; //used to assign stream_ids
    nsn_datapath_update       *update; // The plugin's UPDATE function
    nsn_datapath_conn_manager *conn_manager; // The plugin's connection manager
};

typedef struct nsn_plugin_set nsn_plugin_set_t;
struct nsn_plugin_set 
{
    nsn_plugin_t *plugins;
    usize         count;
};


struct datapath_ops
{
    nsn_datapath_init         *init;
    nsn_datapath_conn_manager *conn_manager;
    nsn_datapath_update       *update;
    nsn_datapath_tx           *tx;
    nsn_datapath_rx           *rx;
    nsn_datapath_deinit       *deinit;
};

////////////////////////////////////////////////////////////////////////////////
// Thread Pool

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

// Argument for the dataplane thread (plugin-independent)
struct nsn_dataplane_thread_args
{
    atu32              state;
    string_t           datapath_name;
    nsn_plugin_t      *plugin_data;
    int                max_tx_burst;
    int                max_rx_burst;
    nsn_cnd_t          cv;
    nsn_mutex_t        lock;
    bool               dp_ready;
};

typedef struct nsn_thread_pool nsn_thread_pool_t;
struct nsn_thread_pool
{
    nsn_os_thread_t *threads;
    struct nsn_dataplane_thread_args *thread_args;
    usize            count;
};


////////////////////////////////////////////////////////////////////////////////
// @Globals
static i64 cpu_hz = -1;

int instance_id               = 0;
mem_arena_t *state_arena      = NULL;
nsn_app_pool_t app_pool       = {0};
nsn_plugin_set_t plugin_set   = {0};
nsn_thread_pool_t thread_pool = {0};

string_list_t arg_list = {0};
nsn_cfg_t *config      = NULL;

static volatile bool g_running = true;

void 
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        g_running = false;
    }
}

// --- Datapath helpers -----------------------------------------------------

// From the config, retrieve the IP addresses of the peers for the plugin "datapath_name", 
// returning their number and the list of IPs in the "peer_list" buffer.
static u16 
get_peers_ip_list(
    nsn_cfg_t *config, char *datapath_ip_key, char **peer_list, 
    u16 max_peers, temp_mem_arena_t* arena
) {
    list_head(options);
    int n = nsn_config_get_string_list_from_subsections(arena->arena, config, str_lit("peers"), str_cstr(datapath_ip_key), &options);
    if (n < 0) {
        log_warn("No peers found for plugin %s\n", datapath_ip_key);
        return 0;
    }

    // Copy the options (strings) into the provided array
    nsn_cfg_opt_t *cur_opt = NULL;
    u16 i = 0;
    list_for_each_entry(cur_opt, &options, list) {
        if (i >= max_peers) {
            break;
        }
        strncpy(peer_list[i], (char*)cur_opt->string.data, cur_opt->string.len);
        peer_list[i][cur_opt->string.len] = '\0';
        log_debug("detected peer with IP %s\n", peer_list[i], datapath_ip_key);
        i++;
    }
    nsn_config_free_param_list(&options, arena->arena);

    return (u16)n;
}

// When calling this function, we must hold the lock on the streams list
static void 
prepare_ep_list(list_head_t* ep_list, nsn_plugin_t *plugin, temp_mem_arena_t* data_arena) 
{
    nsn_inner_stream_t *stream = NULL;
    ep_initializer_t *ep_el    = NULL;
    list_for_each_entry(stream, &plugin->streams, node) {
        ep_el     = mem_arena_push(data_arena->arena, sizeof(ep_initializer_t));
        ep_el->ep = &stream->ep;
        list_add_tail(ep_list, &ep_el->node);
    }
}

// When calling this function, we must hold the lock on the streams list
static void 
clean_ep_list(list_head_t *ep_list, temp_mem_arena_t* data_arena) 
{
    ep_initializer_t *ep_el = NULL;
    while(!list_empty(ep_list)) {
        ep_el                  = list_last_entry(ep_list, ep_initializer_t, node);
        ep_el->node.prev->next = ep_el->node.next;
        list_del(&ep_el->node);
        mem_arena_pop(data_arena->arena, sizeof(ep_initializer_t));
    }
}

// --- Datapath thread -----------------------------------------------------
void *
dataplane_thread_proc(void *arg)
{
    struct nsn_dataplane_thread_args *args = (struct nsn_dataplane_thread_args *)arg;

    nsn_thread_ctx_t this_thread = nsn_thread_ctx_alloc();
    this_thread.is_main_thread   = false;
    nsn_thread_set_ctx(&this_thread);

    int self = nsn_os_current_thread_id();
    nsn_unused(self);

    size_t ip_str_size = 16;
    char string_buf[ip_str_size*4];
    
    u32 state = NSN_DATAPLANE_THREAD_STATE_WAIT;
wait: 
    log_debug("[thread %d] waiting for a message\n", self);
    while ((state = at_load(&args->state, mo_rlx)) == NSN_DATAPLANE_THREAD_STATE_WAIT) {
        usleep(10);
    } 

    if (state == NSN_DATAPLANE_THREAD_STATE_STOP) {
        log_debug("[thread %d] stopping\n", self);
        return NULL;
    }

    // Init temp arena
    temp_mem_arena_t data_arena = nsn_thread_scratch_begin(NULL, 0);

    // Load the datapath plugin
    log_debug("[thread %d] dataplane thread started for datapath: " str_fmt "\n", 
              self, str_varg(args->datapath_name));                 

    string_t datapath_name = args->datapath_name;
    nsn_plugin_t *plugin   = args->plugin_data;
    char datapath_lib[256];
    snprintf(datapath_lib, sizeof(datapath_lib), "./datapaths/lib%s.so", to_cstr(datapath_name));
    struct nsn_os_module module = nsn_os_load_library(datapath_lib, NsnOsLibraryFlag_Now);
    if (module.handle == NULL) {
        log_error("[thread %d] Failed to load library %s: %s\n", self, datapath_lib, dlerror());
        goto quit;
    }

    char fn_name[256];

    struct datapath_ops ops;
    memory_zero_struct(&ops);
    snprintf(fn_name, sizeof(fn_name), "%s_datapath_init", to_cstr(datapath_name));
    ops.init   = (nsn_datapath_init*)nsn_os_get_proc_address(module, fn_name);
    snprintf(fn_name, sizeof(fn_name), "%s_datapath_conn_manager", to_cstr(datapath_name));
    ops.conn_manager = (nsn_datapath_conn_manager*)nsn_os_get_proc_address(module, fn_name);
    snprintf(fn_name, sizeof(fn_name), "%s_datapath_update", to_cstr(datapath_name));
    ops.update = (nsn_datapath_update*)nsn_os_get_proc_address(module, fn_name);
    snprintf(fn_name, sizeof(fn_name), "%s_datapath_tx", to_cstr(datapath_name));
    ops.tx     = (nsn_datapath_tx*)nsn_os_get_proc_address(module, fn_name);
    snprintf(fn_name, sizeof(fn_name), "%s_datapath_rx", to_cstr(datapath_name));
    ops.rx     = (nsn_datapath_rx*)nsn_os_get_proc_address(module, fn_name);
    snprintf(fn_name, sizeof(fn_name), "%s_datapath_deinit", to_cstr(datapath_name));
    ops.deinit = (nsn_datapath_deinit*)nsn_os_get_proc_address(module, fn_name);

    // Prepare the arguments to initialize the plugin
    // 1a) Create the plugin context
    nsn_datapath_ctx_t ctx;
    memory_zero_struct(&ctx);

    // 1b) Retrieve the parameters passed to the plugin in the config file
    bzero(string_buf, ip_str_size*4);
    sprintf(string_buf, "plugins.%s", to_cstr(datapath_name));
    ctx.params = list_head_init(ctx.params);
    nsn_config_get_param_list(config, str_cstr(string_buf), &ctx.params, data_arena.arena);
    
    ctx.max_tx_burst = args->max_tx_burst;
    ctx.max_rx_burst = args->max_rx_burst;

    // 1c) Retrieve the list of peer's IPs for this plugin from the config file
    bzero(string_buf, ip_str_size*4);
    sprintf(string_buf, "%s_ip", to_cstr(datapath_name));
    char** peer_list = mem_arena_push(data_arena.arena, sizeof(char*) * app_pool.count);
    for(u32 i = 0; i < app_pool.count; i++) {
        peer_list[i] = mem_arena_push(data_arena.arena, ip_str_size);
    }
    ctx.n_peers = get_peers_ip_list(config, string_buf, peer_list, app_pool.count, &data_arena);
    ctx.peers = peer_list;

    // Save a pointer to the CP functions in the plugin descriptor
    plugin->conn_manager = ops.conn_manager;
    plugin->update = ops.update;

    // 2) Initialize the plugin
    int ret;
    list_head(ep_list); 
    nsn_os_mutex_lock(&plugin->streams_lock);
    prepare_ep_list(&ep_list, plugin, &data_arena);
    nsn_os_mutex_unlock(&plugin->streams_lock);
    ret = ops.init(&ctx, &ep_list);
    clean_ep_list(&ep_list, &data_arena);
    if (ret < 0) {
        log_error("[thread %d] Failed to init plugin %s\n", self, to_cstr(datapath_name));
        at_store(&args->state, NSN_DATAPLANE_THREAD_STATE_WAIT, mo_rel);
        // Signal failure
        nsn_os_mutex_lock(&args->lock);
        nsn_os_cnd_signal(&args->cv);
        nsn_os_mutex_unlock(&args->lock);
        goto unload_and_clean;
    }

    // Signal that the datapath is ready
    nsn_os_mutex_lock(&args->lock);
    args->dp_ready = true;
    nsn_os_cnd_signal(&args->cv);
    nsn_os_mutex_unlock(&args->lock);

    // 3) Start the dataplane loop
    nsn_inner_stream_t *stream;
    while ((state = at_load(&args->state, mo_rlx)) == NSN_DATAPLANE_THREAD_STATE_RUNNING) {
        // TODO: dpdk example, in the final code the string "dpdk" should be replaced by the name of the datapath
        // and has to be done in a parameterized way. 

        // IOBUFS are freed: (a) by the plugin after TX; (b) by the app after RX. No free is needed by the daemon.

        // TX routine
        nsn_buf_t io_indexes[ctx.max_tx_burst];
        uint32_t nbufs = 0;
        int tx_count;
        nsn_os_mutex_lock(&plugin->streams_lock);
        list_for_each_entry(stream, &plugin->streams, node) {
            if (!at_load(&stream->n_srcs, mo_rlx)) {
                continue;
            }

            nbufs = 0;

            // 1a. Dequeue the io_bufs indexes from the pending (retry send) ring
            nbufs = nsn_ringbuf_dequeue_burst(stream->tx_pending,
                                io_indexes, sizeof(io_indexes[0]),
                                ctx.max_tx_burst, NULL);

            // 1b. Dequeue the io_bufs indexes from the tx_prod ring
            if (nbufs == 0) {
                nbufs = nsn_ringbuf_dequeue_burst(stream->tx_prod,
                                    io_indexes, sizeof(io_indexes[0]),
                                    ctx.max_tx_burst, NULL);
            }

            // 2. Call the tx function of the datapath
            if(nbufs > 0) {
                tx_count = ops.tx(io_indexes, nbufs, &stream->ep);
                if (tx_count < 0) {
                    log_error("[thread %d] Failed to transmit\n");
                } else if ((uint32_t)tx_count < nbufs) {
                    log_trace("[thread %d] Enqueueing %d packets to retry\n", self, nbufs - tx_count);
                    nsn_ringbuf_enqueue_burst(stream->tx_pending, 
                                &io_indexes[tx_count], sizeof(io_indexes[0]), 
                                nbufs - tx_count, NULL);
                }
            }
        }

        // RX routine
        list_for_each_entry(stream, &plugin->streams, node) {
            if (at_load(&stream->n_sinks, mo_rlx) == 0) {
                continue;
            }

            // 1. Rx from the plugin
            nsn_buf_t io_buffs[ctx.max_rx_burst];
            usize io_max = ctx.max_rx_burst;        
            usize np_rx = ops.rx(io_buffs, &io_max, &stream->ep);
            
            // 2. Dispatch the packets to the sinks
            bool delivered;
            for(uint32_t j = 0; j < np_rx; j++) {
                uint8_t* data = (uint8_t*)(stream->ep.tx_zone + 1) + (io_buffs[j].index * stream->ep.io_bufs_size);
                nsn_hdr_t *hdr = (nsn_hdr_t *)data;
                nsn_inner_sink_t* sink;
                delivered = false;
                nsn_os_mutex_lock(&stream->sinks_lock);
                list_for_each_entry(sink, &stream->sinks, node) {
                    if (sink->sink_id == hdr->channel_id) {
                        log_trace("pkt received on channel %u\n", hdr->channel_id);
                        if (nsn_ringbuf_enqueue_burst(sink->rx_cons, &io_buffs[j].index, sizeof(io_buffs[j].index), 1, NULL) == 0) {
                            log_error("[thread %d] Failed to enqueue pkt to sink\n", self);
                        }
                        delivered = true;
                        break;
                    }
                }
                nsn_os_mutex_unlock(&stream->sinks_lock);
                if(!delivered) {
                    log_warn("No sink found for channel %u\n", hdr->channel_id);
                }
            }
        }
        nsn_os_mutex_unlock(&plugin->streams_lock);
    }

    log_debug("[thread %d] deinit\n", self);
    nsn_os_mutex_lock(&plugin->streams_lock);
    prepare_ep_list(&ep_list, plugin, &data_arena);
    nsn_os_mutex_unlock(&plugin->streams_lock);
    if (ops.deinit(NULL, &ep_list)) {
        log_error("[thread %d] Failed to deinit\n", self);
    }
    clean_ep_list(&ep_list, &data_arena);

unload_and_clean:
    log_debug("[thread %d] unloading library\n", self);
    nsn_os_unload_library(module);

    plugin->update = NULL;
    plugin->conn_manager = NULL;
    
    mem_arena_pop(data_arena.arena, ip_str_size*app_pool.count); // peers' IPs
    mem_arena_pop(data_arena.arena, sizeof(peer_list) * app_pool.count); // array of peers' IPs

    // Free the param list
    nsn_config_free_param_list(&ctx.params, data_arena.arena);

    // Clean arena
    nsn_thread_scratch_end(data_arena);

    state = at_load(&args->state, mo_rlx);
    log_debug("[thread %d] state: %s (%d)\n", self, nsn_dataplane_thread_state_str[state], state);

    nsn_os_mutex_lock(&args->lock);
    args->dp_ready = false;
    nsn_os_cnd_signal(&args->cv);
    nsn_os_mutex_unlock(&args->lock);

    if (state == NSN_DATAPLANE_THREAD_STATE_WAIT)
    {
        log_debug("[thread %d] moving to wait state\n", self);
        goto wait;
    }

quit:
    log_info("[thread %d] done\n", self);
    return NULL;
}

// --- QoS Mapping ---------------------------------------------------------
uint32_t nsn_qos_to_plugin_idx(nsn_options_t qos)
{
    log_warn("QoS mapping not completely implemented\n");
    

    // TODO: We need to list the available plugins. Then implement the
    // algorithm described in the paper to find the plugin to match. If 
    // it does not exist, fallback to another.

    // Return the index of the selected plugin!
    if (qos.datapath == NSN_QOS_DATAPATH_FAST) {
        if (qos.reliability == NSN_QOS_RELIABILITY_RELIABLE) {
            log_info("QOS: fast, reliable => selected DPDK TCP plugin\n");
            return 3;
        } else {
            log_info("QOS: fast, unreliable => selected DPDK UDP plugin\n");
            return 2;
        }
    } 

    if (qos.reliability == NSN_QOS_RELIABILITY_RELIABLE) {
            log_info("QOS: default, reliable => selected kernel TCP plugin\n");
            return 1;
        } else {
            log_info("QOS: default, unreliable => selected kernel UDP plugin\n");
            return 0;
    }
    
}

// --- Helper Functions ---------------------------------------------------------
// Helps creating a source/sink. If necessary, it starts a new thread for the dataplane.
// Returns 0 on success, -1 on error.
typedef enum nsn_channel_type {
    NSN_CHANNEL_TYPE_SOURCE,
    NSN_CHANNEL_TYPE_SINK,
} nsn_channel_type_t;

int
ipc_create_channel(int app_id, nsn_cmsg_hdr_t *cmsghdr, nsn_channel_type_t type) 
{
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
        return -1;
    }

    // Find the (valid) plugin
    nsn_cmsg_create_source_t *reply = (nsn_cmsg_create_source_t *)(cmsghdr + 1);
    uint32_t plugin_idx = reply->plugin_idx;
    if (plugin_idx >= plugin_set.count) {
        log_error("plugin index %d is out of bound\n");
        return -2;
    }
    nsn_plugin_t *plugin = &plugin_set.plugins[plugin_idx];

    // Find the (valid) stream
    uint32_t stream_idx = (uint32_t)reply->stream_idx;
    nsn_inner_stream_t *stream;
    list_for_each_entry(stream, &plugin->streams, node) {
        if (stream->idx == stream_idx) {
            break;
        }
    }
    if (!stream) {
        log_error("stream %d not found in the plugin\n", stream_idx);
        return -3;
    }

    // If sink, create the descriptor and the ring. Here, because if it fails, it has no other side effect.
    if(type == NSN_CHANNEL_TYPE_SINK) {
        nsn_cmsg_create_sink_t *reply_snk = (nsn_cmsg_create_sink_t *)(cmsghdr + 1);

        // Create the ring
        snprintf(reply_snk->rx_cons, NSN_CFG_RINGBUF_MAX_NAME_SIZE, "rx_cons_%u_%u", (u32)reply_snk->stream_idx, (u32)reply_snk->sink_id);
        nsn_ringbuf_pool_t *ring_pool = nsn_memory_manager_get_ringbuf_pool(app_pool.apps[app_idx].mem);
        nsn_ringbuf_t *rx_cons_ring = nsn_memory_manager_create_ringbuf(ring_pool, str_cstr(reply_snk->rx_cons));
        if (!rx_cons_ring) {
            log_error("Failed to create the rx_cons ring\n", rx_cons_ring);
            return -3;
        }

        // Create the sink descriptor
        nsn_inner_sink_t *sink = malloc(sizeof(nsn_inner_sink_t));
        sink->rx_cons = rx_cons_ring;
        sink->sink_id = (u32)reply_snk->sink_id; // TODO: Check that sink id is free

        // Add the sink to the stream
        nsn_os_mutex_lock(&stream->sinks_lock);
        list_add_tail(&stream->sinks, &sink->node);
        nsn_os_mutex_unlock(&stream->sinks_lock);
    } else {
        // Create the source descriptor
        nsn_inner_source_t *source = malloc(sizeof(nsn_inner_source_t));
        source->src_id = reply->source_id; // TODO: Check that src id is free

        // no lock: we keep sources only to guarantee their uniqueness, not to share them.
        list_add_tail(&stream->sources, &source->node);
    }
    
    // if this is the first src/snk (=channel) in the PLUGIN, start the first 
    // data plane thread. In the future, this will be delegated to a thread pool manager.
    // This will also automatically create the network state for all the streams.
    if (plugin->active_channels == 0) {
        // Currently, we just consider that thread j is assigned to plugin j.
        uint32_t thread_idx = plugin_idx;
        struct nsn_dataplane_thread_args *dp_args = &thread_pool.thread_args[thread_idx];
        // It might be the case that the thread is already associated with the plugin,
        // until we implement a thread pool manager. In this case, no need to add a 
        // thread to the plugin; just start the existing one.
        if (plugin->thread_count == 0) {
            // Keep a pointer to the thread in the plugin
            plugin->threads[plugin->thread_count] = thread_pool.threads[thread_idx];
            plugin->thread_count++;
            // Assign the plugin to the thread
            dp_args->datapath_name = plugin->name;
            dp_args->plugin_data   = plugin;
        }
        // start the thread
        at_store(&dp_args->state, NSN_DATAPLANE_THREAD_STATE_RUNNING, mo_rlx);
        // wait for the initialization to complete
        nsn_os_mutex_lock(&dp_args->lock);
        while (!dp_args->dp_ready) {
            log_debug("Retry for the dataplane thread to be ready\n");
            nsn_os_cnd_wait(&dp_args->cv, &dp_args->lock);
        }
        nsn_os_mutex_unlock(&dp_args->lock);
    } 
    // If the PLUGIN is running, but this is the first channel in the STREAM,
    // we must tell the PLUGIN to update the STREAM state.
    else if (!stream->ep.data) {
        // This creates a connection/initializes network state!
        // IT MUST BE DONE *BEFORE* UPDATING N_SRC/N_SINKS and N_ACTIVE_CHANNELS
        assert(plugin->update && !stream->ep.data);
        plugin->update(&stream->ep);
        log_debug("Updated DP: new active channel for stream %u\n", stream_idx);
    }

    // Update the number of srcs/sinks in the plugin and stream
    // This will make the datapath aware of the new channel.
    ++plugin->active_channels;
    if(type == NSN_CHANNEL_TYPE_SINK) {
        atomic_fetch_add(&stream->n_sinks, 1);
    } else {
        atomic_fetch_add(&stream->n_srcs, 1);
    }

    return 0;
}

// Helps destroying a source/sink. If necessary, it stops the thread for the dataplane.
// Returns 0 on success, -1 on error.
int
ipc_destroy_channel(int app_id, nsn_cmsg_hdr_t *cmsghdr, nsn_channel_type_t type) {
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
        return 1;
    }

    // Check plugin id and retrieve the plugin
    nsn_cmsg_create_source_t *reply = (nsn_cmsg_create_source_t *)(cmsghdr + 1);
    uint32_t plugin_idx = reply->plugin_idx;
    if (plugin_idx >= plugin_set.count) {
        log_error("plugin index is out of bound\n");
        return 2;
    } 
    nsn_plugin_t *plugin = &plugin_set.plugins[plugin_idx];
    
    // Check stream id and retrieve the stream
    uint32_t stream_idx = (uint32_t)reply->stream_idx;
    nsn_inner_stream_t *stream;
    nsn_os_mutex_lock(&plugin->streams_lock);
    list_for_each_entry(stream, &plugin->streams, node) {
        if (stream->idx == stream_idx) {
            break;
        }
    }
    nsn_os_mutex_unlock(&plugin->streams_lock);
    if (!stream) {
        log_error("stream %d not found in the plugin\n", stream_idx);
        return 3;
    }

    if (type == NSN_CHANNEL_TYPE_SINK) {
        nsn_inner_sink_t *sink, *dead_sink = NULL;
        nsn_os_mutex_lock(&stream->sinks_lock);
        if (list_empty(&stream->sinks)) {
            nsn_os_mutex_unlock(&stream->sinks_lock);
            log_warn("no sinks in the stream\n");
            return 4;
        }
        list_for_each_entry(sink, &stream->sinks, node) {
            if(sink->sink_id == ((nsn_cmsg_create_sink_t *)(cmsghdr + 1))->sink_id) {
                // Ref count of the channels (src/snk) active in the stream
                --plugin->active_channels;
                // Update the number of sinks in the stream: stop receiving if this was the last one
                atomic_fetch_sub(&stream->n_sinks, 1);
                // Remove the sink from the list
                list_del(&sink->node);
                dead_sink = sink;
                break;
            }
        }
        nsn_os_mutex_unlock(&stream->sinks_lock);
        if(!dead_sink) {
            log_error("sink %d not found in the stream\n", ((nsn_cmsg_create_sink_t *)(cmsghdr + 1))->sink_id);
            return 4;
        }     
        
        // Free the ring buffer
        nsn_ringbuf_pool_t *ring_pool = nsn_memory_manager_get_ringbuf_pool(app_pool.apps[app_idx].mem);
        int err = nsn_memory_manager_destroy_ringbuf(ring_pool, str_cstr(dead_sink->rx_cons->name));
        if (err < 0) {
            log_error("Failed to destroy the rx_cons ring\n");
            return 5;
        }

        // Destroy the sink
        free(dead_sink);
    } else {        
        // Ensure we are not leaving packets unsent (this was the last channel and the ring will be destroyed)
        u32 nb_pk = 0;
        if(plugin->active_channels - 1 == 0 && (
                   (nb_pk = nsn_ringbuf_count(stream->tx_prod)) > 0
                || (nb_pk = nsn_ringbuf_count(stream->tx_pending)) > 0)) {
            // The caller will try again later
            log_trace("destroy last src detected %u pending packets: retry\n", nb_pk);
            return EAGAIN;
        }

        nsn_inner_source_t *src, *dead_src = NULL;
        if (list_empty(&stream->sources)) {
            log_warn("no sources in the stream\n");
            return 6;
        }
        list_for_each_entry(src, &stream->sources, node) {
            if(src->src_id == ((nsn_cmsg_create_source_t *)(cmsghdr + 1))->source_id) {
                // Ref count of the channels (src/snk) active in the stream
                --plugin->active_channels;
                // Update the number of srcs in the stream: stop sending if this was the last one
                atomic_fetch_sub(&stream->n_srcs, 1);
                // Remove the sink from the list
                list_del(&src->node);
                dead_src = src;
                break;
            }
        }
        if(!dead_src) {
            log_error("source %d not found in the stream\n", ((nsn_cmsg_create_source_t *)(cmsghdr + 1))->source_id);
            return 7;
        }     
        
        // Destroy the src
        free(src);
    }
   
    // if the stream has no more active channels, stop the data plane thread 
    // (which remains attached to the plugin, until we implement a thread pool manager)
    // (ideally, the thread should go back into the pool)
    // Currently, we just consider that thread j is assigned to plugin j.
    uint32_t thread_idx = plugin_idx;
    struct nsn_dataplane_thread_args *dp_args = &thread_pool.thread_args[thread_idx];
    if(!plugin->active_channels) {
        // pause the dp thread
        at_store(&dp_args->state, NSN_DATAPLANE_THREAD_STATE_WAIT, mo_rlx);
        // wait for the thread to switch to the wait state
        nsn_os_mutex_lock(&dp_args->lock);
        while (dp_args->dp_ready) {
            nsn_os_cnd_wait(&dp_args->cv, &dp_args->lock);
        }
        nsn_os_mutex_unlock(&dp_args->lock);
    } 
    // In case the plugin is still running but this stream has no more active channels,
    // we must tell the plugin to delete the stream state
    else if(!at_load(&stream->n_sinks, mo_rlx) && !at_load(&stream->n_srcs, mo_rlx)) {
        // This destroys the connection/cleans the network state!
        // IT MUST BE DONE *AFTER* UPDATING N_SRC/N_SINKS
        assert(plugin->update && stream->ep.data);
        log_debug("Updated DP: no active channels for stream %u\n", stream_idx);
        plugin->update(&stream->ep);
        stream->ep.data = NULL;
    }

    return 0;
}

////////////////////////////////////////////////////////////////////////////////
// IPC thread
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
            log_debug("error: %s\n", strerror(errno));
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
                log_info("app %d connected\n", app_id);

                // Complete the reply
                cmsghdr->type             = NSN_CMSG_TYPE_CONNECTED;
                nsn_cmsg_connect_t *reply = (nsn_cmsg_connect_t *)(cmsghdr + 1);
                reply->shm_size           = mem_cfg.shm_size;
                reply->io_buf_size        = mem_cfg.io_buffer_size;
                strcpy(reply->free_slots_ring, NSN_CFG_DEFAULT_FREE_SLOTS_RING_NAME);
                snprintf(reply->shm_name, NSN_SHM_NAME_MAX, "nsnd_datamem_%d", app_id);
                
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
            log_trace("received new stream message from app %d\n", app_id);
            
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


            // QoS-to-plugin mapping
            nsn_cmsg_create_stream_t *msg = (nsn_cmsg_create_stream_t*)(cmsghdr + 1);
            uint32_t plugin_idx = nsn_qos_to_plugin_idx(msg->opts);
            if (plugin_idx == NSN_INVALID_PLUGIN_HANDLE) {
                log_error("no plugin found for QoS %d\n", msg->opts);
                cmsghdr->type = NSN_CMSG_TYPE_ERROR;
                int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                *error_code     = 3;
                reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
                break;
            }
            nsn_plugin_t *plugin = &plugin_set.plugins[plugin_idx];

            // Create the stream descriptor
            nsn_inner_stream_t *stream = malloc(sizeof(nsn_inner_stream_t));
            stream->plugin_idx = plugin_idx;
            stream->idx = plugin->stream_id_cnt++;
            atomic_store(&stream->n_srcs, 0);
            stream->sources = list_head_init(stream->sources);
            atomic_store(&stream->n_sinks, 0);
            stream->sinks = list_head_init(stream->sinks);
            nsn_os_mutex_init(&stream->sinks_lock);

            // Set the index of the plugin and stream in the reply
            uint32_t stream_idx = stream->idx;
            nsn_cmsg_create_stream_t *reply = (nsn_cmsg_create_stream_t*)(cmsghdr + 1);
            reply->plugin_idx = plugin_idx;
            reply->stream_idx = stream_idx;

            // Create the tx ring buffer. The "consumer" and "producer" definitions are relative to the application.
            // The tx_cons and the rx_prod are the same ring, the free_slots ring, which is already available to the app.
            // The rx_cons is created at sink creation, allowing each sink to receive incoming data from the plugin.
            // The tx_prod is created here for this plugin, allowing all the sources to send data to the plugin.
            snprintf(reply->tx_prod, NSN_CFG_RINGBUF_MAX_NAME_SIZE, "tx_prod_%u", stream_idx);            
            nsn_ringbuf_pool_t *ring_pool = nsn_memory_manager_get_ringbuf_pool(app_pool.apps[app_idx].mem);
            nsn_ringbuf_t *tx_prod_ring = nsn_memory_manager_create_ringbuf(ring_pool, str_cstr(reply->tx_prod));
            if (!tx_prod_ring) {
                log_error("Failed to create the tx_prod ring\n", tx_prod_ring);
                // clean the stream
                free(stream);
                // return error message
                cmsghdr->type = NSN_CMSG_TYPE_ERROR;
                int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                *error_code     = 5;
                reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
                break;
            }
            // Associate the tx ring with the plugin
            stream->tx_prod = tx_prod_ring;

            // Create the tx pending ring buffer. The size must be the max_tx_burst configured in the datapath: in the
            // worst case, we need to retransmit all the packets we tried to send. We will always check here first. But 
            // because the ring size is fixed for the pool, and it is not worth to create a new pool for "small rings" yet,
            // we will just use the default size for now.
            char tx_pending_ring_name[NSN_CFG_RINGBUF_MAX_NAME_SIZE];
            snprintf(tx_pending_ring_name, NSN_CFG_RINGBUF_MAX_NAME_SIZE, "tx_pending_%u", stream_idx);      
            nsn_ringbuf_t *tx_pending_ring = nsn_memory_manager_create_ringbuf(ring_pool, str_cstr(tx_pending_ring_name));
            if (!tx_pending_ring) {
                log_error("Failed to create the tx_pending ring\n", tx_pending_ring);
                // destroy the tx_prod ring
                nsn_memory_manager_destroy_ringbuf(ring_pool, str_cstr(reply->tx_prod));
                // clean the stream
                free(stream);
                // return error message
                cmsghdr->type = NSN_CMSG_TYPE_ERROR;
                int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                *error_code     = 6;
                reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
                break;
            }
            // Associate the tx pending ring with the plugin
            stream->tx_pending = tx_pending_ring;

            // Prepare the endpoint
            stream->ep.app_id = app_id;
            stream->ep.free_slots = nsn_memory_manager_lookup_ringbuf(app_pool.apps[app_idx].mem, str_lit(NSN_CFG_DEFAULT_FREE_SLOTS_RING_NAME));
            stream->ep.tx_zone = nsn_find_zone_by_name(app_pool.apps[app_idx].mem->zones, str_lit(NSN_CFG_DEFAULT_TX_IO_BUFS_NAME));
            stream->ep.tx_meta_zone = nsn_find_zone_by_name(app_pool.apps[app_idx].mem->zones, str_lit(NSN_CFG_DEFAULT_TX_META_NAME));
            stream->ep.io_bufs_size = mem_cfg.io_buffer_size;            
            stream->ep.io_bufs_count = mem_cfg.io_buffer_pool_size;
            stream->ep.page_size = (1ULL << 21); //2MB TODO: This must become a nsnd param, used also for alloc.
            
            // Add the stream to the plugin
            nsn_os_mutex_lock(&plugin->streams_lock);
            list_add_tail(&plugin->streams, &stream->node);
            nsn_os_mutex_unlock(&plugin->streams_lock);

            // Successful operation: return success
            cmsghdr->type = NAN_CSMG_TYPE_CREATED_STREAM;
            reply_len = sizeof(nsn_cmsg_hdr_t) + sizeof(nsn_cmsg_create_stream_t);
            log_info("[plugin %u] new stream created for app %d\n", plugin_idx, stream_idx, app_id);

        } break;
        case NSN_CMSG_TYPE_DESTROY_STREAM:
        {
            log_trace("received destroy stream message from app %d\n", app_id);

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
                *error_code     = 1;
                reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
                break;
            }

            nsn_cmsg_create_stream_t *reply = (nsn_cmsg_create_stream_t *)(cmsghdr + 1);
            uint32_t plugin_idx = (uint32_t)reply->plugin_idx;
            uint32_t stream_idx = (uint32_t)reply->stream_idx;

            // Check that the plugin index is valid
            if (plugin_idx >= plugin_set.count) {
                log_error("plugin index %d is out of bounds\n", stream_idx);
                cmsghdr->type = NSN_CMSG_TYPE_ERROR;
                int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                *error_code     = 2;
                reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
                break;
            }

            // Check that the stream index is valid
            nsn_plugin_t *plugin = &plugin_set.plugins[plugin_idx];
            nsn_inner_stream_t *stream;
            list_for_each_entry(stream, &plugin->streams, node) {
                if (stream->idx == stream_idx) {
                    break;
                }
            }
            if (!stream) {
                log_error("stream %d not found in the plugin\n", stream_idx);
                cmsghdr->type = NSN_CMSG_TYPE_ERROR;
                int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                *error_code     = 3;
                reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
                break;
            }

            // check that no channel is active for this stream
            u32 n_sinks = at_load(&stream->n_sinks, mo_rlx);
            u32 n_srcs  = at_load(&stream->n_srcs, mo_rlx);
            if (n_sinks > 0 || n_srcs > 0) {
                log_error("stream %d has active channels (src/snk)\n", stream_idx);
                cmsghdr->type = NSN_CMSG_TYPE_ERROR;
                int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                *error_code     = 4;
                reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
                break;
            }

            // 3) [Future Work] Detach the thread(s) associated with this stream. Here, or proactively at channel destruction.

            // 4) destroy the tx_prod ring
            nsn_ringbuf_pool_t *ring_pool = nsn_memory_manager_get_ringbuf_pool(app_pool.apps[app_idx].mem);
            char ring_name[NSN_CFG_RINGBUF_MAX_NAME_SIZE];
            snprintf(ring_name, NSN_CFG_RINGBUF_MAX_NAME_SIZE, "tx_prod_%u", stream_idx);
            int err = nsn_memory_manager_destroy_ringbuf(ring_pool, str_cstr(ring_name));
            if (err < 0) {
                log_error("Failed to destroy the tx_prod ring\n");
                cmsghdr->type = NSN_CMSG_TYPE_ERROR;
                int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                *error_code     = 5;
                reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
                break;
            }

            // 5) destroy the tx_pending ring
            snprintf(ring_name, NSN_CFG_RINGBUF_MAX_NAME_SIZE, "tx_pending_%u", stream_idx);
            err = nsn_memory_manager_destroy_ringbuf(ring_pool, str_cstr(ring_name));
            if (err < 0) {
                log_error("Failed to destroy the tx_pending ring\n");
                cmsghdr->type = NSN_CMSG_TYPE_ERROR;
                int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                *error_code     = 6;
                reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
                break;
            }
            
            // Finalize the destruction of the stream
            nsn_os_mutex_lock(&plugin->streams_lock);
            list_del(&stream->node);
            nsn_os_mutex_unlock(&plugin->streams_lock);
            free(stream);

            // Return success
            cmsghdr->type = NSN_CMSG_TYPE_DESTROYED_STREAM;
            reply_len = sizeof(nsn_cmsg_hdr_t);
            log_info("stream %u destroyed for app %d\n", stream_idx, app_id);

        } break;
        case NSN_CMSG_TYPE_CREATE_SOURCE:
        {
            log_trace("received new source message from app %d\n", app_id);
           
            int err = 0;
            if ((err = ipc_create_channel(app_id, cmsghdr, NSN_CHANNEL_TYPE_SOURCE)) != 0) {
                cmsghdr->type = NSN_CMSG_TYPE_ERROR;
                int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                *error_code     = -err;
                reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
                break;
            }

            // finalize the answer
            cmsghdr->type = NSN_CMSG_TYPE_CREATED_SOURCE;
            reply_len = sizeof(nsn_cmsg_hdr_t) + sizeof(nsn_cmsg_create_source_t);
            log_info("new source created for app %d\n", app_id);
        } break;
        case NSN_CMSG_TYPE_DESTROY_SOURCE: 
        {
            log_trace("received destroy source message from app %d\n", app_id);

            int err = 0;
            if ((err = ipc_destroy_channel(app_id, cmsghdr, NSN_CHANNEL_TYPE_SOURCE)) != 0) {
                cmsghdr->type = NSN_CMSG_TYPE_ERROR;
                int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                *error_code     = -err;
                reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
                break;
            }

            reply_len = sizeof(nsn_cmsg_hdr_t);
            log_info("source destroyed for app %d\n", app_id);

        } break;
        case NSN_CMSG_TYPE_CREATE_SINK:
        {
            log_trace("received new sink message from app %d\n", app_id);

            int err = 0;
            if ((err = ipc_create_channel(app_id, cmsghdr, NSN_CHANNEL_TYPE_SINK)) != 0) {
                cmsghdr->type = NSN_CMSG_TYPE_ERROR;
                int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                *error_code     = -err;
                reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
                break;
            }

            // finalize the answer
            cmsghdr->type = NSN_CMSG_TYPE_CREATED_SINK;
            reply_len = sizeof(nsn_cmsg_hdr_t) + sizeof(nsn_cmsg_create_sink_t);
            log_info("new sink created for app %d\n", app_id);

        } break;
        case NSN_CMSG_TYPE_DESTROY_SINK:
        {
            log_trace("received destroy sink message from app %d\n", app_id);
            
            // destroy the channel and its side effects
            int err = 0;
            if ((err = ipc_destroy_channel(app_id, cmsghdr, NSN_CHANNEL_TYPE_SINK)) != 0) {
                cmsghdr->type = NSN_CMSG_TYPE_ERROR;
                int *error_code = (int *)(buffer + sizeof(nsn_cmsg_hdr_t));
                *error_code     = -err;
                reply_len       = sizeof(nsn_cmsg_hdr_t) + sizeof(int);
                break;
            }

            reply_len = sizeof(nsn_cmsg_hdr_t);
            log_info("sink destroyed for app %d\n", app_id);

        } break;
        case NSN_CMSG_TYPE_DISCONNECT:
        {
            log_trace("received disconnect message from app %d\n", app_id);

            // check if the app is in the pool
            bool found = false;
            for (usize i = 0; i < app_pool.count; i++) {
                if (app_pool.apps[i].app_id == app_id) {
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
                log_info("app %d disconnected\n", app_id);
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

    if (send_reply) {  
        if (sendto(sockfd, cmsghdr, reply_len, 0, (struct sockaddr *)&temp_addr, temp_len) < 0) {
            log_error("error sending reply to app %d (%s): %s\n", app_id, temp_addr.sun_path, strerror(errno));
        }
    }   

clean_and_next: 
    nsn_thread_scratch_end(temp_arena);
    return res;
}

// -- Connection manager thread ------------------------------------------------

int
main_thread_connection_manager() 
{   
    temp_mem_arena_t data_arena = nsn_thread_scratch_begin(NULL, 0);

    for (usize i = 0; i < plugin_set.count; i++) 
    {
        nsn_plugin_t *plugin = &plugin_set.plugins[i];
        if(plugin->conn_manager) 
        {
            list_head(ep_list); 
            nsn_os_mutex_lock(&plugin->streams_lock);
            {
                // we might have waited on the lock, so we need to check again
                if(!plugin->conn_manager) {
                    nsn_os_mutex_unlock(&plugin->streams_lock);
                    continue;
                }
                
                prepare_ep_list(&ep_list, plugin, &data_arena);
            }
            nsn_os_mutex_unlock(&plugin->streams_lock);

            if(!list_empty(&ep_list)) {
                plugin->conn_manager(&ep_list);
            }

            clean_ep_list(&ep_list, &data_arena);
        }
    }

    nsn_thread_scratch_end(data_arena);

    return 0;
}

// --- Os Initialization ------------------------------------------------------

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

////////////////////////////////////////////////////////////////////////////////
// @EntryPoint
int 
main(int argc, char *argv[])
{
    nsn_unused(argc);
    nsn_unused(argv);

    nsn_thread_ctx_t main_thread = nsn_thread_ctx_alloc();
    main_thread.is_main_thread   = true;
    nsn_thread_set_ctx(&main_thread);

    instance_id = nsn_os_get_process_id();
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
 
 #ifdef NSN_ENABLE_LOGGER
    // Set the log level according to the config file
    logger_init(NULL);
    char config_log_level[32] = {0};
    string_t cfg_ll           = str_cstr(config_log_level);
    nsn_config_get_string(config, str_lit("global"), str_lit("log_level"), &cfg_ll);
    logger_set_level_by_name(to_cstr(cfg_ll));
#endif

    os_init();

    int app_num      = 64;
    int io_bufs_num  = NSN_CFG_DEFAULT_IO_BUFS_NUM;
    int io_bufs_size = NSN_CFG_DEFAULT_IO_BUFS_SIZE;   
    int shm_size     = NSN_CFG_DEFAULT_SHM_SIZE;
    int max_tx_burst = NSN_CFG_DEFAULT_MAX_TX_BURST;
    int max_rx_burst = NSN_CFG_DEFAULT_MAX_RX_BURST;
    
    nsn_config_get_int(config, str_lit("global"), str_lit("app_num"), &app_num);      
    nsn_config_get_int(config, str_lit("global"), str_lit("io_bufs_num"), &io_bufs_num);
    nsn_config_get_int(config, str_lit("global"), str_lit("io_bufs_size"), &io_bufs_size);
    nsn_config_get_int(config, str_lit("global"), str_lit("shm_size"), &shm_size);
    nsn_config_get_int(config, str_lit("global"), str_lit("max_tx_burst"), &max_tx_burst);
    nsn_config_get_int(config, str_lit("global"), str_lit("max_rx_burst"), &max_rx_burst);

    // TODO: Sanity check the configuration values!

    // init the memory arena
    mem_arena_t *arena = mem_arena_alloc(megabytes(1));
    app_pool.count           = app_num;
    app_pool.apps            = mem_arena_push_array(arena, nsn_app_t, app_pool.count);
    app_pool.free_apps_slots = mem_arena_push_array(arena, bool, app_pool.count);
    for (usize i = 0; i < app_pool.count; i++)    app_pool.free_apps_slots[i] = true;

    // TODO: Automatically detect which plugins are available and can be used by the daemon.
    char* plugin_set_names[] = {"udpsock", "tcpsock", "udpdpdk", "tcpdpdk"};
    plugin_set.count         = array_count(plugin_set_names);
    plugin_set.plugins       = mem_arena_push_array(arena, nsn_plugin_t, plugin_set.count);

    for (usize i = 0; i < plugin_set.count; i++) {
        nsn_plugin_t *plugin    = &plugin_set.plugins[i];
        plugin->name            = str_lit(plugin_set_names[i]);
        plugin->thread_count    = 0;
        plugin->threads         = mem_arena_push_array(arena, nsn_os_thread_t, NSN_CFG_DEFAULT_MAX_THREADS_PER_PLUGIN);
        plugin->active_channels = 0;
        plugin->streams         = list_head_init(plugin->streams);
        plugin->stream_id_cnt   = 0;
        nsn_os_mutex_init(&plugin->streams_lock);
    }

    // init SIG_INT handler
    {
        struct sigaction sa;
        memory_zero_struct(&sa);
        sa.sa_handler = signal_handler;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGINT, &sa, NULL);
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

    // --- Init the thread pool. Currently, one thread only. We DO NOT set here the dp_args.name, 
    // as the thread pool exists independently of the associated plugin. However, it is important that
    // the name is set when the thread moves to the RUNNING state, as it will try to load the dll.
    // The association is done when a new stream for a new plugin is set, and currently is permanent.
    // Future work will include a way to dynamically attach/detach threads to/from plugins.
    thread_pool.count       = plugin_set.count;
    thread_pool.threads     = mem_arena_push_array(arena, nsn_os_thread_t, thread_pool.count);
    thread_pool.thread_args = mem_arena_push_array(arena, struct nsn_dataplane_thread_args, 
                                                        thread_pool.count);
    for (usize i = 0; i < thread_pool.count; i++) {
        log_trace("creating thread %d\n", i);
        thread_pool.thread_args[i] = (struct nsn_dataplane_thread_args){ 
            .state = NSN_DATAPLANE_THREAD_STATE_WAIT,
            .dp_ready = false,
            .max_tx_burst = max_tx_burst,
            .max_rx_burst = max_rx_burst 
        };

        nsn_os_mutex_init(&thread_pool.thread_args[i].lock);
        nsn_os_cnd_init(&thread_pool.thread_args[i].cv);
        thread_pool.threads[i] = nsn_os_thread_create(dataplane_thread_proc, &thread_pool.thread_args[i]);

        if (thread_pool.threads[i].handle == 0) {
            log_error("Failed to create thread %d\n", i);
            goto clear_and_quit;
        }
    }

    // Create the shared memory and start the Control Path loop
    {
        nsn_mem_manager_cfg_t mem_cfg = {
            .shm_name            = str_lit(NSN_CFG_DEFAULT_SHM_NAME),
            .shm_size            = megabytes(shm_size),
            .io_buffer_pool_size = (usize)io_bufs_num,
            .io_buffer_size      = (usize)io_bufs_size,
        };
        
        // Control path
        while (g_running) {
            if (main_thread_control_ipc(sockfd, mem_cfg) < 0)   log_warn("Failed to handle control ipc\n");
            if (main_thread_connection_manager() < 0)           log_warn("Failed to handle connection manager\n");
        }
    }
        
    // Stop the threads in the thread pool
    {
        for (usize i = 0; i < thread_pool.count; i++) {
            at_store(&thread_pool.thread_args[i].state, NSN_DATAPLANE_THREAD_STATE_STOP, mo_rlx);
        }
        
        for (usize i = 0; i < thread_pool.count; i++) {
            nsn_os_thread_join(thread_pool.threads[i]);
        }
    }

    // cleanup
clear_and_quit:
    if (sockfd != -1) close(sockfd);

    unlink(NSNAPP_TO_NSND_IPC);
    mem_arena_release(state_arena);
    mem_arena_release(arena);

    log_debug("done\n");

    return 0;
}
