#include "base/nsn_types.h"

#include "base/nsn_memory.h"
#include "base/nsn_os.h"
#include "base/nsn_shm.h"
#include "base/nsn_thread_ctx.h"

#include "common/nsn_config.h"
#include "common/nsn_ipc.h"
#include "common/nsn_ringbuf.h"
#include "common/nsn_zone.h"
#include "common/nsn_temp.h"

// #include <nsn/nsn.h>

#include "base/nsn_memory.c"
#include "base/nsn_os_inc.c"
#include "base/nsn_shm.c"
#include "base/nsn_string.c"

#include "common/nsn_config.c"
#include "common/nsn_ringbuf.c"

#define NSN_LOG_IMPLEMENTATION
#include "common/nsn_log.h"

#define NSN_APP_DEFAULT_CONFIG_FILE     "nsn-app.cfg"
#define NSN_MAX_STREAMS                 8
#define NSN_MAX_SOURCES                 8
#define NSN_MAX_SINKS                   8


// internals
typedef struct nsn_stream_inner nsn_stream_inner_t;
struct nsn_stream_inner {
    // The stream is valid
    bool is_active;
    // Local INDEX, to be used in this lib
    nsn_stream_t stream_id;
    // Plugin id
    uint32_t plugin_id;
    // Stream idx: use only for lib-to-daemon interactions 
    nsn_stream_t _idx;
    // send tx slot to the daemon
    nsn_ringbuf_t *tx_prod;
};


typedef struct nsn_source_inner nsn_source_inner_t;
struct nsn_source_inner {
    // The source is valid
    bool is_active;
    // Stream id 
    nsn_stream_t stream;
    // User-provided id
    uint32_t id;
    // Use the tx queue from the stream
};

typedef struct nsn_sink_inner nsn_sink_inner_t;
struct nsn_sink_inner {
    // The sink is valid
    bool is_active;
    // Stream id 
    nsn_stream_t stream;
    // User-provided id
    uint32_t id;
    // Rx queue
    nsn_ringbuf_t *rx_cons;
    // User-provided callbakck
    handle_data_cb cb;
};

// nsn app state
mem_arena_t *arena = NULL;
int app_id         = -1;
int sockfd         = -1;
struct sockaddr_un nsn_app_addr;
struct sockaddr_un nsnd_addr;
nsn_shm_t *shm            = NULL;

// Slots management
nsn_mm_zone_t *tx_bufs;
size_t tx_buf_size;
nsn_mm_zone_t *tx_buf_meta;
// nsn_mm_zone_t *rx_bufs;
nsn_mm_zone_t *rings_zone;
nsn_ringbuf_t *free_slots_ring;

nsn_mutex_t nsn_app_mutex = NSN_OS_MUTEX_INITIALIZER;
nsn_stream_inner_t streams[NSN_MAX_STREAMS]; //TODO: is there a better way? A list?
uint32_t n_str = 0;
nsn_source_inner_t sources[NSN_MAX_SOURCES]; //TODO: is there a better way? A list?
uint32_t n_src = 0;
nsn_sink_inner_t sinks[NSN_MAX_SINKS];
uint32_t n_snk = 0;

#define SPIN_LOOP_PAUSE() nsn_pause()

// -----------------------------------------------------------------------------
// Termination handler
void 
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        // close all the sinks, sources
        if (n_src > 0) {
            for (uint32_t i = 0; i < array_count(sources); ++i) {
                if (sources[i].is_active) {
                    log_info("Destroying source %d\n", sources[i].id);
                    nsn_destroy_source(sources[i].id);
                }
            }
        }
        if (n_snk > 0) {
            for (uint32_t i = 0; i < array_count(sinks); ++i) {
                if (sinks[i].is_active) {
                    log_info("Destroying sink %d\n", sinks[i].id);
                    nsn_destroy_sink(sinks[i].id);
                }
            }
        }
        // close all the streams
        if (n_str > 0) {
            for (uint32_t i = 0; i < array_count(streams); ++i) {
                if (streams[i].is_active) {
                    log_info("Destroying stream %d\n", streams[i].stream_id);
                    nsn_destroy_stream(streams[i].stream_id);
                }
            }
        }

        // uninitialize the daemon
        nsn_close();

    }
    
    exit(0);
}

// -----------------------------------------------------------------------------
// Helpers
// @param zone: the zone to search in
// @param ring_name: the name of the ring buffer to retrieve from the zone
// @return: a pointer to the ring buffer, NULL if the ring buffer was not found
static nsn_ringbuf_t *
nsn_lookup_ringbuf(nsn_mm_zone_t* rings_zone, string_t ring_name) {
    if (!rings_zone) {
        log_error("Invalid zone\n");
        return NULL;
    }

    nsn_ringbuf_pool_t* pool = (nsn_ringbuf_pool_t*)nsn_mm_zone_get_ptr(shm->data, rings_zone);
    if (!pool) {
        log_error("Failed to get the ring buffer pool\n");
        return NULL;
    }
    log_debug("Ring pool found at %p, with %lu free slots\n", pool, pool->free_slots_count);

    // check which slots are free
    bool* ring_tracker = (bool*)(pool + 1);
    char* ring_data = (char*)(ring_tracker + pool->count);  
    usize ring_size = sizeof(nsn_ringbuf_t) + (pool->ecount * pool->esize);

    // find the ring buffer to retrieve
    nsn_ringbuf_t* ring = 0;
    for (usize i = 0; i < pool->count; ++i) {
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

// -----------------------------------------------------------------------------
// API
int 
nsn_init()
{
    arena = mem_arena_alloc_default();

    // load the app configuration file
    nsn_thread_ctx_t main_thread = nsn_thread_ctx_alloc();
    main_thread.is_main_thread   = true;
    nsn_thread_set_ctx(&main_thread);
    
    nsn_cfg_t *config = nsn_load_config(arena, str_lit(NSN_APP_DEFAULT_CONFIG_FILE));
    nsn_config_get_int(config, str_lit("app"), str_lit("l4_port"), &app_id);

//  #ifdef NSN_ENABLE_LOGGER
    // Set the log level according to the config file
    logger_init(NULL);
    char config_log_level[32] = {0};
    string_t cfg_ll           = str_cstr(config_log_level);
    nsn_config_get_string(config, str_lit("app"), str_lit("log_level"), &cfg_ll);
    logger_set_level_by_name(to_cstr(cfg_ll));
// #endif

    temp_mem_arena_t temp = temp_mem_arena_begin(arena);

    // open a connection with the insance of the nsn daemon
    sockfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return -1;
    }

    nsn_app_addr.sun_family = AF_UNIX;
    
    char name[IPC_MAX_PATH_SIZE];
    snprintf(name, IPC_MAX_PATH_SIZE, "%s%d", NSND_TO_NSNAPP_IPC, app_id);
    strncpy(nsn_app_addr.sun_path, name, sizeof(nsn_app_addr.sun_path));

    if (bind(sockfd, (struct sockaddr *)&nsn_app_addr, sizeof(struct sockaddr_un)) < 0) {
        log_error("failed to bind to path %s: '%s'\n", name, strerror(errno));
        goto exit_error;
        return -1;
    }

    // set a timeout for the socket
    struct timeval tv;
    tv.tv_sec  = 3;
    tv.tv_usec = 0;
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
        log_error("failed to connect to nsnd with error '%s', is it running?\n", strerror(errno));
        goto exit_error;
    }

    if (cmsghdr->type == NSN_CMSG_TYPE_ERROR) {
        int error = *(int *)(cmsg + sizeof(nsn_cmsg_hdr_t));
        log_error("failed to connect to nsnd with error '%d'\n", error); 
        goto exit_error;
    }

    struct sigaction sa;
    memory_zero_struct(&sa);
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    nsn_cmsg_connect_t *resp = (nsn_cmsg_connect_t *)(cmsg + sizeof(nsn_cmsg_hdr_t));

    shm = nsn_shm_attach(arena, resp->shm_name, resp->shm_size);
    if (shm == NULL) {
        log_error("failed to attach to the shared memory segment\n");
        goto exit_error;
    }
    log_info("connected to nsnd, the shm is at /dev/shm/%s, with size %zu\n", resp->shm_name, resp->shm_size);

    // // Lookup the free slots ring
    // char* ring_position = (char*)(shm->data + resp->free_slots_ring_offset);
    // log_info("Lookup ring\n offset %u\n from shm->data %p\nexpected at %p\n", resp->free_slots_ring_offset, shm->data, ring_position);
    // free_slots_ring = nsn_ringbuf_lookup(ring_position, str_lit(resp->free_slots_ring));
    // log_info("Found ring at %p\n", free_slots_ring);
    // if (free_slots_ring == NULL) {
    //     log_error("failed to attach to the free slots ring\n");
    //     goto exit_error_close_shm;
    // }

    // Retrieve the memory manager's created zones: IO-SLOTS and RINGS. 
    // TODO: this is a hack, we should have a proper way to get the zones, e.g., through a memory manager API.
    nsn_mm_zone_list_t *zones = (nsn_mm_zone_list_t *)(nsn_shm_rawdata(shm) + sizeof(fixed_mem_arena_t));

    // a) Find the slot zone(s)
    tx_bufs = nsn_find_zone_by_name(zones, str_lit(NSN_CFG_DEFAULT_TX_IO_BUFS_NAME));
    if (tx_bufs == NULL) {
        log_error("failed to find the rx_io_buffer_pool zone\n");
        goto exit_error;
    }
    tx_buf_size = resp->io_buf_size;

    tx_buf_meta = nsn_find_zone_by_name(zones, str_lit(NSN_CFG_DEFAULT_TX_META_NAME));
    if (tx_buf_meta == NULL) {
        log_error("failed to find the tx_io_meta_pool zone\n");
        goto exit_error;
    }
    
    // rx_bufs = nsn_find_zone_by_name(zones, str_lit(NSN_CFG_DEFAULT_RX_IO_BUFS_NAME));
    // if (rx_bufs == NULL) {
    //     log_error("failed to find the tx_io_buffer_pool zone\n");
    //     goto exit_error;
    // }
    // rx_buf_size = ?;
    
    // b) Find the ring zone, its offset in the arena, and then the free_slots ring inside it.
    rings_zone = nsn_find_zone_by_name(zones, str_lit(NSN_CFG_DEFAULT_RINGS_ZONE_NAME));
    if (rings_zone == NULL) {
        log_error("failed to find the tx_io_buffer_pool zone\n");
        goto exit_error;
    }
    free_slots_ring = nsn_lookup_ringbuf(rings_zone, str_lit(NSN_CFG_DEFAULT_FREE_SLOTS_RING_NAME));
    if(!free_slots_ring) {
        log_error("failed to find the free slots ring\n");
        goto exit_error;
    }    

    // Initialize the local steam state
    for (uint32_t i = 0; i < array_count(streams); i++) {
        streams[i].is_active = false;
        streams[i].plugin_id = NSN_INVALID_PLUGIN_HANDLE;
        streams[i]._idx = NSN_INVALID_STREAM_HANDLE;
        streams[i].stream_id = NSN_INVALID_STREAM_HANDLE;
        streams[i].tx_prod = NULL;
    }
    n_str = 0;

    // Initialize the local source state
    for (uint32_t i = 0; i < array_count(sources); i++) {
        sources[i].is_active = false;
        sources[i].id = NSN_INVALID_SRC;
        sources[i].stream = NSN_INVALID_STREAM_HANDLE;
    }
    n_src = 0;

    // Initialize the local sink state
    for (uint32_t i = 0; i < array_count(sinks); i++) {
        sinks[i].is_active = false;
        sinks[i].id = NSN_INVALID_SNK;
        sinks[i].stream = NSN_INVALID_STREAM_HANDLE;
        sinks[i].cb = NULL;
    }
    n_snk = 0;
    
    temp_mem_arena_end(temp);
    return 0;

// exit_error_close_shm:
    // detach from the shared memory segment shared with the daemon
    nsn_shm_detach(shm);

exit_error:
    close(sockfd);
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
        log_error("failed to disconnect from nsnd with error '%s', is it running?\n", strerror(errno));
    } else {
        if (cmsghdr->type == NSN_CMSG_TYPE_ERROR) {
            int error = *(int *)(cmsg + sizeof(nsn_cmsg_hdr_t));
            log_error("failed to disconnect from nsnd with error '%d'\n", error); 
        } else {
            log_info("disconnected from nsnd\n");
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

#ifdef NSN_ENABLE_LOGGER
    // close the logger
    logger_close();
#endif

    return 0;
}

// -----------------------------------------------------------------------------
nsn_stream_t
nsn_create_stream(nsn_options_t opts)
{
    log_info("Creating stream\n");

    nsn_stream_t stream = NSN_INVALID_STREAM_HANDLE;
    if (n_str == NSN_MAX_STREAMS) {
        log_warn("limit exceeded: too many streams\n");
        return stream;
    } else {
        // Get the first available source descriptor
        for(uint32_t i = 0; i < array_count(streams); i++) {
            if (!streams[i].is_active) {
                stream = i;
                break;
            }
        }
    }

    // Sanity check the QoS options
    if (opts.consumption < 0 || opts.consumption > 1 ||
        opts.datapath < 0 || opts.datapath > 1 ||
        opts.determinism < 0 || opts.determinism > 1 ||
        opts.reliability < 0 || opts.reliability > 1) {
        log_warn("invalid QoS options\n");
        return NSN_INVALID_STREAM_HANDLE;
    }
    
    temp_mem_arena_t temp = temp_mem_arena_begin(arena);
    byte *cmsg = mem_arena_push_array(temp.arena, byte, 4096);

    nsn_cmsg_hdr_t *cmsghdr = (nsn_cmsg_hdr_t *)cmsg;
    cmsghdr->type   = NSN_CMSG_TYPE_CREATE_STREAM;
    cmsghdr->app_id = app_id;

    nsn_cmsg_create_stream_t* msg = (nsn_cmsg_create_stream_t *)(cmsg + sizeof(nsn_cmsg_hdr_t));
    msg->opts = opts;

    // TODO: The mapping between the requested QoS and a plugin happens in the daemon. We should send the policies and the daemon should return the corresponding stream index.
    sendto(sockfd, cmsg, sizeof(nsn_cmsg_hdr_t) + sizeof(nsn_cmsg_create_stream_t), 0, (struct sockaddr *)&nsnd_addr, sizeof(struct sockaddr_un));

    if (recvfrom(sockfd, cmsg, 4096, 0, NULL, NULL) == -1) {
        log_error("failed to create stream with error '%s', is it running?\n", strerror(errno));
        goto exit;
    } else if (cmsghdr->type == NSN_CMSG_TYPE_ERROR) {
        int error = *(int *)(cmsg + sizeof(nsn_cmsg_hdr_t));
        log_error("failed to create stream with error '%d'\n", error); 
        goto exit;
    }

    // Get the name of the tx_prod ring from the daemon and attach to it
    msg = (nsn_cmsg_create_stream_t *)(cmsg + sizeof(nsn_cmsg_hdr_t));
    streams[stream]._idx = msg->stream_idx;
    streams[stream].tx_prod = nsn_lookup_ringbuf(rings_zone, str_lit(msg->tx_prod));

    log_debug("The 'tx_prod' ringbuffer for the stream %d is: %p\n", stream, streams[stream].tx_prod);

    if (streams[stream].tx_prod == NULL) {
        log_error("stream failed to attach to the tx ring\n");
        streams[stream].tx_prod = NULL;
        stream = NSN_INVALID_STREAM_HANDLE;       
        goto exit;
    }

    // Success: fill in the remaining fields of the stream descriptor
    streams[stream].plugin_id = msg->plugin_idx;
    streams[stream].stream_id = stream;
    streams[stream].is_active = true;
    n_str++;

exit:
    temp_mem_arena_end(temp);
    return stream;
}

// -----------------------------------------------------------------------------
int 
nsn_destroy_stream(nsn_stream_t stream)
{
    if (stream == NSN_INVALID_STREAM_HANDLE) {
        log_error("invalid stream handle\n");
        return -1;
    }

    if (stream >= NSN_MAX_STREAMS) {
        log_error("stream not found\n");
        return -1;
    }
    if (!streams[stream].is_active) {
        log_error("invalid stream (idx %u, is active %d)\n", stream, streams[stream].is_active);
        return -1;
    }

    temp_mem_arena_t temp = temp_mem_arena_begin(arena);
    byte *cmsg = mem_arena_push_array(temp.arena, byte, 4096);

    nsn_cmsg_hdr_t *cmsghdr = (nsn_cmsg_hdr_t *)cmsg;
    cmsghdr->type   = NSN_CMSG_TYPE_DESTROY_STREAM;
    cmsghdr->app_id = app_id;

    nsn_cmsg_create_stream_t* msg = (nsn_cmsg_create_stream_t *)(cmsghdr + 1);
    msg->plugin_idx = streams[stream].plugin_id;
    msg->stream_idx = streams[stream]._idx;

    sendto(sockfd, cmsg, sizeof(nsn_cmsg_hdr_t) + sizeof(nsn_cmsg_create_stream_t), 0, (struct sockaddr *)&nsnd_addr, sizeof(struct sockaddr_un));

    if (recvfrom(sockfd, cmsg, 4096, 0, NULL, NULL) == -1) {
        log_error("failed to destroy stream with error '%s', is it running?\n", strerror(errno));
    } else {
        if (cmsghdr->type == NSN_CMSG_TYPE_ERROR) {
            int error = *(int *)(cmsg + sizeof(nsn_cmsg_hdr_t));
            log_error("failed to destroy stream with error '%d'\n", error); 
        } else {
            // clean up the stream descriptor
            streams[stream].is_active = false;
            streams[stream].plugin_id = NSN_INVALID_PLUGIN_HANDLE;
            streams[stream]._idx = NSN_INVALID_STREAM_HANDLE;
            streams[stream].stream_id = NSN_INVALID_STREAM_HANDLE;
            streams[stream].tx_prod = NULL;
            n_str--;
            log_info("destroyed stream\n");
        }
    }

    temp_mem_arena_end(temp);

    return 0;
}

// -----------------------------------------------------------------------------
nsn_source_t 
nsn_create_source(nsn_stream_t stream, uint32_t source_id) {
    if (stream >= array_count(streams)) {
        log_error("invalid argument: stream\n");
        return NSN_INVALID_SRC;
    }
    if (source_id == NSN_INVALID_SRC) {
        log_error("invalid argument: source_id %u\n", source_id);
        return NSN_INVALID_SRC;
    }
    uint32_t src_idx = NSN_INVALID_SRC;
    if (n_src == NSN_MAX_SOURCES) {
        log_error("limit exceeded: too many sources\n");
        return NSN_INVALID_SRC;
    } else {
        // Get the first available source descriptor
        for(uint32_t i = 0; i < array_count(sources); i++) {
            if (!sources[i].is_active) {
                src_idx = i;
                break;
            }
        }
    }
    
    temp_mem_arena_t temp = temp_mem_arena_begin(arena);
    byte *cmsg = mem_arena_push_array(temp.arena, byte, 4096);
    nsn_cmsg_hdr_t *cmsghdr = (nsn_cmsg_hdr_t *)cmsg;
    cmsghdr->type   = NSN_CMSG_TYPE_CREATE_SOURCE;
    cmsghdr->app_id = app_id;

    // Send the request to the daemon, including the stream id of the source
    nsn_cmsg_create_source_t *msg = (nsn_cmsg_create_source_t *)(cmsg + sizeof(nsn_cmsg_hdr_t));
    msg->plugin_idx = streams[stream].plugin_id;
    msg->stream_idx = streams[stream]._idx;
    msg->source_id  = source_id;
    sendto(sockfd, cmsg, sizeof(nsn_cmsg_hdr_t)+sizeof(nsn_cmsg_create_source_t), 0, (struct sockaddr *)&nsnd_addr, sizeof(struct sockaddr_un));

    // If successful, receive two handlers to attach to the TX rings
    if (recvfrom(sockfd, cmsg, 4096, 0, NULL, NULL) == -1) {
        log_error("failed to create source with error '%s', is it running?\n", strerror(errno));
        source_id = NSN_INVALID_SRC;
        goto exit;
    } else if (cmsghdr->type == NSN_CMSG_TYPE_ERROR) {
        int error = *(int *)(cmsg + sizeof(nsn_cmsg_hdr_t));
        log_error("failed to create source with error '%d'\n", error); 
        source_id = NSN_INVALID_SRC;
        goto exit;
    }
    
    // finalize the source creation 
    sources[src_idx].id = source_id;
    sources[src_idx].is_active = true;
    sources[src_idx].stream = stream;
    n_src++;    

    log_info("created source %u\n", source_id);
    log_trace("created source %u in slot %u with is_active=%d\n", source_id, src_idx, sources[src_idx].is_active);

exit:
    temp_mem_arena_end(temp);
    return source_id;
}

// -----------------------------------------------------------------------------
int 
nsn_destroy_source(nsn_source_t source) {
    
    uint32_t source_idx = NSN_INVALID_SRC;
    for(uint32_t i = 0; i < array_count(sources); i++) {
        if (sources[i].id == (uint32_t)source) {
           source_idx = i; 
        }
    }
    if (source_idx == NSN_INVALID_SRC) {
        log_error("source not found\n");
        return -1;
    }
    if (!sources[source_idx].is_active) {
        log_error("invalid source (idx %u, is active %d)\n", source_idx, sources[source_idx].is_active);
        return -1;
    }

    // communicate with the daemon to destroy the source, i.e. to
    // check if some dp threads can be stopped.
    int ok = 0;
    temp_mem_arena_t temp = temp_mem_arena_begin(arena);
    byte *cmsg = mem_arena_push_array(temp.arena, byte, 4096);
    nsn_cmsg_hdr_t *cmsghdr = (nsn_cmsg_hdr_t *)cmsg;
    cmsghdr->type   = NSN_CMSG_TYPE_DESTROY_SOURCE;
    cmsghdr->app_id = app_id;

    nsn_cmsg_create_source_t *msg = (nsn_cmsg_create_source_t *)(cmsg + sizeof(nsn_cmsg_hdr_t));
    msg->plugin_idx = streams[sources[source_idx].stream].plugin_id;
    msg->stream_idx = streams[sources[source_idx].stream]._idx;
    msg->source_id  = sources[source_idx].id;

    byte *reply = mem_arena_push_array(temp.arena, byte, 4096);
    nsn_cmsg_hdr_t *replyhdr = (nsn_cmsg_hdr_t *)reply;

   bool stop = false;
   int ret;
   while (!stop) {
        while(sendto(sockfd, cmsg, sizeof(nsn_cmsg_hdr_t)+sizeof(nsn_cmsg_create_source_t), 0, (struct sockaddr *)&nsnd_addr, sizeof(struct sockaddr_un)) < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                log_error("failed to destroy source with error '%s', is it running?\n", strerror(errno));
                ok = -1;
                goto clean_and_exit;
            }
            // retry
            usleep(10);
        }
        
        while((ret = recvfrom(sockfd, reply, 4096, 0, NULL, NULL)) < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                log_error("failed to destroy source with error '%s', is it running?\n", strerror(errno));
                ok = -1;
                goto clean_and_exit;
            }
            // retry
            usleep(10);
        }

        if (replyhdr->type == NSN_CMSG_TYPE_ERROR) {
            int error = *(int *)(reply + sizeof(nsn_cmsg_hdr_t));
            if (error == -EAGAIN || error == -EWOULDBLOCK) {
                // retry
                usleep(10);
                continue;
            }
            log_error("failed to destroy source with error '%d'\n", error); 
            ok = -1;
            goto clean_and_exit;
        }
        stop = true;
    }

    // We can proceed to the destruction of the source
    sources[source_idx].id = NSN_INVALID_SRC;
    sources[source_idx].is_active = false;
    sources[source_idx].stream = NSN_INVALID_STREAM_HANDLE;
    n_src--;

clean_and_exit:
    temp_mem_arena_end(temp);
    return ok;
}

// -----------------------------------------------------------------------------
nsn_sink_t
nsn_create_sink(nsn_stream_t stream, uint32_t sink_id, handle_data_cb cb) {
    if (stream >= array_count(streams)) {
        log_warn("invalid argument: stream\n");
        return NSN_INVALID_SNK;
    }
    if (sink_id == NSN_INVALID_SNK) {
        log_warn("invalid argument: sink_id %u\n", sink_id);
        return NSN_INVALID_SNK;
    }
    uint32_t snk_idx = NSN_INVALID_SNK;
    if (n_snk == NSN_MAX_SINKS) {
        log_warn("limit exceeded: too many sinks\n");
        return NSN_INVALID_SNK;
    } else {
        // Get the first available sink descriptor
        for(uint32_t i = 0; i < array_count(sinks); i++) {
            if (!sinks[i].is_active) {
                snk_idx = i;
                break;
            }
        }
    }
    
    temp_mem_arena_t temp = temp_mem_arena_begin(arena);
    byte *cmsg = mem_arena_push_array(temp.arena, byte, 4096);
    nsn_cmsg_hdr_t *cmsghdr = (nsn_cmsg_hdr_t *)cmsg;
    cmsghdr->type   = NSN_CMSG_TYPE_CREATE_SINK;
    cmsghdr->app_id = app_id;

    // Send the request to the daemon, including the stream id of the sink
    nsn_cmsg_create_sink_t *msg = (nsn_cmsg_create_sink_t *)(cmsg + sizeof(nsn_cmsg_hdr_t));
    msg->plugin_idx = streams[stream].plugin_id;
    msg->stream_idx = streams[stream]._idx;
    msg->sink_id  = sink_id;
    sendto(sockfd, cmsg, sizeof(nsn_cmsg_hdr_t)+sizeof(nsn_cmsg_create_sink_t), 0, (struct sockaddr *)&nsnd_addr, sizeof(struct sockaddr_un));

    // If successful, receive two handlers
    if (recvfrom(sockfd, cmsg, 4096, 0, NULL, NULL) == -1) {
        log_error("failed to create sink with error '%s', is it running?\n", strerror(errno));
        sink_id = NSN_INVALID_SNK;
        goto exit;
    } else if (cmsghdr->type == NSN_CMSG_TYPE_ERROR) {
        int error = *(int *)(cmsg + sizeof(nsn_cmsg_hdr_t));
        log_error("failed to create sink with error '%d'\n", error); 
        sink_id = NSN_INVALID_SNK;
        goto exit;
    }

    sinks[snk_idx].rx_cons = nsn_lookup_ringbuf(rings_zone, str_lit(msg->rx_cons));
    if (sinks[snk_idx].rx_cons == NULL) {
        log_error("sink failed to attach to the rx ring\n");
        sinks[snk_idx].rx_cons = NULL;
        sink_id = NSN_INVALID_SNK;       
        goto exit;
    }

    // finalize the sink creation 
    sinks[snk_idx].id = sink_id;
    sinks[snk_idx].is_active = true;
    sinks[snk_idx].stream = stream;
    sinks[snk_idx].cb = cb;
    n_snk++;    

    log_info("created sink %u\n", sink_id);

exit:
    temp_mem_arena_end(temp);
    return sink_id;
}

// -----------------------------------------------------------------------------
int
nsn_destroy_sink(nsn_sink_t sink) {
    uint32_t sink_idx = NSN_INVALID_SNK;
    for(uint32_t i = 0; i < array_count(sinks); i++) {
        if (sinks[i].id == (uint32_t)sink) {
           sink_idx = i; 
        }
    }
    if (sink_idx == NSN_INVALID_SNK) {
        log_error("sink not found\n");
        return -1;
    }
    if (!sinks[sink_idx].is_active) {
        log_error("invalid sink (idx %u, is active %d)\n", sink_idx, sinks[sink_idx].is_active);
        return -1;
    }

    // communicate with the daemon to destroy the sink, i.e. to
    // check if some dp threads can be stopped.
    int ok = 0;
    temp_mem_arena_t temp = temp_mem_arena_begin(arena);
    byte *cmsg = mem_arena_push_array(temp.arena, byte, 4096);
    nsn_cmsg_hdr_t *cmsghdr = (nsn_cmsg_hdr_t *)cmsg;
    cmsghdr->type   = NSN_CMSG_TYPE_DESTROY_SINK;
    cmsghdr->app_id = app_id;

    nsn_cmsg_create_sink_t *msg = (nsn_cmsg_create_sink_t *)(cmsg + sizeof(nsn_cmsg_hdr_t));
    msg->plugin_idx = streams[sinks[sink_idx].stream].plugin_id;
    msg->stream_idx = streams[sinks[sink_idx].stream]._idx;
    msg->sink_id  = sinks[sink_idx].id;

    sendto(sockfd, cmsg, sizeof(nsn_cmsg_hdr_t)+sizeof(nsn_cmsg_create_sink_t), 0, (struct sockaddr *)&nsnd_addr, sizeof(struct sockaddr_un));

    if (recvfrom(sockfd, cmsg, 4096, 0, NULL, NULL) == -1) {
        log_error("failed to destroy sink with error '%s', is it running?\n", strerror(errno));
        ok = -1;
        goto clean_and_exit;
    } else if (cmsghdr->type == NSN_CMSG_TYPE_ERROR) {
        int error = *(int *)(cmsg + sizeof(nsn_cmsg_hdr_t));
        log_error("failed to destroy sink with error '%d'\n", error); 
        ok = -1;
        goto clean_and_exit;
    }

    // If we receive no error, we can proceed to the destruction of the sink
    sinks[sink_idx].id = NSN_INVALID_SNK;
    sinks[sink_idx].is_active = false;
    sinks[sink_idx].stream = NSN_INVALID_STREAM_HANDLE;
    sinks[sink_idx].cb = NULL;
    n_snk--;

clean_and_exit:
    temp_mem_arena_end(temp);
    return ok;
}

nsn_buffer_t tmp_buf;

// -----------------------------------------------------------------------------
nsn_buffer_t *nsn_get_buffer(size_t size, int flags) {

    if (size > 1500) {
        log_error("invalid size %lu\n", size);
        tmp_buf.len = 0;
        return &tmp_buf;
    }

    if (flags & NSN_BLOCKING) {
        while (nsn_ringbuf_dequeue_burst(free_slots_ring, &tmp_buf.index, sizeof(tmp_buf.index), 1, NULL) == 0) {
            SPIN_LOOP_PAUSE();
        }
    } else {
        if(nsn_ringbuf_dequeue_burst(free_slots_ring, &tmp_buf.index, sizeof(tmp_buf.index), 1, NULL) == 0) {
            return &tmp_buf;
        }
    }

    uint8_t *data = (uint8_t*)(tx_bufs + 1) + (tmp_buf.index * tx_buf_size); 
    log_trace("Got iobuf #%lu, data %p, len %lu\n", tmp_buf.index, data, tx_buf_size);
    tmp_buf.data = data + INSANE_HEADER_LEN;
    tmp_buf.len  = tx_buf_size - INSANE_HEADER_LEN;

    return &tmp_buf;
}

// -----------------------------------------------------------------------------
int nsn_emit_data(nsn_source_t source, nsn_buffer_t *buf) {

    if (source == NSN_INVALID_SRC) {
        log_error("invalid source\n");
        return -1;
    }

    if(buf->len <= 0 || (size_t)buf->len > tx_buf_size) {
        log_error("invalid buffer size %d\n", buf->len);
        return -2;
    }

    if(buf->data == NULL) {
        // TODO: This is a temporary ack to test the python bindings
        log_error("invalid buffer data: %p\n", buf->data);
        memset(buf->data, 'a', buf->len);
        // return -3;
    }

    nsn_source_inner_t *src = &sources[source];
    nsn_stream_inner_t *str = &streams[src->stream];

    // Set the nsn header and metadata
    nsn_hdr_t *hdr = (nsn_hdr_t *)(buf->data - INSANE_HEADER_LEN);
    hdr->channel_id = src->id;
    ((nsn_meta_t*)(tx_buf_meta + 1))[buf->index].len = buf->len + INSANE_HEADER_LEN;

    while(nsn_ringbuf_enqueue_burst(str->tx_prod, &buf->index, sizeof(buf->index), 1, NULL) == 0) {
        SPIN_LOOP_PAUSE();
    }
    log_trace("Emitted iobuf #%lu\n", buf->index);

    return buf->index;
}

// -----------------------------------------------------------------------------
int nsn_check_emit_outcome(nsn_source_t source, int id) {
    nsn_unused(source);
    nsn_unused(id);
    log_error("check_emit_outcome not implemented\n");
    return -1;
}

// -----------------------------------------------------------------------------
int nsn_data_available(nsn_sink_t sink, int flags) {
    nsn_unused(flags);
    nsn_unused(sink);
    log_error("data_available not implemented\n");
    return -1;
}

nsn_buffer_t tmp_consume_buf = {0};

// -----------------------------------------------------------------------------
nsn_buffer_t *nsn_consume_data(nsn_sink_t sink, int flags) {

    if (sink == NSN_INVALID_SRC) {
        log_error("invalid source\n");
        return &tmp_consume_buf;
    }

    nsn_sink_inner_t *_sink = &sinks[sink];

    if (flags & NSN_BLOCKING) {
        while (nsn_ringbuf_dequeue_burst(_sink->rx_cons, &tmp_consume_buf.index, sizeof(tmp_consume_buf.index), 1, NULL) == 0) {
            SPIN_LOOP_PAUSE();
        }
    } else {
        if (nsn_ringbuf_dequeue_burst(_sink->rx_cons, &tmp_consume_buf.index, sizeof(tmp_consume_buf.index), 1, NULL) == 0) {
            tmp_consume_buf.len = 0;
            return &tmp_consume_buf;
        }
    }

    uint8_t *data = (uint8_t*)(tx_bufs + 1) + (tmp_consume_buf.index * tx_buf_size); 
    usize   len   = ((nsn_meta_t*)(tx_buf_meta + 1) + tmp_consume_buf.index)->len;
    tmp_consume_buf.data      = data + INSANE_HEADER_LEN;
    tmp_consume_buf.len       = len - INSANE_HEADER_LEN; 
    log_trace("Received on buf #%lu, data %p, len %lu\n", tmp_consume_buf.index, data, tmp_consume_buf.len);

    return &tmp_consume_buf;
}

// -----------------------------------------------------------------------------
int nsn_release_data(nsn_buffer_t *buf) {
    if (buf->len == 0) {
        log_error("release of invalid buffer\n");
        return 0;
    }
    int ret = nsn_ringbuf_enqueue_burst(free_slots_ring, &buf->index, sizeof(buf->index), 1, NULL);
    if(ret != 1) {
        log_error("failed to release buffer\n");
    } 
    return ret;
}
