#ifndef NSN_DATAPATH_H
#define NSN_DATAPATH_H

#include "nsn_types.h"
#include "nsn.h"
#include "nsn_log.h"
#include "nsn_zone.h"
#include "nsn_memory.h"
#include "nsn_string.h"
#include "nsn_ringbuf.h"

// Argument for the plugin
typedef struct nsn_datapath_ctx nsn_datapath_ctx_t;
struct nsn_datapath_ctx
{
    // List of plugin parameters
    list_head_t params;
    
    // Array of peers' IPs
    char** peers;
    u16   n_peers;
    // Daemon-wise config values
    int max_tx_burst;
    int max_rx_burst;
    // Additional config if necessary
    char  config[0];
};

typedef struct nsn_buf nsn_buf_t;
struct nsn_buf
{
    usize  index;
};

typedef struct nsn_endpoint nsn_endpoint_t;
struct nsn_endpoint
{
    // App id, corresponding to an L4 port
    int app_id;
    // Ring for the free IO buffers
    nsn_ringbuf_t *free_slots;
    
    // Pointers to data and metadata memory
    nsn_mm_zone_t *tx_zone;
    nsn_mm_zone_t *tx_meta_zone;
    // Memory page size (for zero-copy)
    usize page_size;
    // Data slot size
    usize io_bufs_size;
    
    // Plugin-specific data to store the endpoint state
    void* data;
    usize data_size;
};

typedef struct ep_initializer ep_initializer_t;
struct ep_initializer
{
   list_head_t     node;
   nsn_endpoint_t* ep;
};

#define NSN_DATAPATH_INIT(name)                 int name##_datapath_init(nsn_datapath_ctx_t *ctx, list_head_t* endpoint_list)
typedef NSN_DATAPATH_INIT(nsn);
#define NSN_DATAPATH_CONN_MANAGER(name)         int name##_datapath_conn_manager(list_head_t* endpoint_list)
typedef NSN_DATAPATH_CONN_MANAGER(nsn);
#define NSN_DATAPATH_TX(name)                   int name##_datapath_tx(nsn_buf_t *bufs, usize buf_count, nsn_endpoint_t *endpoint)
typedef NSN_DATAPATH_TX(nsn);
#define NSN_DATAPATH_RX(name)                   int name##_datapath_rx(nsn_buf_t *bufs, usize *buf_count, nsn_endpoint_t *endpoint)
typedef NSN_DATAPATH_RX(nsn);
#define NSN_DATAPATH_UPDATE(name)               int name##_datapath_update(nsn_endpoint_t *endpoint)
typedef NSN_DATAPATH_UPDATE(nsn);
#define NSN_DATAPATH_DEINIT(name)               int name##_datapath_deinit(nsn_datapath_ctx_t *ctx, list_head_t* endpoint_list)
typedef NSN_DATAPATH_DEINIT(nsn);

#endif // NSN_DATAPATH_H