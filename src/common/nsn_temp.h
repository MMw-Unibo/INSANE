#ifndef NSN_TEMP_H
#define NSN_TEMP_H

#include "base/nsn_types.h"

#include "common/nsn_zone.h"

//--------------------------------------------------------------------------------------------------
// Definitions
// TODO: These are duplicates of the nsnd.h/.c definitions. 
// Consider passing these names from the daemon to the app via IPC instead,
// and/or defining the structs in a common file
#define NSN_CFG_DEFAULT_TX_IO_BUFS_NAME         "tx_io_buffer_pool"
#define NSN_CFG_DEFAULT_TX_META_NAME            "tx_io_meta_pool"
#define NSN_CFG_DEFAULT_RX_IO_BUFS_NAME         "rx_io_buffer_pool"
#define NSN_CFG_DEFAULT_RINGS_ZONE_NAME         "rings_zone"
#define NSN_CFG_DEFAULT_FREE_SLOTS_RING_NAME    "free_slots"

typedef struct nsn_ringbuf_pool nsn_ringbuf_pool_t;
struct nsn_ringbuf_pool
{
    nsn_mm_zone_t   *zone;
    char             name[32];            // the name of the pool
    size_t           count;               // the number of ring buffers in the pool
    size_t           esize;               // the size of the elements in each ring buffer
    size_t           ecount;              // the number of elements in the ring buffer    
    size_t           free_slots_count;
} nsn_cache_aligned;

typedef struct nsn_meta nsn_meta_t;
struct nsn_meta
{
    size_t len;
};

#endif // NSN_TEMP_H