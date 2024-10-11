
#ifndef NSN_H
#define NSN_H

#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include "nsn_ringbuf.h"
#include "nsn_zone.h"

// --- Error Codes ----------------------------------------------------------------
#define NSN_ERROR_ALREADY_INITIALIZED   1
#define NSN_ERROR_NOT_INITIALIZED       2

//--------------------------------------------------------------------------------------------------
// INSANE Buffer
//--------------------------------------------------------------------------------------------------
typedef struct nsn_buffer {
    usize    index;
    uint8_t *data;
    usize    len;
} nsn_buffer_t;

//--------------------------------------------------------------------------------------------------

static inline int nsn_buffer_is_valid(nsn_buffer_t *buf) { return buf->data != NULL; }

typedef enum datapath_qos
{
    datapath_slow,
    datapath_fast
} datapath_qos_t;

typedef enum consumption_qos
{
    consumption_low,
    consumption_high
} consumption_qos_t;

typedef enum determinism_qos
{
    determinism_no,
    determinism_timesensitive
} determinism_qos_t;

typedef enum transport_qos
{
    unreliable_dgram,
    reliable_stream
} transport_qos_t;

//--------------------------------------------------------------------------------------------------
// QoS API
//--------------------------------------------------------------------------------------------------

typedef struct nsn_options {
    int datapath;
    int consumption;
    int determinism;
    int reliability;
} nsn_options_t;

//--------------------------------------------------------------------------------------------------
#define NSN_INVALID_SNK UINT32_MAX
typedef uint32_t nsn_sink_t;

#define NSN_INVALID_SRC UINT32_MAX
typedef uint32_t nsn_source_t;

#define NSN_INVALID_STREAM_HANDLE  UINT32_MAX
typedef uint32_t nsn_stream_t;

typedef void *handle_data_cb;

//--------------------------------------------------------------------------------------------------
// Flags for the nsn_emit_data function
#define NSN_BLOCKING     0x1
#define NSN_NONBLOCKING  0x2

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
    nsn_mm_zone_t *zone;
    char           name[32];            // the name of the pool
    usize          count;               // the number of ring buffers in the pool
    usize          esize;               // the size of the elements in each ring buffer
    usize          ecount;              // the number of elements in the ring buffer    
    usize          free_slots_count;
} nsn_cache_aligned;

typedef struct nsn_meta nsn_meta_t;
struct nsn_meta
{
    usize len;
};

//--------------------------------------------------------------------------------------------------
// INSANE API
//--------------------------------------------------------------------------------------------------

/* Open an INSANE session */
int nsn_init();

/* Closes an INSANE session */
int nsn_close();

/**
 * @brief    Open an INSANE stream
 * @param    opt QoS options for this stream
 * @returns  The handler to the created stream
 */
nsn_stream_t nsn_create_stream(nsn_options_t *opts);

/**
 * @brief    Close an INSANE stream
 * @param    stream     The stream to be closed
 * @returns  The outcome of the close operation
 */
int nsn_destroy_stream(nsn_stream_t stream);

/**
 * @brief    Open an INSANE source
 * @param    stream     A handle to the stream to attach this source
 * @param    source_id  An application-provided port identifier for this
                        source on the specified stream
 * @returns  The handler to the created source
 */
nsn_source_t nsn_create_source(nsn_stream_t *stream, uint32_t source_id);

/**
 * @brief    Close an INSANE source
 * @param    source     The source to be closed
 * @returns  The outcome of the close operation
 */
int nsn_destroy_source(nsn_source_t source);

/**
 * @brief    Get a buffer slot to write an outgoing message
 * @param    size   The required minimum size of the buffer
 * @param    flag   Flags to control the kind of buffer returned
 *                  (e.g., NSN_NONBLOCKING, NSN_BLOCKING)
 * @returns  A buffer slot ready to be written by the application
 */
nsn_buffer_t nsn_get_buffer(size_t size, int flags);

/**
 * @brief    Ask INSANE to send a buffer slot out to the network
 * @param    source A handle to the source to which the message will be sent
 * @param    buf    The buffer slot contaning the message to be sent
 * @returns  A token to asynchronously retrieve the outcome of the operation
 */
int nsn_emit_data(nsn_source_t source, nsn_buffer_t buf);

/**
 * @brief    Retrieve the outcome of a write operation
 * @param    source A handle to the source to which the message was sent
 * @param    id     A token obtained from a write operation
 * @returns  The outcome of the specified write operation
 */
int nsn_check_emit_outcome(nsn_source_t source, int id);

/**
 * @brief    Open an INSANE sink
 * @param    stream     A handle to the stream to attach this sink
 * @param    source_id  An application-provided source identifier for this
                        sink on the specified stream
 * @param    cb         A callback that will be called by INSANE for
                        every new message  for this sink
 * @returns  The handler to the created sink
 */
nsn_sink_t nsn_create_sink(nsn_stream_t *stream, uint32_t sink_id, handle_data_cb cb);

/**
 * @brief    Close an INSANE sink
 * @param    sink     The sink to be closed
 * @returns  The outcome of the close operation
 */
int nsn_destroy_sink(nsn_sink_t sink);

/**
 * @brief    Check if there is data available for the specified sink
 * @param    sink   The sink on which to check data availability
 * @param    flags  Flags to control the behavior of this function
 * @returns  Whethere there is data available or not
 */
int nsn_data_available(nsn_sink_t sink, int flags);

/**
 * @brief    Consume a message from a sink
 * @param    sink   The sink from which to get data
 * @param    flags  Flags to control the behavior of this function,
                    that can be NSN_BLOCKING or NSN_NONBLOCKING
 * @returns  A buffer slot containing the outcome of the operation and, if
             successful, the read data
 */
nsn_buffer_t nsn_consume_data(nsn_sink_t sink, int flags);

/**
 * @brief    Release a buffer slot to INSANE
 * @param    buf    The buffer slot to return to the middleware after data was
                    used by the application
 * @returns  The outcome of the operation (number of buffers released)
 */
int nsn_release_data(nsn_buffer_t buf);

#endif // NSN_H