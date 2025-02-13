
#ifndef NSN_H
#define NSN_H

#include <stddef.h>
#include <stdint.h>
#include <limits.h>

typedef struct nsn_hdr nsn_hdr_t;
struct nsn_hdr { uint32_t channel_id; };
#define INSANE_HEADER_LEN sizeof(nsn_hdr_t)

#define NSN_APP_DEFAULT_CONFIG_FILE     "nsn-app.cfg"

// --- Error Codes ----------------------------------------------------------------
#define NSN_ERROR_ALREADY_INITIALIZED   1
#define NSN_ERROR_NOT_INITIALIZED       2

//--------------------------------------------------------------------------------------------------
// INSANE Buffer
//--------------------------------------------------------------------------------------------------
typedef struct nsn_buffer nsn_buffer_t;
struct nsn_buffer 
{
    size_t   index;
    uint8_t *data;
    size_t   len;
};

//--------------------------------------------------------------------------------------------------

static inline int nsn_buffer_is_valid(nsn_buffer_t *buf) { return buf->len != 0; }

//--------------------------------------------------------------------------------------------------
// QoS options
//--------------------------------------------------------------------------------------------------

typedef struct nsn_options nsn_options_t;
struct nsn_options
{
    int datapath;
    int consumption;
    int determinism;
    int reliability;
};

#define NSN_QOS_DATAPATH_DEFAULT 0x0
#define NSN_QOS_DATAPATH_FAST    0x1

#define NSN_QOS_CONSUMPTION_LOW  0x0
#define NSN_QOS_CONSUMPTION_POLL 0x1

#define NSN_QOS_DETERMINISM_DEFAULT 0x0
#define NSN_QOS_DETERMINISM_TIMESENSITIVE 0x1

#define NSN_QOS_RELIABILITY_UNRELIABLE 0x0
#define NSN_QOS_RELIABILITY_RELIABLE   0x1

//--------------------------------------------------------------------------------------------------
#define NSN_INVALID_SNK UINT32_MAX
typedef uint32_t nsn_sink_t;

#define NSN_INVALID_SRC UINT32_MAX
typedef uint32_t nsn_source_t;

#define NSN_INVALID_STREAM_HANDLE  UINT32_MAX
typedef uint32_t nsn_stream_t;

#define NSN_INVALID_PLUGIN_HANDLE  UINT32_MAX

typedef void *handle_data_cb;

//--------------------------------------------------------------------------------------------------
// Flags for the nsn_emit_data function
#define NSN_BLOCKING     0x1
#define NSN_NONBLOCKING  0x2

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
nsn_stream_t nsn_create_stream(nsn_options_t opts);

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