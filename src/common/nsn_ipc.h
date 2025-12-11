#ifndef NSN_IPC_H
#define NSN_IPC_H

#include "base/nsn_types.h"
#include "base/nsn_shm.h"

#include "nsn/nsn.h"

// TODO: this should be a config file or something
#define NSNAPP_TO_NSND_IPC      "/tmp/nsnd_control_plane.socket"
#define NSND_TO_NSNAPP_IPC      "/tmp/nsn_app"
#define IPC_MAX_PATH_SIZE       108

#define NSN_MAX_RING_NAME_SIZE  64

// enum nsn_ipc_type
// {
//     nsn_ipc_type_none,
//     nsn_ipc_type_shmem,
//     nsn_ipc_type_socket
// };

enum nsn_cmsg_type
{
    NSN_CMSG_TYPE_NONE,             // message from daemon to app to notify an error
    NSN_CMSG_TYPE_ERROR,            // message from app to daemon to create a new instance
    NSN_CMSG_TYPE_CONNECT,          // message from daemon to app to confirm the creation of a new instance
    NSN_CMSG_TYPE_CONNECTED,        // message from app to daemon to create a new stream
    NSN_CMSG_TYPE_CREATE_STREAM,    // message from daemon to app to confirm the creation of a new stream
    NAN_CSMG_TYPE_CREATED_STREAM,   // message from app to daemon to destroy a stream
    NSN_CMSG_TYPE_DESTROY_STREAM,   // message from daemon to app to confirm the destruction of a stream
    NSN_CMSG_TYPE_DESTROYED_STREAM, // message from app to daemon to create a new source
    NSN_CMSG_TYPE_CREATE_SOURCE,    // message from daemon to app to confirm the creation of a new source
    NSN_CMSG_TYPE_CREATED_SOURCE,   // message from app to daemon to destroy a source
    NSN_CMSG_TYPE_DESTROY_SOURCE,   // message from app to daemon to create a new sink
    NSN_CMSG_TYPE_CREATE_SINK,      // message from daemon to app to confirm the creation of a sink
    NSN_CMSG_TYPE_CREATED_SINK,     // message from app to daemon to destroy a sink
    NSN_CMSG_TYPE_DESTROY_SINK,     // message from app to daemon to destroy an instance
    NSN_CMSG_TYPE_DISCONNECT,       // message from daemon to app to confirm the destruction of an instance
    NSN_CMSG_TYPE_DISCONNECTED,
};

typedef struct nsn_cmsg_hdr nsn_cmsg_hdr_t;
struct nsn_cmsg_hdr
{
    int type;
    int app_id;
};

typedef struct nsn_cmsg_connect nsn_cmsg_connect_t;
struct nsn_cmsg_connect
{
    char    shm_name[NSN_SHM_NAME_MAX];                 // The size of the shared memory segment in bytes
    usize   shm_size;                                   // The name of the free_slots ring
    char    free_slots_ring[NSN_MAX_RING_NAME_SIZE];    // Size of the io buffers
    size_t  io_buf_size;
};

typedef struct nsn_cmsg_create_stream nsn_cmsg_create_stream_t;
struct nsn_cmsg_create_stream
{
    u32             plugin_idx;                         // Index of the plugin this stream belongs to
    u32             stream_idx;                         // Index of the stream in the stream table
    nsn_options_t   opts;                               // QoS options
    char            tx_prod[NSN_MAX_RING_NAME_SIZE];    // Name of the tx_prod ring
};

typedef struct nsn_cmsg_create_source nsn_cmsg_create_source_t;
struct nsn_cmsg_create_source
{
    u32          plugin_idx;    // Index of the plugin the stream belongs to
    u32          stream_idx;    // Index of the associated stream
    nsn_source_t source_id;     // Id of the source
};

typedef struct nsn_cmsg_create_sink nsn_cmsg_create_sink_t;
struct nsn_cmsg_create_sink
{
    u32             plugin_idx;                         // Index of the plugin the stream belongs to
    nsn_stream_t    stream_idx;                         // Index of the associated stream
    nsn_sink_t      sink_id;                            // Id of the sink
    char            rx_cons[NSN_MAX_RING_NAME_SIZE];    // Name of the rx_cons ring

    // Local IPC peer (source) information
    struct {
        bool    is_local_peer_found;
        int     app_id;
        char    shm_name[NSN_SHM_NAME_MAX];
        usize   shm_size;
        usize   io_buf_size;

        // char    data_zone_name[NSN_ZONE_NAME_MAX];
        // char    meta_zone_name[NSN_ZONE_NAME_MAX];
        char    free_slots_ring[NSN_MAX_RING_NAME_SIZE];
    } peer;
};

#endif // NSN_IPC_H