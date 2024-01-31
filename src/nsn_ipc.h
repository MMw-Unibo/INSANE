#ifndef NSN_IPC_H
#define NSN_IPC_H

#include "nsn_types.h"

// TODO: this should be a config file or something
#define NSNAPP_TO_NSND_IPC    "/tmp/nsnd_control_plane.socket"
#define NSND_TO_NSNAPP_IPC    "/tmp/nsn_app"
#define IPC_MAX_PATH_SIZE     108

// enum nsn_ipc_type
// {
//     nsn_ipc_type_none,
//     nsn_ipc_type_shmem,
//     nsn_ipc_type_socket
// };

enum nsn_cmsg_type
{
    nsn_cmsg_type_none,
    // message from daemon to app to notify an error
    nsn_cmsg_type_error,
    // message from app to daemon to create a new instance
    nsn_cmsg_type_connect,          
    // message from daemon to app to confirm the creation of a new instance
    nsn_cmsg_type_connected,
    // message from app to daemon to destroy an instance
    nsn_cmsg_type_disconnect,
    // message from daemon to app to confirm the destruction of an instance
    nsn_cmsg_type_disconnected,
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
#define NSN_MAX_PATH_SIZE 64
    char  shm_name[NSN_MAX_PATH_SIZE];
};

#endif // NSN_IPC_H