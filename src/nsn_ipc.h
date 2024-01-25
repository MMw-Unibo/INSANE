#ifndef NSN_IPC_H
#define NSN_IPC_H

#include "nsn_types.h"

// TODO: this should be a config file or something
#define REQUEST_IPC_PATH    "/tmp/nsnd_control_plane.socket"

// enum nsn_ipc_type
// {
//     nsn_ipc_type_none,
//     nsn_ipc_type_shmem,
//     nsn_ipc_type_socket
// };

enum nsn_msg_type
{
    nsn_msg_type_none,
    nsn_msg_type_connect,
    nsn_msg_type_disconnect,
    nsn_msg_type_data
};

struct nsn_request
{
    int type;
    int id;
};

#endif // NSN_IPC_H