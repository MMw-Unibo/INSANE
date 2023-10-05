#ifndef INSANE_RUNTIME_H
#define INSANE_RUNTIME_H

#include <rte_mbuf.h>

#include "common.h"
#include "mem_manager.h"
#include "netdev.h"
#include "queue.h"

#define MAX_APPS 20

//--------------------------------------------------------------------------------------------------
//    INSANE Runtime
//--------------------------------------------------------------------------------------------------
typedef struct nsn_runtime {
    u16 port_id;
    u16 queue_id;
    u16 daemon_udp_port;

    nsn_memmanager_t mem_manager;

    int apps_ipc[MAX_APPS];
    int n_apps;

    netdev_t *dev;
    netdev_t *dst_dev;
} nsn_runtime_t;

#endif // INSANE_RUNTIME_H
