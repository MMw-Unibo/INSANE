#ifndef INSANE_ROUTE_H
#define INSANE_ROUTE_H

#include "common.h"
#include "list.h"
#include "netdev.h"
#include "runtime.h"

#define ROUTE_LOOPBACK (1 << 0) // 0x01
#define ROUTE_GATEWAY  (1 << 1) // 0x02
#define ROUTE_HOST     (1 << 2) // 0x04
#define ROUTE_REJECT   (1 << 3) // 0x08
#define ROUTE_UP       (1 << 4) // 0x10

//--------------------------------------------------------------------------------------------------
// Route Entry
//--------------------------------------------------------------------------------------------------
typedef struct route_entry {
    list_head_t list;

    u32 dst;
    u32 gateway;
    u32 netmask;
    u8  flags;
    u32 metric;

    netdev_t *dev;
} route_entry_t;

//--------------------------------------------------------------------------------------------------

void route__init(nsn_runtime_t *nsnrt);

void routes_delete();

route_entry_t *route_lookup(u32 dst_addr);

#endif // INSANE_ROUTE_H
