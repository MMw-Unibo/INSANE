#ifndef INSANE_NETDEV_H
#define INSANE_NETDEV_H

#include "common.h"
#include "ethernet.h"

//--------------------------------------------------------------------------------------------------
//    Network device
//--------------------------------------------------------------------------------------------------
typedef struct netdev {
    u32 addr;
    u8  addr_len;
    u8  hw_addr[ETHERNET_ADDRESS_LEN];
    u32 mtu;
} netdev_t;

//--------------------------------------------------------------------------------------------------

netdev_t *netdev__init(char *addr, char *hw_addr, u32 mtu);

void netdev__delete(netdev_t *dev);

#endif // INSANE_NETDEV_H
