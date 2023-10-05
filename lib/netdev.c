#include "netdev.h"

#include "ip.h"

//--------------------------------------------------------------------------------------------------
netdev_t *netdev__init(char *addr, char *hw_addr, u32 mtu) {
    netdev_t *dev = malloc(sizeof(netdev_t));

    i32 res = ip_parse(addr, &dev->addr);
    if (res < 0)
        goto err;

    sscanf(hw_addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &dev->hw_addr[0], &dev->hw_addr[1],
           &dev->hw_addr[2], &dev->hw_addr[3], &dev->hw_addr[4], &dev->hw_addr[5]);

    dev->addr_len = 6;
    dev->mtu      = mtu;

    return dev;

err:
    free(dev);
    return NULL;
}

//--------------------------------------------------------------------------------------------------
void netdev__delete(netdev_t *dev) {
    free(dev);
}
