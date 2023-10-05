#include "route.h"
#include "ip.h"

static NSN_LIST_HEAD(routes);

//--------------------------------------------------------------------------------------------------
static route_entry_t *__route__alloc(u32 dest, u32 gateway, u32 netmask, u8 flags, u32 metric,
                                     netdev_t *dev) {
    route_entry_t *route = malloc(sizeof(route_entry_t));

    route->dst     = dest;
    route->gateway = gateway;
    route->netmask = netmask;
    route->flags   = flags;
    route->metric  = metric;
    route->dev     = dev;

    list__init(&route->list);

    return route;
}

//--------------------------------------------------------------------------------------------------
static void __route__add(u32 dest, u32 gateway, u32 netmask, u8 flags, u32 metric, netdev_t *dev) {
    route_entry_t *route = __route__alloc(dest, gateway, netmask, flags, metric, dev);

    list__add_tail(&routes, &route->list);
}

//--------------------------------------------------------------------------------------------------
void route__init(nsn_runtime_t *nsnrt) {
    __route__add(nsnrt->dev->addr, 0, 0xffffff00, ROUTE_HOST, 0, nsnrt->dev);
}

//--------------------------------------------------------------------------------------------------
void routes_delete() {
    list_head_t   *item, *tmp;
    route_entry_t *route;

    list_for_each_safe(item, tmp, &routes) {
        route = list_entry(item, route_entry_t, list);
        list__del(item);

        free(route);
    }
}

//--------------------------------------------------------------------------------------------------
route_entry_t *route_lookup(u32 dst_addr) {
    list_head_t   *item;
    route_entry_t *rt = NULL;
    list_for_each(item, &routes) {
        rt = list_entry(item, route_entry_t, list);
        if ((dst_addr & rt->netmask) == (rt->dst & rt->netmask))
            break;
    }

    return rt;
}
