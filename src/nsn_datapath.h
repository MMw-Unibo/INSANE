#ifndef NSN_DATAPATH_H
#define NSN_DATAPATH_H

#include "nsn_types.h"

struct nsn_datapath_ctx
{
    volatile int running;

    void  *data_memory;
    usize  data_memory_size;

    void *configs;
};

#define NSN_DATAPATH_INIT(name)                     int name##_datapath_init(struct nsn_datapath_ctx *ctx)
typedef NSN_DATAPATH_INIT(nsn);
#define NSN_DATAPATH_TX(name)                       int name##_datapath_tx(struct nsn_datapath_ctx *ctx)
typedef NSN_DATAPATH_TX(nsn);
#define NSN_DATAPATH_RX(name)                       int name##_datapath_rx(struct nsn_datapath_ctx *ctx)
typedef NSN_DATAPATH_RX(nsn);
#define NSN_DATAPATH_DEINIT(name)                   int name##_datapath_deinit(struct nsn_datapath_ctx *ctx)
typedef NSN_DATAPATH_DEINIT(nsn);

#endif // NSN_DATAPATH_H