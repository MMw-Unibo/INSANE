#ifndef NSN_DATAPATH_H
#define NSN_DATAPATH_H

#include "nsn_types.h"

typedef struct nsn_datapath_ctx nsn_datapath_ctx_t;
struct nsn_datapath_ctx
{
    void  *data_memory;
    usize  data_memory_size;

    char configs[256];
};

typedef struct nsn_buf nsn_buf_t;
struct nsn_buf
{
    void  *data;
    usize  size;
};

#define NSN_DATAPATH_INIT(name)                 int name##_datapath_init(nsn_datapath_ctx_t *ctx)
typedef NSN_DATAPATH_INIT(nsn);
#define NSN_DATAPATH_TX(name)                   int name##_datapath_tx(nsn_buf_t *bufs, usize buf_count)
typedef NSN_DATAPATH_TX(nsn);
#define NSN_DATAPATH_RX(name)                   int name##_datapath_rx(nsn_buf_t *bufs, usize *buf_count)
typedef NSN_DATAPATH_RX(nsn);
#define NSN_DATAPATH_DEINIT(name)               int name##_datapath_deinit(nsn_datapath_ctx_t *ctx)
typedef NSN_DATAPATH_DEINIT(nsn);

#endif // NSN_DATAPATH_H