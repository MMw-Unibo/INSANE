#ifndef INSANE_PRIVA_H
#define INSANE_PRIVA_H

#include "common.h"
#include "queue.h"

//-------------------------------------------------------------------------------------------------
#define INSANE_HEADER_LEN sizeof(nsn_hdr_t)

//--------------------------------------------------------------------------------------------------
// INSANE Header
//--------------------------------------------------------------------------------------------------
typedef struct nsn_hdr {
    u32 source_id;
} nsn_hdr_t;

//--------------------------------------------------------------------------------------------------
// INSANE Sink
//--------------------------------------------------------------------------------------------------
typedef struct nsn_sink_inner {
    i32            id;
    u32            source_id;
    mempool_type_t mptype;

    // nsn_queue_t *rx_prod;
    // nsn_queue_t *rx_cons;
    struct rte_ring *rx_prod;
    struct rte_ring *rx_cons;
} nsn_sink_inner_t;

//--------------------------------------------------------------------------------------------------
// INSANE Source
//--------------------------------------------------------------------------------------------------
typedef struct nsn_source_inner {
    u32            id;
    mempool_type_t mptype;
} nsn_source_inner_t;

#endif // INSANE_PRIVA_H
