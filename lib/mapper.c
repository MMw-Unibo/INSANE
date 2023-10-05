#include "mapper.h"

// TODO: Base this decision on both user choices and technology available.
// If datapath_slow => always socket
// If datapath_fase => RDMA, if available
//                  => DPDK, if consumption_high
//                  => XDP,  if consumption_low

mempool_type_t map_qos_to_transport(nsn_options_t *options) {
    mempool_type_t res;

    if (options->datapath == datapath_fast && options->consumption == consumption_high) {
        res = mempool_dpdk;
    } else {
        res = mempool_socket;
    }

    return res;
}
