#ifndef INSANE_PKTMETA_H
#define INSANE_PKTMETA_H

#include "common.h"

//--------------------------------------------------------------------------------------------------
// Packet Metadata
//--------------------------------------------------------------------------------------------------
typedef enum nsn_pktproto {
    nsn_proto_ipv4_udp,
    nsn_proto_arp,
} nsn_pktproto_t;

typedef struct nsn_pktmeta {
    nsn_pktproto_t proto;
    i32            payload_len;
    i32            total_len;
} nsn_pktmeta_t;

#endif // INSANE_PKTMETA_H
