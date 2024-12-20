#include "../src/nsn_datapath.h"
#include "../src/nsn_config.c"
#include "../src/nsn_string.c"
#include "../src/nsn_memory.c"
#include "../src/nsn_ringbuf.c"
#include "../src/nsn_os_linux.c"

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_flow.h>

// This DPDK plugin assumes we are working with NICs that use the mlx5 driver.
// We need RSS filtering to enable the zero-copy receive, because we can associate
// different mempools with different queues, i.e., different applications. 
// However, the mlx5 driver does not allow to have just some queues active and some
// stopped (as DPDK would allow with rx_deferred starte). So we need to configure and
// start a number of queues (MAX_DEVICE_QUEUES) which will be active immediately.
// Hence, we set the rte_isolate_flow() to ensure that a queue only receives packets
// matching its RSS flow rule. This has some implications:
// - we need to create a rule to receive ARP packets on queue 0 (control queue)
// - isolate() works only for bifurcated drivers: other drivers will need code to 
//     ensure that all traffic not matching the RSS ruls of other queues is received
//     on queue 0 (or dropped)
// - we did not include rte_queue_start() logic which will be nice to have when supported


#define MAX_PARAM_STRING_SIZE 2048
#define MAX_DEVICE_QUEUES     16    // Must be at least 2

// Local state
static char** peers;
static u16    n_peers;
static char*  local_ip;
static struct rte_ether_addr local_mac_addr;
static u16    port_id;
static nsn_ringbuf_t *free_queue_ids;
struct rte_mempool *rx_ctrl_pool;
static temp_mem_arena_t scratch;
struct rte_flow *rx_arp_flow;

// Per-endpoint state
struct udpdpdk_ep {
    u16 queue_id;
    struct rte_mempool *rx_pool;
    struct rte_flow *app_flow;
    nsn_buf_t pending_rx_buf;
};

static struct rte_flow * 
configure_udp_rss_flow(u16 port_id, u16 queue_id, uint16_t udp_port, struct rte_flow_error *error) {
    struct rte_flow_attr         attr;
    struct rte_flow_item         pattern[4];
    struct rte_flow_item_eth     item_eth_mask = {};
    struct rte_flow_item_eth     item_eth_spec = {};
    struct rte_flow_item_ipv4    ipv4_spec;
    struct rte_flow_item_ipv4    ipv4_mask;
    struct rte_flow_item_udp     udp_spec;
    struct rte_flow_item_udp     udp_mask;
    struct rte_flow_action       action[2];
    struct rte_flow             *flow  = NULL;
    struct rte_flow_action_queue queue = {.index = queue_id};
    int                          err;

    bzero(&attr, sizeof(attr));
    bzero(pattern, sizeof(pattern));
    bzero(action, sizeof(action));

    // rule attr
    attr.ingress = 1;

    // action sequence
    action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    action[0].conf = &queue;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    // patterns
    item_eth_spec.hdr.ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4);
    item_eth_mask.hdr.ether_type = RTE_BE16(0xFFFF);
    pattern[0].type              = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[0].mask              = &item_eth_mask;
    pattern[0].spec              = &item_eth_spec;

    bzero(&ipv4_spec, sizeof(ipv4_spec));
    ipv4_spec.hdr.next_proto_id = 0x11; // UDP only
    inet_pton(AF_INET, local_ip, &ipv4_spec.hdr.dst_addr); // Local IP only
    bzero(&ipv4_mask, sizeof(ipv4_mask));
    ipv4_mask.hdr.next_proto_id = 0xff; // UDP Mask
    // ipv4_mask.hdr.dst_addr      = 0xffffffff; // This is not supported by the Intel IGC driver
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    // pattern[1].spec = &ipv4_spec;      // This is not supported by the Intel i40e driver
    // pattern[1].mask = &ipv4_mask;      // This is not supported by the Intel i40e driver
    pattern[1].last = NULL;

    bzero(&udp_spec, sizeof(udp_spec));
    udp_spec.hdr.dst_port = RTE_BE16(udp_port); // UDP port
    bzero(&udp_mask, sizeof(udp_mask));
    udp_mask.hdr.dst_port = 0xffff;
    pattern[2].type       = RTE_FLOW_ITEM_TYPE_UDP;
    pattern[2].spec       = &udp_spec;
    pattern[2].mask       = &udp_mask;
    pattern[2].last       = NULL;

    pattern[3].type = RTE_FLOW_ITEM_TYPE_END;

    err = rte_flow_validate(port_id, &attr, pattern, action, error);
    if (!err) {
        flow = rte_flow_create(port_id, &attr, pattern, action, error);
    }

    return flow;
}

static struct rte_flow *
configure_arp_rss_flow(u16 port_id, u16 queue_id, struct rte_flow_error *error) {
    struct rte_flow_attr         attr;
    struct rte_flow_item         pattern[2];
    struct rte_flow_item_eth     item_eth_mask = {};
    struct rte_flow_item_eth     item_eth_spec = {};
    struct rte_flow_action       action[2];
    struct rte_flow             *flow  = NULL;
    struct rte_flow_action_queue queue = {.index = queue_id};
    int                          err;

    bzero(&attr, sizeof(attr));
    bzero(pattern, sizeof(pattern));
    bzero(action, sizeof(action));

    // rule attr
    attr.ingress = 1;

    // action sequence
    action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    action[0].conf = &queue;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    // patterns
    // TODO: There is a specific enum for ARP but I was not able to use it
    item_eth_spec.hdr.ether_type = RTE_BE16(RTE_ETHER_TYPE_ARP);
    item_eth_mask.hdr.ether_type = RTE_BE16(0xFFFF);

    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[0].mask = &item_eth_mask;
    pattern[0].spec = &item_eth_spec;
    pattern[1].type = RTE_FLOW_ITEM_TYPE_END;

    err = rte_flow_validate(port_id, &attr, pattern, action, error);
    if (!err) {
        flow = rte_flow_create(port_id, &attr, pattern, action, error);
    }

    return flow;
}


NSN_DATAPATH_UPDATE(udpdpdk) {
    if (endpoint == NULL) {
        fprintf(stderr, "[udpdpdk] invalid endpoint\n");
        return -1;
    }

    // Case 1. Delete endpoint data.
    if(endpoint->data) {
        struct udpdpdk_ep *conn = (struct udpdpdk_ep *)endpoint->data;
        
        // Return the pending buffer to the free slots
        nsn_ringbuf_enqueue_burst(endpoint->free_slots, &conn->pending_rx_buf, sizeof(conn->pending_rx_buf), 1, NULL);

        // Destroy the flow
        if (conn->app_flow) {
            rte_flow_destroy(port_id, conn->app_flow, NULL);
        }

        // Stop the device queue
        rte_eth_dev_rx_queue_stop(port_id, conn->queue_id);

        // Enqueue the queue_id in the free queue_ids
        nsn_ringbuf_enqueue_burst(free_queue_ids, &conn->queue_id, sizeof(void*), 1, NULL);

        // Free the ep data and clean the ep state
        free(endpoint->data);
        endpoint->data = NULL;
        endpoint->data_size = 0;

        // Stop the queue
        int ret = rte_eth_dev_rx_queue_stop(port_id, conn->queue_id);
    } 
    // Case 2. Create endpoint data.
    else { 
        if (nsn_ringbuf_count(free_queue_ids) == 0) {
            fprintf(stderr, "[udpdpdk] No free queues left for the application\n");
            return -1;
        }

        // create the state of the endpoint, which will hold connection data
        endpoint->data = malloc(sizeof(struct udpdpdk_ep));
        if (endpoint->data == NULL) {
            fprintf(stderr, "[udpdpdk] malloc() failed\n");
            return -1;
        }
        endpoint->data_size = sizeof(struct udpdpdk_ep);

        // Initialize the state of the endpoint
        struct udpdpdk_ep *conn = (struct udpdpdk_ep*)endpoint->data;

        // Assign a queue to this application
        u64 queue_id;
        nsn_ringbuf_dequeue_burst(free_queue_ids, &queue_id, sizeof(void*), 1, NULL);
        conn->queue_id = queue_id;

        // get a descriptor to receive
        u32 np = nsn_ringbuf_dequeue_burst(endpoint->free_slots, &conn->pending_rx_buf, sizeof(conn->pending_rx_buf), 1, NULL);
        if (np == 0) {
            printf("[udpsock] No free slots to receive from ring %p [%u]\n", endpoint->free_slots, nsn_ringbuf_count(endpoint->free_slots));
            free(conn);
            return -1;
        }

        // Retrieve the mempool for the associated RX queue
        // TODO: we will need an indirect mempool for the zero-copy receive
        char pool_name[64];
        sprintf(pool_name, "rx_pool_%u", conn->queue_id);
        conn->rx_pool = rte_mempool_lookup(pool_name);
        if (conn->rx_pool == NULL) {
            fprintf(stderr, "[udpdpdk] failed to create mempool\n");
            nsn_ringbuf_enqueue_burst(endpoint->free_slots, &conn->pending_rx_buf, sizeof(conn->pending_rx_buf), 1, NULL); 
            free(conn);
            return -1;
        }

        // TODO: Create the tx direct and indirect mempool, and possibly prepare the headers (at least for the local part)

        // Now create the RSS filter on that queue for this endpoint's UDP port
        struct rte_flow_error flow_error;
        conn->app_flow = configure_udp_rss_flow(port_id, conn->queue_id, endpoint->app_id, &flow_error);
        if (conn->app_flow == NULL) {
            fprintf(stderr, "[udpdpdk] failed to create flow: %s\n", flow_error.message ? flow_error.message : "unkown");
            nsn_ringbuf_enqueue_burst(endpoint->free_slots, &conn->pending_rx_buf, sizeof(conn->pending_rx_buf), 1, NULL); 
            free(conn);
            return -1;
        }

        // Start the queue
        int ret = rte_eth_dev_rx_queue_start(port_id, conn->queue_id);
        if (ret < 0) {
            fprintf(stderr, "[udpdpdk] failed to start queue %u: %s\n", conn->queue_id, strerror(ret));
            rte_flow_destroy(port_id, conn->app_flow, NULL);
            nsn_ringbuf_enqueue_burst(endpoint->free_slots, &conn->pending_rx_buf, sizeof(conn->pending_rx_buf), 1, NULL); 
            free(conn);
            return -1;
        }
    }
    return 0;
}

NSN_DATAPATH_CONN_MANAGER(udpdpdk)
{
    // Because this gets called periodically, we can put here the management of queue 0,
    // which is used for control messages (e.g., ARP).

    // For each endpoint, receive a burst of packets (=> ARP requests)
    // and answer them with ARP replies
    nsn_unused(endpoint_list);
    return 0;
}

NSN_DATAPATH_INIT(udpdpdk)
{
    nsn_thread_ctx_t this_thread = nsn_thread_ctx_alloc();
    this_thread.is_main_thread   = false;
    nsn_thread_set_ctx(&this_thread);

    scratch = nsn_thread_scratch_begin(NULL, 0);

    // 1a) Initialize local state 
    n_peers = ctx->n_peers;
    peers = ctx->peers;
    
    // 1b) Retrieve the local IP from the list of parameters
    string_t local_ip_str;
    local_ip_str.data = mem_arena_push(scratch.arena, MAX_PARAM_STRING_SIZE);
    local_ip_str.len = 0;
    int ret = nsn_config_get_string_from_list(&ctx->params, str_lit("ip"), &local_ip_str);
    if (ret < 0) {
        fprintf(stderr, "[udpdpdk] nsn_config_get_string_from_list() failed: no option \"ip\" found\n");
        goto early_fail;
    }
    local_ip = to_cstr(local_ip_str);
    fprintf(stderr, "[udpdpdk] parameter: ip: %s\n", local_ip);

    // 2a) Get the EAL parameters: first as a single string, then as parameters
    string_t eal_args;
    eal_args.data = (u8*)malloc(MAX_PARAM_STRING_SIZE);
    eal_args.len = 0;
    ret = nsn_config_get_string_from_list(&ctx->params, str_lit("eal_args"), &eal_args);
    if (ret < 0) {
        fprintf(stderr, "[udpdpdk] nsn_config_get_string_from_list() failed: no option \"eal_args\" found\n");
        goto early_fail;
    }
    fprintf(stderr, "[udpdpdk] parameter: eal_args: %s\n", to_cstr(eal_args));
    char* argv [MAX_PARAM_STRING_SIZE];
    int argc = 1;
    string_t delimiter = str_lit(" ");
    string_list_t eal_args_list = str_split(scratch.arena, eal_args, &delimiter, 1);
    argv[0] = mem_arena_push(scratch.arena, strlen("udpdpdk") + 1);
    strcpy(argv[0], "udpdpdk");
    for(string_node_t *node = eal_args_list.head; node; node = node->next) {
        argv[argc] = mem_arena_push(scratch.arena, node->string.len + 1); // does this memory need to be freed explicitly? especially in case of error (return -1)?
        strncpy(argv[argc], to_cstr(node->string), node->string.len);
        argc++;
    }
    
    // 2b) Get the DPDK device name
    string_t dev_name_str;
    dev_name_str.data = mem_arena_push(scratch.arena, MAX_PARAM_STRING_SIZE);
    dev_name_str.len = 0;
    ret = nsn_config_get_string_from_list(&ctx->params, str_lit("pci_device"), &dev_name_str);
    if (ret < 0) {
        fprintf(stderr, "[udpdpdk] nsn_config_get_string_from_list() failed: no option \"pci_device\" found\n");
        goto early_fail;
    }
    char* dev_name = to_cstr(dev_name_str);
    fprintf(stderr, "[udpdpdk] parameter: dev_name: %s\n", dev_name);

    // Now, finally, initialize EAL
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        fprintf(stderr, "[udpdpdk] rte_eal_init failed: %s\n", rte_strerror(rte_errno));
        goto early_fail;
    }

    // Select the desired device
    bool                    found = false;
    struct rte_eth_dev_info devinfo;
    RTE_ETH_FOREACH_DEV(port_id) {
        ret = rte_eth_dev_info_get(port_id, &devinfo);
        if (ret < 0) {
            fprintf(stderr, "[udpdpdk] cannot get info for port %u: %s, skipping\n", port_id,
                   rte_strerror(rte_errno));
            continue;
        }
        if(strcmp(rte_dev_name(devinfo.device), dev_name) == 0) {
            fprintf(stderr, "[udpdpdk] found device %s on port %u\n", dev_name, port_id);
            found = true;
            break;
        }
    }
    if (!found) {
        fprintf(stderr, "[udpdpdk] device %s not found\n", dev_name);
        goto fail;
    }

    int socket_id = rte_eth_dev_socket_id(port_id);    
    if (socket_id < 0) {
        if (rte_errno) {
            fprintf(stderr, "[udpdpdk] cannot get socket id: %s\n", rte_strerror(rte_errno));
            goto fail;
        } else {
            socket_id = rte_socket_id();
        }
    } else if (socket_id != (int)rte_socket_id()) {
        fprintf(stderr, "[udpdpdk] Warning: running on a different socket than that the NIC is attached to!\n");
        goto fail;
    }

    // Get the local MAC address
    ret = rte_eth_macaddr_get(port_id, &local_mac_addr);
    if (ret < 0) {
        fprintf(stderr, "[udpdpdk] failed to get MAC address for port %u: %s\n", port_id,
                  rte_strerror(rte_errno));
        goto fail;
    }

    // Create a mempool to receive "spare" data, i.e., data not associated to any endpoint,
    // e.g., for ARP and possibly control messages
    rx_ctrl_pool = rte_pktmbuf_pool_create("rx_ctrl", 10239, 64, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);
    if (rx_ctrl_pool == NULL) {
        fprintf(stderr, "[udpdpdk] failed to create mempool\n");
        goto fail;
    }

    // Configure the port
    struct rte_eth_conf port_conf;
    bzero(&port_conf, sizeof(port_conf));
    // port_conf.rxmode.mtu = MTU;
    port_conf.rxmode.offloads |= (RTE_ETH_RX_OFFLOAD_CHECKSUM | RTE_ETH_RX_OFFLOAD_SCATTER);
    port_conf.txmode.mq_mode  = RTE_ETH_MQ_TX_NONE;
    port_conf.txmode.offloads |= (RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_MULTI_SEGS);
    if (devinfo.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
    }
    // if ((ret = rte_eth_dev_set_mtu(port_id, MTU)) != 0) {
    //     fprintf(stderr, "[udpdpdk] setting mtu failed: %s\n", rte_strerror(rte_errno));
    //     goto fail;
    // }
    uint16_t nb_rxd = 1024;
    uint16_t nb_txd = 1024;
    if ((ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd)) != 0) {
        fprintf(stderr, "[udpdpdk] error setting tx and rx descriptors: %s\n", rte_strerror(rte_errno));
        goto fail;;
    }

    // Isolate the flow - only allow traffic that is specified by the flow rules (RSS filter)
    // i.e., ARP on queue 0 and UDP to app_id port on the other queues
    struct rte_flow_error error;
    ret = rte_flow_isolate(port_id, 1, &error);
    if (ret < 0) {
        fprintf(stderr, "[udpdpdk] failed to isolate traffic: %s\n", error.message? error.message : rte_strerror(rte_errno));
        goto fail;
    }

    // Configure the queues. We have:
    // - A single tx queue
    // - n_peers rx queues + 1 (queue 0) for control messages.
    uint16_t tx_queues = 1;
    uint16_t rx_queues = MAX_DEVICE_QUEUES;
    if ((ret = rte_eth_dev_configure(port_id, rx_queues, tx_queues, &port_conf)) != 0) {
        fprintf(stderr, "[udpdpdk] error configuring device queues: %s\n", rte_strerror(rte_errno));
        goto fail;;
    }

    // Configure the tx queue
    nb_rxd = 1024;
    nb_txd = 1024;
    struct rte_eth_txconf txconf = devinfo.default_txconf;
    txconf.offloads              = port_conf.txmode.offloads;
    if ((ret = rte_eth_tx_queue_setup(port_id, 0, nb_txd, socket_id, &txconf)) != 0) {
        fprintf(stderr, "[udpdpdk] failed configuring tx queue 0: %s\n", rte_strerror(rte_errno));
        goto fail;
    } 

    // Prepare a ring to store the "free" queue IDs
    u32 ring_size = rte_align32pow2(rx_queues);
    void *ring_memory = mem_arena_push(scratch.arena, sizeof(nsn_ringbuf_t) + (sizeof(void*) * ring_size));
    free_queue_ids = nsn_ringbuf_create(ring_memory, str_lit("free_queue_ids"), ring_size);

    // Configure the rx queues: queue 0 to start immediately
    if ((ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd, socket_id, NULL, rx_ctrl_pool)) != 0) {
        fprintf(stderr, "[udpdpdk] failed configuring rx queue %u: %s\n", 0, rte_strerror(rte_errno));
        goto fail;
    }

    // The remaining queues are confgured with "deferred start"
    // NOTE: mlx5 driver does not support deferred start, so this will have no effect.
    // But other drivers might support it, so we leave it.
    struct rte_eth_rxconf rx_conf = devinfo.default_rxconf;
    rx_conf.rx_deferred_start = 1;
    char pool_name[64];
    struct rte_mempool *rx_pool;
    for (uint16_t i = 1; i < rx_queues; i++) {
        // Create a mempool for the queue (will be retrieved later by the endpoint, using name)
        // TODO: In the final version, this mempool should ideally be an external mempool,
        // where each mbuf actually points to a slot in the shared memory of this app.
        // For the moment, we just create a local mempool and copy the data on receive.
        bzero(pool_name, 64);
        sprintf(pool_name, "rx_pool_%u", i);
        if ((rx_pool = rte_pktmbuf_pool_create(pool_name, 10239, 64, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id)) == NULL) {
            fprintf(stderr, "[udpdpdk] failed to create mempool\n");
            goto fail;
        }

        // Setup the queue using that mempool
        if ((ret = rte_eth_rx_queue_setup(port_id, i, nb_rxd, socket_id, &rx_conf, rx_pool)) != 0) {
            fprintf(stderr, "[udpdpdk] failed configuring rx queue %u: %s\n", i, rte_strerror(rte_errno));
            goto fail;
        }

        // Put the queue id in the ring
        nsn_ringbuf_enqueue_burst(free_queue_ids, &i, sizeof(void*), 1, NULL);
    }

    // Start the device
    ret = -EAGAIN;
    while (ret == -EAGAIN) {
        ret = rte_eth_dev_start(port_id);
    };
    if (ret) {
        fprintf(stderr, "[udpdpdk] impossible to start device: %s\n", rte_strerror(rte_errno));
        goto fail;
    }

    // ARP packets to be received on queue 0
    rx_arp_flow = configure_arp_rss_flow(port_id, 0, &error);    
    if (rx_arp_flow == NULL) {
        fprintf(stderr, "[udpdpdk] failed to create ARP flow: %s\n", error.message? error.message : rte_strerror(rte_errno));
        goto fail_and_stop;
    }

    // Stop the queues that are not used. This is necessary because some drivers, such as mlx5,
    // do not support deferred start, and all queues are started immediately.
    for (uint16_t i = 1; i < rx_queues; i++) {
        ret = rte_eth_dev_rx_queue_stop(port_id, i);
        if (ret < 0) {
            fprintf(stderr, "[udpdpdk] failed to stop queue %u: %s\n", i, rte_strerror(rte_errno));
        }
    }

    // Setup the communication channels to the peers
    // This will enable the FLOW RULES, only for the queues that are actually used
    ep_initializer_t *ep_in;
    list_for_each_entry(ep_in, endpoint_list, node) {
        ret = udpdpdk_datapath_update(ep_in->ep);
        if (ret < 0) {
            fprintf(stderr, "[udpdpdk] udpdpdk_datapath_update() failed\n");
            goto fail_and_stop;
        }
    }

    return 0;

fail_and_stop:
    rte_eth_dev_stop(port_id);
fail:
    rte_eal_cleanup();
early_fail:    
    nsn_thread_scratch_end(scratch);
    return -1;
}

NSN_DATAPATH_TX(udpdpdk)
{
    nsn_unused(bufs);
    nsn_unused(endpoint);

    fprintf(stderr, "[udpdpdk] Unimplemented datapath tx\n");

    return buf_count;
}

NSN_DATAPATH_RX(dpdk)
{
    nsn_unused(bufs);
    nsn_unused(endpoint);

    fprintf(stderr, "[udpdpdk] Unimplemented datapath rx\n");
    return (int)*buf_count;
}

NSN_DATAPATH_DEINIT(udpdpdk)
{
    nsn_unused(ctx);

    int res = 0;
    struct ep_initializer *ep_in;
    list_for_each_entry(ep_in, endpoint_list, node) {
        res = udpdpdk_datapath_update(ep_in->ep);
        if (res < 0) {
            fprintf(stderr, "[udpdpdk] failed cleanup of endpoint %d\n", ep_in->ep->app_id);
        }
    }

    // Stop the device (and all queues, consequently)
    rte_eth_dev_stop(port_id);
    // Clean up DPDK - BUT DOES THIS WORK?
    rte_eal_cleanup();

    // Destroy the scratch memory
    nsn_thread_scratch_end(scratch);

    return 0;
}
