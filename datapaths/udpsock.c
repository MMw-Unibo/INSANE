#include "../src/nsn_datapath.h"
#include "../src/nsn_string.c"
#include "../src/nsn_memory.c"
#include "../src/nsn_os_linux.c"
#include "../src/nsn_ringbuf.c"

#include <arpa/inet.h>
#include <netinet/in.h>

#define UDP_SOCKET_ADDR_MAX 64

// Currently, the state of the plugin is kept by the daemon under an opaque pointer,
// which is passed to the plugin functions. Alternatively, we could keep the state here
// and just exchange the stream index to select the correct state.
// The important thing to remember is that as streams are opened/closed, we should create/destroy
// the corresponding state in the plugin. TODO: find a way to efficiently do that without stalling
// the datapath.
struct udpsock_ep {
    u16  s_port;
    char s_addr[UDP_SOCKET_ADDR_MAX]; 
    int  s_sockfd;
    struct sockaddr_in sock_addr;
    nsn_buf_t pending_rx_buf;
};

static char*  local_ip;
static char** peers;
static u16    n_peers;

NSN_DATAPATH_UPDATE(udpsock)
{
    if (endpoint == NULL) {
        fprintf(stderr, "[udpsock] invalid endpoint\n");
        return -1;
    }

    // Case 1. Delete endpoint data.
    if(endpoint->data) {
        struct udpsock_ep *conn = (struct udpsock_ep *)endpoint->data;
        if (conn->s_sockfd != -1) {
            close(conn->s_sockfd);
        }
        nsn_ringbuf_enqueue_burst(endpoint->free_slots, &conn->pending_rx_buf, sizeof(conn->pending_rx_buf), 1, NULL);       
        free(endpoint->data);
        endpoint->data = NULL;
    } 
    // Case 2. Create endpoint data.
    else { 
        int fd = 0, flags = 0, reuseaddr = 0;

        // create the state of the endpoint, which will hold connection data
        endpoint->data = malloc(sizeof(struct udpsock_ep));
        if (endpoint->data == NULL) {
            fprintf(stderr, "malloc() failed\n");
            return -1;
        }
        endpoint->data_size = sizeof(struct udpsock_ep);

        // initialize the state of the endpoint 
        struct udpsock_ep *conn = (struct udpsock_ep *)endpoint->data;
        // Source address is the local_ip (config file)
        strcpy(conn->s_addr, local_ip);
        // Source port is the app_id
        conn->s_port = endpoint->app_id;
        if (conn->s_port == 0) {
            free(endpoint->data);
            fprintf(stderr, "[udpsock] invalid app_id %u\n", conn->s_port);
            return -1;
        }

        // get a descriptor to receive
        u32 np = nsn_ringbuf_dequeue_burst(endpoint->free_slots, &conn->pending_rx_buf, sizeof(conn->pending_rx_buf), 1, NULL);
        if (np == 0) {
            printf("[udpsock] No free slots to receive from ring %p [%u]\n", endpoint->free_slots, nsn_ringbuf_count(endpoint->free_slots));
            return -1;
        }

        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd == -1) {
            free(endpoint->data);
            fprintf(stderr, "[udpsock] socket() failed\n");
            return -1;
        }

        flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1) {
            close(fd);
            free(endpoint->data);
            fprintf(stderr, "[udpsock] fcntl() failed\n");
            return -1;
        }

        flags |= O_NONBLOCK;
        if (fcntl(fd, F_SETFL, flags) == -1) {
            close(fd);
            free(endpoint->data);
            fprintf(stderr, "[udpsock] fcntl() failed\n");
            return -1;
        }

        reuseaddr = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) == -1) {
            close(fd);
            free(endpoint->data);
            fprintf(stderr, "[udpsock] setsockopt() failed\n");
            return -1;
        }

        memory_zero_struct(&conn->sock_addr);
        conn->sock_addr.sin_family      = AF_INET;
        conn->sock_addr.sin_port        = htons(conn->s_port);
        conn->sock_addr.sin_addr.s_addr = inet_addr(conn->s_addr);
        if (bind(fd, (struct sockaddr *)&conn->sock_addr, sizeof(conn->sock_addr)) == -1) {
            close(fd);
            free(endpoint->data);
            fprintf(stderr, "[udpsock] bind() failed\n");
            return -1;
        }

        // finalize the initialization
        conn->s_sockfd = fd;
    }

    return 0;
}

NSN_DATAPATH_INIT(udpsock)
{
    // Initialize local state 
    n_peers = ctx->n_peers;
    peers = ctx->peers;
    local_ip = ctx->local_ip;

    // Setup the connections to the peers
    // TODO: Should we fail entirely if a peer cannot be reached? For the moment, yes.
    int ret = 0;
    ep_initializer_t *ep_in;
    list_for_each_entry(ep_in, endpoint_list, node) {
        ret = udpsock_datapath_update(ep_in->ep);
        if (ret < 0) {
            fprintf(stderr, "[udpsock] udpsock_datapath_update() failed\n");
            return ret;
        }
    }

    return ret;
}

NSN_DATAPATH_TX(udpsock)
{
    isize ret = 0;
    usize i;
    int tx_count = 0;

    struct udpsock_ep *conn = (struct udpsock_ep *)endpoint->data;

    struct sockaddr_in send_addr;
    send_addr.sin_family = AF_INET;
    send_addr.sin_port = htons(endpoint->app_id);

    for (i = 0; i < buf_count; i++) {
        // Get the data and size from the index
        char* data = (char*)(endpoint->tx_zone + 1) + (bufs[i].index * endpoint->io_bufs_size); 
        usize size = ((nsn_meta_t*)(endpoint->tx_meta_zone + 1) + bufs[i].index)->len;        

        // Send the buf to all the peers
        for(int p = 0; p < n_peers; p++) {
            // printf("[udpsock] Sending to %s\n", peers[p]);
            inet_pton(AF_INET, peers[p], &send_addr.sin_addr);
            while((ret = sendto(conn->s_sockfd, data, size, 0, (struct sockaddr *)&send_addr, sizeof(send_addr))) < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    printf("[udpsock] sendto() failed: %s\n", strerror(errno));
                    return tx_count;
                }
            }
        }
        tx_count++;
    }

    // Free the descriptors after using them
    if(nsn_ringbuf_enqueue_burst(endpoint->free_slots, bufs, sizeof(bufs[0]), buf_count, NULL) < buf_count) {
        fprintf(stderr, "[udpsock] Failed to enqueue %lu descriptors\n", buf_count);
    }

    return tx_count;
}

NSN_DATAPATH_RX(udpsock)
{
    struct udpsock_ep *ep_sk = (struct udpsock_ep *)endpoint->data;

    isize ret = 0;
    usize i   = 0;

    // set the receive buffer
    bufs[i]     = ep_sk->pending_rx_buf;
    char *data  = (char*)(endpoint->tx_zone + 1) + (bufs[i].index * endpoint->io_bufs_size);    
    usize *size = &((nsn_meta_t*)(endpoint->tx_meta_zone + 1) + bufs[i].index)->len;

    // In UDP, we receive 1 pkt per time - no burst receive
    if ((ret = recvfrom(ep_sk->s_sockfd, data, endpoint->io_bufs_size, 0, NULL, NULL)) > 0) {
        // Update the pending tx descriptor
        u32 np = nsn_ringbuf_dequeue_burst(endpoint->free_slots, &ep_sk->pending_rx_buf, sizeof(ep_sk->pending_rx_buf), 1, NULL);
        if (np == 0) {
            printf("[udpsock] No free slots for next receive! Ring: %p [count %u]\n", endpoint->free_slots, nsn_ringbuf_count(endpoint->free_slots));
        }
        // printf("[udpsock] Received %ld bytes idx = %lu\n", ret, bufs[i].index);
        // Set the size as packet metadata
        *size = ret;
        i++;
        *buf_count = *buf_count - 1;
    } else {
        if( 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            // Something failed 
            printf("recvfrom() failed: %s\n", strerror(errno));        
            return i;
        }
    } 

    return i;
}

NSN_DATAPATH_DEINIT(udpsock)
{
    nsn_unused(ctx);

    int res = 0;
    struct ep_initializer *ep_in;
    list_for_each_entry(ep_in, endpoint_list, node) {
        res = udpsock_datapath_update(ep_in->ep);
        if (res < 0) {
            fprintf(stderr, "[udpsock] udpsock_datapath_update() failed\n");
            return res;
        }
    }

    n_peers = 0;
    peers = NULL;
    local_ip = NULL;

    return res;
}