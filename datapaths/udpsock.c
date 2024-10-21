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
};

NSN_DATAPATH_INIT(udpsock)
{
    char *config   = ctx->configs;
    char *port_str = NULL;
    int fd = 0, flags = 0, reuseaddr = 0;

    // TODO: Should we fail entirely if a peer cannot be reached?
    // For the moment, yes.
    for(usize i = 0; i < endpoint_count; i++) {
        if (endpoints[i] == NULL) {
            continue;
        }

        // allocate memory for the endpoint state
        endpoints[i]->data = malloc(sizeof(struct udpsock_ep));
        if (endpoints[i]->data == NULL) {
            fprintf(stderr, "malloc() failed\n");
            return -1;
        }
        endpoints[i]->data_size = sizeof(struct udpsock_ep);

        struct udpsock_ep *ep = (struct udpsock_ep *)endpoints[i]->data;

        // TODO: create the config file/section with the static daemon list    
        // Here, assume there's only one peer.
        // parse config, : separated, e.g. "<addr>:<port>"
        port_str = strchr(config, ':');
        if (port_str == NULL) {
            free(endpoints[i]->data);
            return -1;
        }

        *port_str = '\0';
        ep->s_port = atoi(port_str + 1);
        if (ep->s_port == 0) {
            free(endpoints[i]->data);
            return -1;
        }

        strncpy(ep->s_addr, config, UDP_SOCKET_ADDR_MAX);

        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd == -1) {
            free(endpoints[i]->data);
            fprintf(stderr, "socket() failed\n");
            return -1;
        }

        flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1) {
            close(fd);
            free(endpoints[i]->data);
            fprintf(stderr, "fcntl() failed\n");
            return -1;
        }

        flags |= O_NONBLOCK;
        if (fcntl(fd, F_SETFL, flags) == -1) {
            close(fd);
            free(endpoints[i]->data);
            fprintf(stderr, "fcntl() failed\n");
            return -1;
        }

        reuseaddr = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) == -1) {
            close(fd);
            free(endpoints[i]->data);
            fprintf(stderr, "setsockopt() failed\n");
            return -1;
        }

        memory_zero_struct(&ep->sock_addr);
        ep->sock_addr.sin_family      = AF_INET;
        ep->sock_addr.sin_port        = htons(endpoints[i]->app_id);
        ep->sock_addr.sin_addr.s_addr = inet_addr(ep->s_addr); //TODO: we need this to be passed as a parameter in the endpoint struct
        if (bind(fd, (struct sockaddr *)&ep->sock_addr, sizeof(ep->sock_addr)) == -1) {
            close(fd);
            free(endpoints[i]->data);
            fprintf(stderr, "bind() failed\n");
            return -1;
        }

        ep->s_sockfd = fd;
        ep->s_port   = endpoints[i]->app_id;
    }

    return 0;

}

struct sockaddr_in send_addr;

NSN_DATAPATH_TX(udpsock)
{
    isize ret = 0;
    usize i;
    int tx_count = 0;

    struct udpsock_ep *ep = (struct udpsock_ep *)endpoint->data;

    memory_zero_struct(&send_addr);
    send_addr.sin_family = AF_INET;
    send_addr.sin_port = htons(endpoint->app_id);
    inet_pton(AF_INET, "10.0.0.212", &send_addr.sin_addr);

    for (i = 0; i < buf_count; i++) {
        char* data = (char*)(endpoint->tx_zone + 1) + (bufs[i].index * endpoint->io_bufs_size); 
        usize size = ((nsn_meta_t*)(endpoint->tx_meta_zone + 1) + bufs[i].index)->len;        

        ret = sendto(ep->s_sockfd, data, size, 0, (struct sockaddr *)&send_addr, sizeof(send_addr));
        if (ret == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                printf("EAGAIN or EWOULDBLOCK\n");
            else 
                printf("sendto() failed: %s\n", strerror(errno));
        } else {
            tx_count++;
        }
    }

    // Free the descriptors after using them
    nsn_ringbuf_enqueue_burst(endpoint->free_slots, bufs, sizeof(bufs[0]), buf_count, NULL);

    return tx_count;
}

NSN_DATAPATH_RX(udpsock)
{
    struct udpsock_ep *ep_sk = (struct udpsock_ep *)endpoint->data;

    isize ret = 0;
    usize i   = 0;
    while (*buf_count--) {

        // TODO: This design is dubious. To receive data from the socket, we need to give a buffer to the recvfrom() function.
        // To get a buffer, we need to dequeue a descriptor from the free_slots ring and then get the buffer from the tx_zone.
        // However, because the socket is non-blocking, if we don't have data to receive, we just pass on, "wasting" the descriptor.
        // Currently, I'm re-enqueuing it back to the free_slots ring, but this is not the best solution. Maybe we could have some
        // state where we save one free buffer and use it until we get data from the socket?

        // get a descriptor
        u32 np = nsn_ringbuf_dequeue_burst(endpoint->free_slots, &bufs[i], sizeof(bufs[i]), 1, NULL);
        if (np == 0) {
            printf("[udpsock] No free slots to receive from ring %p [%u]\n", endpoint->free_slots, nsn_ringbuf_count(endpoint->free_slots));
            break;
        }

        // set the receive buffer
        char *data =  (char*)(endpoint->tx_zone + 1) + (bufs[i].index * endpoint->io_bufs_size);    
        usize *size = &((nsn_meta_t*)(endpoint->tx_meta_zone + 1) + bufs[i].index)->len;

        ret = recvfrom(ep_sk->s_sockfd, data, endpoint->io_bufs_size, 0, NULL, NULL);
        // if ok increment i, otherwise retry
        if (ret == -1) {
            // We didn't get any data, so we re-enqueue the descriptor
            nsn_ringbuf_enqueue_burst(endpoint->free_slots, &bufs[i], sizeof(bufs[i]), 1, NULL);
            // Check the reason of the -1
            if (errno != EAGAIN || errno != EWOULDBLOCK) {
                printf("recvfrom() failed: %s\n", strerror(errno));
            }
            break;
        } else {
            // Set the size as packet metadata
            *size = ret;
            i++;
        }
    }

    return i;
}

NSN_DATAPATH_DEINIT(udpsock)
{
    nsn_unused(ctx);

    int res = 0;
    for(usize i = 0; i < endpoint_count; i++) {
        if (endpoints[i] == NULL) {
            continue;
        }

        struct udpsock_ep *ep = (struct udpsock_ep *)endpoints[i]->data;
        if (ep->s_sockfd != -1) {
            close(ep->s_sockfd);
        }

        free(endpoints[i]->data);
    }
    
    return res;
}