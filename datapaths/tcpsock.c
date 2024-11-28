#include "../src/nsn_datapath.h"
#include "../src/nsn_string.c"
#include "../src/nsn_memory.c"
#include "../src/nsn_os_linux.c"
#include "../src/nsn_ringbuf.c"

#include <arpa/inet.h>
#include <netinet/in.h>

#define TCP_SOCKET_ADDR_MAX 64

// Currently, the state of the plugin is kept by the daemon under an opaque pointer,
// which is passed to the plugin functions. Alternatively, we could keep the state here
// and just exchange the stream index to select the correct state.
// The important thing to remember is that as streams are opened/closed, we should create/destroy
// the corresponding state in the plugin. TODO: find a way to efficiently do that without stalling
// the datapath.
static char*  local_ip;
static char** peers;
static u16    n_peers;

// Per-stream state
struct tcpsock_ep {
    nsn_buf_t pending_rx_buf;   
    int       s_svc_sockfd;     // Server socket
    int       *s_sockfd;        // Array of open sockets
    atu32     connected_peers;  // Number of connected peers
};

static int try_connect_peer(const char* peer, u16 port) { 
        
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        return fd;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        close(fd);
        fprintf(stderr, "[tcpsock] fcntl() failed: %s\n", strerror(errno));
        return fd;
    }

    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) == -1) {
        close(fd);
        fprintf(stderr, "[tcpsock] fcntl() failed: %s\n", strerror(errno));
        return fd;
    }

    int reuseaddr = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) == -1) {
        close(fd);
        fprintf(stderr, "[tcpsock] setsockopt() failed: %s\n", strerror(errno));
        return -1;
    }

    int reuseport = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuseport, sizeof(reuseaddr)) == -1) {
        close(fd);
        fprintf(stderr, "[tcpsock] setsockopt() failed: %s\n", strerror(errno));
        return -1;
    }


    // TCP does not allow to have more than one socket on the same port,
    // unless it is a server socket. So, for all the client connections,
    // we must rely on ephemeral ports.

    struct sockaddr_in sock_addr;
    memory_zero_struct(&sock_addr);
    sock_addr.sin_family      = AF_INET;
    sock_addr.sin_port        = htons(port);
    sock_addr.sin_addr.s_addr = inet_addr(local_ip);
    if (bind(fd, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) == -1) {
        close(fd);
        fprintf(stderr, "[tcpsock] bind() failed: %s\n", strerror(errno));
        return -1;
    }

    // Try to connect to peers. If fail, the conn manager will retry
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(peer);

    int ret = connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if(ret < 0 && errno != EINPROGRESS) {
        fprintf(stderr, "[tcpsock] connect() failed: %s (%d)\n", strerror(errno), errno);
        close(fd);
        return -1;
    }     

    // Use select to wait for readiness
    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(fd, &writefds);

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 1000; // 1 ms

    int result = select(fd + 1, NULL, &writefds, NULL, &timeout);
    if (result <= 0) {
        if (result == 0) {
            fprintf(stderr, "[tcpsock] connect() timed out\n");
        } else {
            fprintf(stderr, "[tcpsock] select() failed: %s\n", strerror(errno));
        }
        close(fd);
        return -1;
    }

    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) == -1) {
        close(fd);
        fprintf(stderr, "[tcpsock] getsockopt() failed: %s\n", strerror(errno));
        return -1;
    }

    if (error != 0) {
        close(fd);
        fprintf(stderr, "[tcpsock] connect() failed: %s (%d)\n", strerror(error), error);
        return -1;
    }

    return fd;
}

NSN_DATAPATH_UPDATE(tcpsock)
{
    if (endpoint == NULL) {
        fprintf(stderr, "[tcpsock] invalid endpoint\n");
        return -1;
    }

    // Case 1. Delete endpoint data and CLOSE all the sockets
    if(endpoint->data) {
        struct tcpsock_ep *conn = (struct tcpsock_ep *)endpoint->data;
        if (conn->s_svc_sockfd != -1) {
            close(conn->s_svc_sockfd);
        }
        for (int p = 0; p < n_peers; p++) {
            if (conn->s_sockfd[p] != -1) {
                close(conn->s_sockfd[p]);
                conn->s_sockfd[p] = -1;
                atomic_fetch_sub(&conn->connected_peers, 1);
            }
        }

        nsn_ringbuf_enqueue_burst(endpoint->free_slots, &conn->pending_rx_buf, sizeof(conn->pending_rx_buf), 1, NULL);       

        free(conn->s_sockfd);
        free(endpoint->data);
        endpoint->data = NULL;
    } 
    // Case 2. Create endpoint data and create the SERVER socket
    else { 
        int fd = 0, flags = 0, reuseaddr = 0;

        // Source port is the app_id
        if (endpoint->app_id < 4096 || endpoint->app_id > 65535) {
            fprintf(stderr, "[tcpsock] invalid app_id %u\n", endpoint->app_id);
            return -1;
        }

        // create the state of the endpoint, which will hold connection data
        endpoint->data = malloc(sizeof(struct tcpsock_ep));
        if (!endpoint->data) {
            fprintf(stderr, "malloc() failed: %s\n", strerror(errno));
            return -1;
        }
        endpoint->data_size = sizeof(struct tcpsock_ep);

        // initialize the state of the endpoint 
        struct tcpsock_ep *conn = (struct tcpsock_ep *)endpoint->data;
        conn->s_sockfd = malloc(n_peers * sizeof(int));
        if (!conn->s_sockfd) {
            fprintf(stderr, "malloc() failed: %s\n", strerror(errno));
            return -1;
        }

        // get a descriptor to receive
        u32 np = nsn_ringbuf_dequeue_burst(endpoint->free_slots, &conn->pending_rx_buf, sizeof(conn->pending_rx_buf), 1, NULL);
        if (np == 0) {
            printf("[tcpsock] No free slots to receive from ring %p [%u]\n", endpoint->free_slots, nsn_ringbuf_count(endpoint->free_slots));
            free(conn->s_sockfd);
            free(endpoint->data);
            return -1;
        }

        // create the server socket
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == -1) {
            free(conn->s_sockfd);
            free(endpoint->data);
            fprintf(stderr, "[tcpsock] socket() failed:%s\n", strerror(errno));
            return -1;
        }

        flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1) {
            close(fd);
            free(conn->s_sockfd);
            free(endpoint->data);
            fprintf(stderr, "[tcpsock] fcntl() failed: %s\n", strerror(errno));
            return -1;
        }

        flags |= O_NONBLOCK;
        if (fcntl(fd, F_SETFL, flags) == -1) {
            close(fd);
            free(conn->s_sockfd);
            free(endpoint->data);
            fprintf(stderr, "[tcpsock] fcntl() failed: %s\n", strerror(errno));
            return -1;
        }

        reuseaddr = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) == -1) {
            close(fd);
            free(conn->s_sockfd);
            free(endpoint->data);
            fprintf(stderr, "[tcpsock] setsockopt() failed: %s\n", strerror(errno));
            return -1;
        }

        int reuseport = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuseport, sizeof(reuseaddr)) == -1) {
            close(fd);
            fprintf(stderr, "[tcpsock] setsockopt() failed: %s\n", strerror(errno));
            return -1;
        }

        struct sockaddr_in sock_addr;
        memory_zero_struct(&sock_addr);
        sock_addr.sin_family      = AF_INET;
        sock_addr.sin_port        = htons(endpoint->app_id);
        sock_addr.sin_addr.s_addr = inet_addr(local_ip);
        if (bind(fd, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) == -1) {
            close(fd);
            free(conn->s_sockfd);
            free(endpoint->data);
            fprintf(stderr, "[tcpsock] bind() failed: %s\n", strerror(errno));
            return -1;
        }

        if (listen(fd, n_peers) < 0) {
            close(fd);
            free(conn->s_sockfd);
            free(endpoint->data);
            fprintf(stderr, "[tcpsock] listen() failed: %s (%d)\n", strerror(errno), errno);
            return -1;
        }

        // finalize the initialization
        conn->s_svc_sockfd = fd;

        // try to connect to peers. If fail, the conn manager will retry
        for (int p = 0; p < n_peers; p++) {
            conn->s_sockfd[p] = try_connect_peer(peers[p], endpoint->app_id);
            if(conn->s_sockfd[p] > 0) {
                fprintf(stderr, "[tcpsock] connected to %s\n", peers[p]);
                atomic_fetch_add(&conn->connected_peers, 1);
            }
        }
    }

    return 0;
}

NSN_DATAPATH_CONN_MANAGER(tcpsock)
{
    if (endpoint_list == NULL) {
        fprintf(stderr, "[tcpsock] connection manager: invalid endpoint_list\n");
        return -1;
    }
    if (list_empty(endpoint_list)) {
        return 0;
    }

    ep_initializer_t *ep_in;
    list_for_each_entry(ep_in, endpoint_list, node) {    
        nsn_endpoint_t *ep = ep_in->ep;
        struct tcpsock_ep *conn = (struct tcpsock_ep *)ep->data;

        // already connected to all peers - skip
        u32 conn_peers = at_load(&conn->connected_peers, mo_rlx);
        if (conn_peers == n_peers) {
            continue;
        }

        // Accept incoming connections
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = -1;
        while((client_fd = accept(conn->s_svc_sockfd, (struct sockaddr *)&client_addr, &addr_len)) > 0) {
            for (int p = 0; p < n_peers; p++) {
                if(!strcmp(inet_ntoa(client_addr.sin_addr), peers[p]) && client_addr.sin_port == htons(ep->app_id)) {
                    conn->s_sockfd[p] = client_fd;
                    atomic_fetch_add(&conn->connected_peers, 1);
                    fprintf(stderr, "[tcpsock] connection manager: accepted connection from %s:%u\n", peers[p], ep->app_id);
                    break;
                }
            }
            // TODO: close the connection if the peer is not in the list/wrong port
        }
        if (client_fd < 0 && errno != EWOULDBLOCK && errno != EAGAIN) {
            fprintf(stderr, "[tcpsock] connection manager: accept failed: %s\n", strerror(errno));
        }       

        // Try to connect to missing peer
        // for (int p = 0; p < n_peers; p++) {
        //     if (conn->s_sockfd[p] > 0) {
        //         continue;
        //     }
        //     conn->s_sockfd[p] = try_connect_peer(peers[p], ep->app_id);
        //     if(conn->s_sockfd[p] > 0) {
        //         fprintf(stderr, "Connected to %s\n", peers[p]);
        //         atomic_fetch_add(&conn->connected_peers, 1);
        //     }
        // }
    }

    return 0;
}

NSN_DATAPATH_INIT(tcpsock)
{
    // Initialize local state 
    n_peers = ctx->n_peers;
    peers = ctx->peers;
    local_ip = ctx->local_ip;

    // Setup the connections to the peers
    int ret = 0;
    ep_initializer_t *ep_in;
    list_for_each_entry(ep_in, endpoint_list, node) {
        ret = tcpsock_datapath_update(ep_in->ep);
        if (ret < 0) {
            fprintf(stderr, "[tcpsock] tcpsock_datapath_update() failed\n");
            return ret;
        }
    }

    return ret;
}

NSN_DATAPATH_TX(tcpsock)
{
    isize ret   = 0;
    usize nb_tx = 0;
    usize i;
    int tx_count = 0;

    struct tcpsock_ep *conn = (struct tcpsock_ep *)endpoint->data;

    for (i = 0; i < buf_count; i++) {
        // Get the data and size from the index
        char* data = (char*)(endpoint->tx_zone + 1) + (bufs[i].index * endpoint->io_bufs_size); 
        usize size = ((nsn_meta_t*)(endpoint->tx_meta_zone + 1) + bufs[i].index)->len;  

        if (nsn_unlikely(size > endpoint->io_bufs_size)) {
            fprintf(stderr, "[tcpsock] Invalid packet size: %lu. Discarding packet...\n", size);
            tx_count++;
            continue;
        }      

        // Send the buf to all the peers. 
        // If a send to p fails, close the connection with p: no retry
        for(int p = 0; p < n_peers; p++) {
            if (conn->s_sockfd[p] == -1) {
                continue;
            }

            // First, packet size. Asynchronous!
            if (nsn_unlikely((ret = write(conn->s_sockfd[p], &size, sizeof(size))) < 0)) {    
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // Because we cannot guarantee that all peers have received this packet, we consider this
                    // as an error case. To avoid this, we need to design a more sophisticated protocol that 
                    // keeps track of which peer received which packet.
                    if (p > 0) {
                        fprintf(stderr, "[tcpsock] send() size failed: %s\n", strerror(errno));
                        close(conn->s_sockfd[p]);
                        atomic_fetch_sub(&conn->connected_peers, 1); 
                        // continue because we already sent the pkt to at least one peer
                        continue;
                    } else {
                        // no send happens now: retry! Do not continue as we would disalign the peers
                        goto finalize_send;
                    }
                } else {
                    fprintf(stderr, "[tcpsock] send() size failed: %s\n", strerror(errno));
                    close(conn->s_sockfd[p]);
                    atomic_fetch_sub(&conn->connected_peers, 1); 
                    continue;
                }
            } 
            fprintf(stderr, "[tcpsock] sending %lu bytes...", size);

            // Then, the actual packet. Now that we committed by sending a size, we must send synchronously
            nb_tx = 0;
            while(nb_tx < size) {
                if((ret = write(conn->s_sockfd[p], data, size - nb_tx)) < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        // fatal error: stop sending data to this peer
                        fprintf(stderr, "\n[tcpsock] send() data failed: %s\n", strerror(errno));
                        close(conn->s_sockfd[p]);
                        atomic_fetch_sub(&conn->connected_peers, 1); 
                        break;
                    }
                    // as we committed to send data, we keep trying
                    continue;
                }
                nb_tx += ret;
                data  += ret;
            }
            if(nsn_unlikely(nb_tx != size)) {
                fprintf(stderr, "\n[tcpsock] error: sent %lu bytes, but expected were %lu\n", nb_tx, size);
                continue;
            }
            fprintf(stderr, "... sent %ld bytes index %lu\n", nb_tx, bufs[i].index);
        }

        tx_count++;
    }

finalize_send:
    // Free the descriptors after using them
    if(tx_count > 0 && nsn_ringbuf_enqueue_burst(endpoint->free_slots, bufs, sizeof(bufs[0]), tx_count, NULL) < (u32)tx_count) {
        fprintf(stderr, "[tcpsock] Failed to enqueue %d descriptors\n", tx_count);
    }

    return tx_count;
}

NSN_DATAPATH_RX(tcpsock)
{
    struct tcpsock_ep *ep_sk = (struct tcpsock_ep *)endpoint->data;

    isize ret   = 0;
    usize nb_rx = 0;
    usize i     = 0;

    // set the receive buffer
    bufs[i]     = ep_sk->pending_rx_buf;
    char *data  = (char*)(endpoint->tx_zone + 1) + (bufs[i].index * endpoint->io_bufs_size);    
    usize *size = &((nsn_meta_t*)(endpoint->tx_meta_zone + 1) + bufs[i].index)->len;

    // In TCP we decide to receive 1 pkt per time from each peer. First the size, then the data
    usize buf_size;
    for (int p = 0; p < n_peers; p++) {
        if (ep_sk->s_sockfd[p] == -1) {
            continue;
        }
        
        buf_size = 0;
        if (nsn_likely((ret = read(ep_sk->s_sockfd[p], &buf_size, sizeof(buf_size)))) > 0) {
            // if something fails now, we must close the connection as the protocol is broken
            if (nsn_unlikely(buf_size > endpoint->io_bufs_size)) {
                fprintf(stderr, "[tcpsock] rx protocol error: invalid packet size %lu\n", buf_size);
                close(ep_sk->s_sockfd[p]);
                ep_sk->s_sockfd[p] = -1;
                atomic_fetch_sub(&ep_sk->connected_peers, 1);
                continue;
            }    
            fprintf(stderr, "[tcpsock] receiving %lu bytes...", buf_size);

            // Wait for the full packet. We assume that it is sent immediately.
            nb_rx = 0;
            while (nb_rx < buf_size) {            
                if((ret = read(ep_sk->s_sockfd[p], data, buf_size - nb_rx)) < 0) {
                    if(errno != EAGAIN && errno != EWOULDBLOCK) {
                        // Something failed 
                        fprintf(stderr, "\nrecvfrom() failed: %s\n", strerror(errno));
                        close(ep_sk->s_sockfd[p]);
                        ep_sk->s_sockfd[p] = -1;
                        atomic_fetch_sub(&ep_sk->connected_peers, 1);
                        break;       
                    }
                    continue;
                }
                nb_rx += ret;
                data  += ret;
            }
            if (nsn_unlikely(nb_rx != buf_size)) {
                fprintf(stderr, "... but received %lu\n", nb_rx);
                continue;
            }
            fprintf(stderr, "... received %ld bytes idx = %lu\n", nb_rx, bufs[i].index);

            // Update the pending tx descriptor
            u32 np = nsn_ringbuf_dequeue_burst(endpoint->free_slots, &ep_sk->pending_rx_buf, sizeof(ep_sk->pending_rx_buf), 1, NULL);
            if (np == 0) {
                fprintf(stderr, "[tcpsock] No free slots for next receive! Ring: %p [count %u]\n", endpoint->free_slots, nsn_ringbuf_count(endpoint->free_slots));
                return i;
            }

            // Set the size as packet metadata
            *size = buf_size;
            i++;
            *buf_count = *buf_count - 1;
        } else {
            if(errno != EAGAIN && errno != EWOULDBLOCK && errno != EINPROGRESS) {
                // Something failed 
                fprintf(stderr, "read() failed: %s\n", strerror(errno));    
                close(ep_sk->s_sockfd[p]);
                ep_sk->s_sockfd[p] = -1;    
                atomic_fetch_sub(&ep_sk->connected_peers, 1);
            }
            continue;
        }

        // set the receive buffer for next rx
        bufs[i] = ep_sk->pending_rx_buf;
        data    = (char*)(endpoint->tx_zone + 1) + (bufs[i].index * endpoint->io_bufs_size);    
        size    = &((nsn_meta_t*)(endpoint->tx_meta_zone + 1) + bufs[i].index)->len;
    }

    return i;
}

NSN_DATAPATH_DEINIT(tcpsock)
{
    nsn_unused(ctx);

    int res = 0;
    struct ep_initializer *ep_in;
    list_for_each_entry(ep_in, endpoint_list, node) {
        res = tcpsock_datapath_update(ep_in->ep);
        if (res < 0) {
            fprintf(stderr, "[tcpsock] tcpsock_datapath_update() failed\n");
            return res;
        }
    }

    n_peers = 0;
    peers = NULL;
    local_ip = NULL;

    return res;
}