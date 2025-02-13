#include "../src/nsn_datapath.h"

#include "../src/base/nsn_string.c"
#include "../src/base/nsn_memory.c"
#include "../src/base/nsn_os_linux.c"

#include "../src/common/nsn_temp.h"
#include "../src/common/nsn_ringbuf.c"
#include "../src/common/nsn_config.c"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

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

    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (int[]){4194304}, sizeof(int));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (int[]){4194304}, sizeof(int));
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (int[]){1}, sizeof(int));

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
            
            // Set the proper flags
            setsockopt(client_fd, SOL_SOCKET, SO_SNDBUF, (int[]){4194304}, sizeof(int));
            setsockopt(client_fd, SOL_SOCKET, SO_RCVBUF, (int[]){4194304}, sizeof(int));
            setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, (int[]){1}, sizeof(int));

            int flags = fcntl(client_fd, F_GETFL, 0);
            if (flags == -1) {
                fprintf(stderr, "[tcpsock] fcntl() failed: %s\n", strerror(errno));
                close(client_fd);
                return -1;
            }
            flags |= O_NONBLOCK;
            if (fcntl(client_fd, F_SETFL, flags) == -1) {
                fprintf(stderr, "[tcpsock] fcntl() failed: %s\n", strerror(errno));
                close(client_fd);
                return -1;
            }   
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
    nsn_thread_ctx_t this_thread = nsn_thread_ctx_alloc();
    this_thread.is_main_thread   = false;
    nsn_thread_set_ctx(&this_thread);

    // Initialize local state 
    n_peers = ctx->n_peers;
    peers = ctx->peers;

    // Retrieve the local IP from the list of parameters
    string_t local_ip_str;
    local_ip_str.data = (u8*)malloc(16);
    local_ip_str.len = 0;
    int ret = nsn_config_get_string_from_list(&ctx->params, str_lit("ip"), &local_ip_str);
    if (ret < 0) {
        fprintf(stderr, "[tcpsock] nsn_config_get_string_from_list() failed: no option \"ip\" found\n");
        return ret;
    }
    local_ip = to_cstr(local_ip_str);
    fprintf(stderr, "[tcpsock] parameter: ip: %s\n", local_ip);

    // Setup the connections to the peers
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

        if (nsn_unlikely(size == 0 || size > endpoint->io_bufs_size)) {
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
            nb_tx = 0;
            char* buf_size_ptr = (char*)&size;
            while(nb_tx < sizeof(size)) {
                if ((ret = send(conn->s_sockfd[p], buf_size_ptr, sizeof(size) - nb_tx, MSG_DONTWAIT)) < 0) {    
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        if (p == 0 && !nb_tx) {
                            // no send happens now: retry! Do not continue as we would disalign the peers
                            // we can do this because we haven't sent anything yet
                            goto finalize_send;
                        } else {
                            // because we already sent some bytes (to p or to some other peer), we are now
                            // committed to send the entire message, so we must retry the send here until it
                            // is either successful or it fails.
                            ret = 0;
                            goto retry;
                        }
                    } else {
                        fprintf(stderr, "[tcpsock] send() size failed: %s\n", strerror(errno));
                        close(conn->s_sockfd[p]);
                        conn->s_sockfd[p] = -1;
                        atomic_fetch_sub(&conn->connected_peers, 1); 
                        break;
                    }
                }
retry:
                nb_tx += ret;
                buf_size_ptr += ret;
            } 
            if (nb_tx != sizeof(size)) {
                fprintf(stderr, "[tcpsock] error: sent %ld bytes, but expected were %lu\n", ret, sizeof(size));
                continue;
            }

            // Then, the actual packet. Now that we committed by sending a size, we must send synchronously
            nb_tx = 0;
            while(nb_tx < size) {
                if((ret = send(conn->s_sockfd[p], data, size - nb_tx, MSG_DONTWAIT)) < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        // fatal error: stop sending data to this peer
                        fprintf(stderr, "[tcpsock] send() data failed: %s\n", strerror(errno));
                        close(conn->s_sockfd[p]);
                        conn->s_sockfd[p] = -1;
                        atomic_fetch_sub(&conn->connected_peers, 1); 
                        break;
                    }
                    // as we committed to send data, we keep trying
                    continue;
                }
                nb_tx += ret;
                data  += ret;
            }
            if(nb_tx != size) {
                fprintf(stderr, "[tcpsock] error: sent %lu bytes, but expected were %lu\n", nb_tx, size);
                continue;
            }
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

        nb_rx = 0;
        buf_size = 0;
        char *buf_size_ptr = (char*)&buf_size;
        while (nb_rx < sizeof(buf_size)) {            
            if ((ret = recv(ep_sk->s_sockfd[p], buf_size_ptr, sizeof(buf_size) - nb_rx, MSG_DONTWAIT)) <= 0) {
                if (ret == 0) {
                    // Connection closed
                    fprintf(stderr, "[tcpsock] connection closed by %s\n", peers[p]);
                    close(ep_sk->s_sockfd[p]);
                    ep_sk->s_sockfd[p] = -1;
                    atomic_fetch_sub(&ep_sk->connected_peers, 1);
                    break;
                }
                if(errno != EAGAIN && errno != EWOULDBLOCK) {
                    // Something failed 
                    fprintf(stderr, "[tcpsock] recv() failed: %s\n", strerror(errno));
                    close(ep_sk->s_sockfd[p]);
                    ep_sk->s_sockfd[p] = -1;
                    atomic_fetch_sub(&ep_sk->connected_peers, 1);
                    break;       
                }

                // I'm here because I received EAGAIN or EWOULDBLOCK
                // If I have received some bytes, I must retry, otherwise I must return
                if (nb_rx == 0) {
                    break;
                }

                continue;
            }
            nb_rx += ret;
            buf_size_ptr += ret;
        }
        if (nb_rx != sizeof(buf_size)) {
            continue;
        }

        // if something fails now, we must close the connection as the protocol is broken
        if (buf_size == 0 || buf_size > endpoint->io_bufs_size) {
            fprintf(stderr, "[tcpsock] rx protocol error: invalid packet size %lu\n", buf_size);
            close(ep_sk->s_sockfd[p]);
            ep_sk->s_sockfd[p] = -1;
            atomic_fetch_sub(&ep_sk->connected_peers, 1);
            continue;
        }    

        // Wait for the full packet. We assume that it is sent immediately.
        nb_rx = 0;
        while (nb_rx < buf_size) {            
            if((ret = recv(ep_sk->s_sockfd[p], data, buf_size - nb_rx, MSG_DONTWAIT)) <= 0) {
                if(ret == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
                    // Something failed 
                    fprintf(stderr, "\n[tcpsock] recvfrom() failed: %s\n", strerror(errno));
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
        if (nb_rx != buf_size) {
            fprintf(stderr, "[tcpsock] recv() failed before receiving all data: %s\n", strerror(errno));
            continue;
        }

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
    free(local_ip);

    return res;
}