#define _GNU_SOURCE
#include <assert.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <stdatomic.h>
#include <netdb.h>
#include <ifaddrs.h>

#include <arpa/inet.h>

#include <linux/if_packet.h>

#include <net/if.h>

#include <netinet/in.h>
#include <netinet/ip.h> 

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>

#include "../../include/nsn/nsn.h"

typedef struct {
    int fd;
    int socket_type;        // SOCK_STREAM, SOCK_DGRAM, etc.
    int blocking_mode;      // NSN_BLOCKING, NSN_NONBLOCKING
    int socket_protocol;    
    nsn_stream_t stream;
    nsn_sink_t sink;
    nsn_source_t source;
    int is_nsn_socket;
    uint32_t sink_id;
    uint32_t source_id;
} socket_mapping_t;

#define MAX_SOCKETS 1024
static socket_mapping_t socket_map[MAX_SOCKETS];
static int nsn_initialized = 0; // Flag to indicate if NSN library is initialized
// Global counter for the stream id
static uint32_t global_stream_id_counter = 0;
// --- Global stream id helper ----------------------------------------------
static uint32_t get_next_global_stream_id() {
    return atomic_fetch_add(&global_stream_id_counter, 1);
}
__thread int inside_nsn_code = 0;

static socket_mapping_t *find_socket_mapping(int fd) {
    for (int i = 0; i < MAX_SOCKETS; i++) {
        if (socket_map[i].fd == fd && socket_map[i].is_nsn_socket) {
            return &socket_map[i];
        }
    }
    return NULL;
}

static socket_mapping_t *add_socket_mapping(int fd, int type, int protocol, int blocking_mode, int is_nsn) {
    for (int i = 0; i < MAX_SOCKETS; i++) {
        if (socket_map[i].fd == 0) {
            socket_map[i].fd = fd;
            socket_map[i].socket_type = type;
            socket_map[i].socket_protocol = protocol;
            socket_map[i].is_nsn_socket = is_nsn;
            socket_map[i].stream = NSN_INVALID_STREAM_HANDLE;
            socket_map[i].sink = NSN_INVALID_SNK;
            socket_map[i].source = NSN_INVALID_SRC;
            socket_map[i].blocking_mode = blocking_mode;
            socket_map[i].sink_id = 0;
            socket_map[i].source_id = 0;
            return &socket_map[i];
        }
    }
    return NULL;
}


static int (*__start_main)(int (*main)(int, char **, char **), int argc,
                           char **ubp_av, void (*init)(void),
                           void (*fini)(void), void (*rtld_fini)(void),
                           void(*stack_end));

static int (*default_fcntl)(int fildes, int cmd, ...) = NULL;
static int (*default_setsockopt)(int fd, int level, int optname,
                                 const void *optval, socklen_t optlen) = NULL;
static int (*default_getsockopt)(int fd, int level, int optname,
                                 const void *optval, socklen_t *optlen) = NULL;
static ssize_t (*default_read)(int sockfd, void *buf, size_t len) = NULL;
static ssize_t (*default_write)(int fd, const void *buf, size_t count) = NULL;
static int (*default_connect)(int sockfd, const struct sockaddr *addr,
                              socklen_t addrlen) = NULL;
static int (*default_socket)(int domain, int type, int protocol) = NULL;
static int (*default_listen)(int sockfd, int backlog) = NULL;
static int (*default_accept)(int sockfd, struct sockaddr *addr, socklen_t *addrlen) = NULL;
static int (*default_close)(int fildes) = NULL;
static int (*default_bind)(int sockfd, const struct sockaddr *addr,
                           socklen_t addrlen) = NULL;
static int (*default_select)(int nfds, fd_set *restrict readfds,
                             fd_set *restrict writefds,
                             fd_set *restrict errorfds,
                             struct timeval *restrict timeout);
static ssize_t (*default_send)(int sockfd, const void *message, size_t length,
                               int flags) = NULL;
static ssize_t (*default_sendto)(int sockfd, const void *message, size_t length,
                                 int flags, const struct sockaddr *dest_addr,
                                 socklen_t dest_len) = NULL;
static ssize_t (*default_recvfrom)(int sockfd, void *buf, size_t len,
                                   int flags, struct sockaddr *restrict address,
                                   socklen_t *restrict addrlen) = NULL;

int socket(int domain, int type, int protocol)
{
    if(inside_nsn_code){    
        int ret = default_socket(domain, type, protocol);
       if (ret < 0) {
            fprintf(stderr, "[NSN] Failed to create socket: %s\n", strerror(errno));
            return ret;
        }
        return ret;
    }
    int base_type = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC); // Removes flags
    int mode = (type & SOCK_NONBLOCK) ? NSN_NONBLOCKING : NSN_BLOCKING; // Determine blocking mode
    if (domain == AF_INET && (base_type == SOCK_STREAM || base_type == SOCK_DGRAM)) {
        const char* socket_type_str = (base_type == SOCK_STREAM) ? "TCP" : "UDP";
        printf("[INTERCEPT] Socket %s detected - initializing NSN\n", socket_type_str);
        
        // Initialize NSN if not already done
        if (!nsn_initialized) {
            inside_nsn_code = 1; // We are inside NSN code
            if (nsn_init() < 0) {
                fprintf(stderr, "[NSN] Failed to initialize NSN library\n");
                errno = ENOMEM;
                return -1;
            }
            nsn_initialized = 1;
            inside_nsn_code = 0; // We are outside NSN code
        }
        
        // Create the socket
        int fd = default_socket(domain, type, protocol);
        if (fd < 0) {
            return fd;
        }
        
        // Add mapping for NSN socket
        socket_mapping_t *mapping = add_socket_mapping(fd, base_type, protocol, mode, 1);
        if (mapping) {
            printf("[NSN] Socket %d %s marked for NSN interception\n", fd, socket_type_str);
        }
        
        return fd;
    }
    
    return default_socket(domain, type, protocol);
}

int setsockopt(int fd, int level, int optname,
               const void *optval, socklen_t optlen)
{
    if(inside_nsn_code){
        return default_setsockopt(fd, level, optname, optval, optlen);
    }
    socket_mapping_t *mapping = find_socket_mapping(fd);
    if (mapping && mapping->is_nsn_socket) {
        if (level == SOL_SOCKET) {
            switch (optname) { // Simulate success but do not call the original function
                case SO_RCVBUF:
                    return 0; 
                    
                case SO_SNDBUF:
                    return 0; 
                    
                case SO_REUSEADDR:
                    return 0; 
                    
                default:
                    return 0; 
            }
        }
    }

    return default_setsockopt(fd, level, optname, optval, optlen);
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    
    if(inside_nsn_code){
        return default_bind(sockfd, addr, addrlen);
    }

    socket_mapping_t *mapping = find_socket_mapping(sockfd);
    if (mapping) {

        nsn_options_t options = {0}; 
        
        // Configure reliability based on socket type
        if (mapping->socket_type == SOCK_DGRAM) {
            // Configuring UDP socket as UNRELIABLE
            options.datapath = NSN_QOS_DATAPATH_DEFAULT; 
            options.consumption = NSN_QOS_CONSUMPTION_POLL; 
            options.determinism = NSN_QOS_DETERMINISM_DEFAULT; // Default determinism
            options.reliability = NSN_QOS_RELIABILITY_UNRELIABLE;
            
        } else if (mapping->socket_type == SOCK_STREAM) {
            // Configuring TCP socket as RELIABLE
            options.datapath = NSN_QOS_DATAPATH_DEFAULT; 
            options.consumption = NSN_QOS_CONSUMPTION_POLL; 
            options.determinism = NSN_QOS_DETERMINISM_DEFAULT; // Default determinism
            options.reliability = NSN_QOS_RELIABILITY_RELIABLE;
        }
        
        inside_nsn_code = 1; // Inside NSN code
        // Create NSN stream with the configured options
        mapping->stream = nsn_create_stream(options);
        if (mapping->stream == NSN_INVALID_STREAM_HANDLE) {
            fprintf(stderr, "[NSN] Failed to create NSN stream\n");
            errno = ENOMEM;
            return -1;
        }
        inside_nsn_code = 0; // Outside NSN code
        return 0; // Simulate success
    }
    
    return default_bind(sockfd, addr, addrlen);
}

int listen(int sockfd, int backlog)
{
    if(inside_nsn_code){
        return default_listen(sockfd, backlog);
    }
    socket_mapping_t *mapping = find_socket_mapping(sockfd);
    
    if (mapping && mapping->is_nsn_socket) {
        return 0; // Return 0 as if it was successful
    }
    
    return default_listen(sockfd, backlog);
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) 
{
    if (inside_nsn_code) {
        return default_accept(sockfd, addr, addrlen);
    }

    socket_mapping_t *mapping = find_socket_mapping(sockfd);
    if (mapping && mapping->is_nsn_socket) {
        return mapping->fd; // Return the socket fd as if it was successful
    }
    
    return default_accept(sockfd, addr, addrlen);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) 
{
    if (inside_nsn_code) {
        return default_connect(sockfd, addr, addrlen);
    }

    socket_mapping_t *mapping = find_socket_mapping(sockfd);
    if (mapping && mapping->is_nsn_socket) {
        return mapping->fd; // Return the socket fd as if it was successful
    }
    
    return default_connect(sockfd, addr, addrlen);
}

ssize_t read(int sockfd, void *buf, size_t len)
{
    if(inside_nsn_code){
        int ret = default_read(sockfd, buf, len);
        if (ret < 0) {
            fprintf(stderr, "[NSN] Failed to read data in NSN code: %s\n", strerror(errno));
            return ret;
        }
        return ret;
    }
    socket_mapping_t *mapping = find_socket_mapping(sockfd);
    mapping->sink_id = get_next_global_stream_id();
    // Ignore the read of 1 byte for closing the socket
    if (mapping && mapping->is_nsn_socket && len == 1 && mapping->source != NSN_INVALID_SRC) {
        return 0;
    }

    // Create NSN sink if not already created
    if(mapping->sink == NSN_INVALID_SNK) {
        inside_nsn_code = 1; // Inside NSN code
        mapping->sink = nsn_create_sink(mapping->stream, mapping->sink_id , NULL);
        if (mapping->sink == NSN_INVALID_SNK) {
            fprintf(stderr, "[NSN] Failed to create NSN sink\n");
            errno = ENOMEM;
            return -1;
        }        
        inside_nsn_code = 0; // Outside NSN code
        printf("[NSN] Created stream and sink for socket %d\n", sockfd);
    }

    if (mapping && mapping->sink != NSN_INVALID_SNK) {
        // We use nsn_consume_data instead of the original recvfrom, we receive a buffer from NSN
        inside_nsn_code = 1;
        nsn_buffer_t *nbuf = nsn_consume_data(mapping->sink, mapping->blocking_mode);
        inside_nsn_code = 0;

        if (!nsn_buffer_is_valid(nbuf)) {
            fprintf(stderr, "[NSN] Failed to get valid buffer\n");
            return -1;
        }
        
        size_t copy_len = (len < nbuf->len) ? len : nbuf->len;
        memcpy(buf, nbuf->data, copy_len); // we copy the data to the original buffer

        nsn_release_data(nbuf);

        return (ssize_t)copy_len;
    }
    
    return default_read(sockfd, buf, len);
}

ssize_t write(int fd, const void *buf, size_t count)
{
    if (inside_nsn_code){
        int ret = default_write(fd, buf, count);
        if (ret < 0) {
            fprintf(stderr, "[NSN] Failed to create socket in NSN code: %s\n", strerror(errno));
            return ret;
        }
        return ret;
    }
    socket_mapping_t *mapping = find_socket_mapping(fd);
    mapping->source_id = get_next_global_stream_id();
    if (!mapping || !mapping->is_nsn_socket) {
        return default_write(fd, buf, count);
    }

    // Create NSN source if not already created
    if(mapping->source == NSN_INVALID_SRC) {
        inside_nsn_code = 1; // Inside NSN code
        mapping->source = nsn_create_source(mapping->stream, mapping->source_id); 
        inside_nsn_code = 0; // Outside NSN code
        if (mapping->source == NSN_INVALID_SRC) {
            fprintf(stderr, "[NSN] Failed to create source for socket %d\n", fd);
            errno = EIO;
            return -1;
        }
        printf("[NSN] Created stream and source for socket %d\n", fd);
    }
    
    // Get the NSN buffer
    nsn_buffer_t *out_buf = nsn_get_buffer(count, mapping->blocking_mode);
    if (!nsn_buffer_is_valid(out_buf)) {
        fprintf(stderr, "[NSN] Failed to get valid buffer\n");
        return -1;
    }

    // Copy the data to the NSN buffer
    memcpy(out_buf->data, buf, count);
    out_buf->len = count; // Set buffer length

    // Emit the data using NSN
    int ret = nsn_emit_data(mapping->source, out_buf);
    if (ret < 0) {
        fprintf(stderr, "[NSN] Failed to emit data\n");
        errno = EIO;
        return -1;
    }

    return (ssize_t)count;  // Simulate write success

}


ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags, 
                 struct sockaddr *src_addr, socklen_t *addrlen) {
    if(inside_nsn_code){
        int ret = default_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
        if (ret < 0) {
            fprintf(stderr, "[NSN] Failed to receive data in NSN code: %s\n", strerror(errno));
            return ret;
        }
        return ret;
    }
    socket_mapping_t *mapping = find_socket_mapping(sockfd);
    mapping->sink_id = get_next_global_stream_id();
    // Create NSN sink if not already created
    if(mapping->sink == NSN_INVALID_SNK) {
        inside_nsn_code = 1; // Inside NSN code
        mapping->sink = nsn_create_sink(mapping->stream, mapping->sink_id , NULL);
        if (mapping->sink == NSN_INVALID_SNK) {
            fprintf(stderr, "[NSN] Failed to create NSN sink\n");
            errno = ENOMEM;
            return -1;
        }        
        inside_nsn_code = 0; // Outside NSN code
        printf("[NSN] Created stream and sink for socket %d\n", sockfd);
    }
    
    if (mapping && mapping->sink != NSN_INVALID_SNK) {
        // We use nsn_consume_data instead of the original recvfrom, we receive a buffer from NSN
        inside_nsn_code = 1; // flag inside NSN code
        nsn_buffer_t *nbuf = nsn_consume_data(mapping->sink, mapping->blocking_mode);
        inside_nsn_code = 0; // flag outside NSN code
        
        if (!nsn_buffer_is_valid(nbuf)) {
            fprintf(stderr, "[NSN] Failed to get valid buffer\n");
            return -1;
        }
        
        size_t copy_len = (len < nbuf->len) ? len : nbuf->len;
        memcpy(buf, nbuf->data, copy_len); // we copy the data to the original buffer

        nsn_release_data(nbuf);

        return (ssize_t)copy_len;
    }
    
    return default_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen)
{
    if (inside_nsn_code){
        int ret = default_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
        if (ret < 0) {
            fprintf(stderr, "[NSN] Failed to create socket in NSN code: %s\n", strerror(errno));
            return ret;
        }
        return ret;
    }
    socket_mapping_t *mapping = find_socket_mapping(sockfd);
    mapping->source_id = get_next_global_stream_id();
    if (!mapping || !mapping->is_nsn_socket) {
        return default_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    }

    // Create source
    if(mapping->source == NSN_INVALID_SRC) {
       inside_nsn_code = 1; // Inside NSN code
        mapping->source = nsn_create_source(mapping->stream, mapping->source_id);
        inside_nsn_code = 0; // Outside NSN code
        if (mapping->source == NSN_INVALID_SRC) {
            fprintf(stderr, "[NSN] Failed to create source for socket %d\n", sockfd);
            errno = EIO;
            return -1;
        }
        printf("[NSN] Created stream and source for socket %d\n", sockfd);
    }
   
    // Get the NSN buffer
    nsn_buffer_t *out_buf = nsn_get_buffer(len, mapping->blocking_mode); 
    if (!nsn_buffer_is_valid(out_buf)) {
        fprintf(stderr, "[NSN] Failed to get valid buffer\n");
        return -1;
    }

    // Copy the data to the NSN buffer
    memcpy(out_buf->data, buf, len);
    out_buf->len = len; // Set buffer length
    // Emit the data using NSN
    int ret = nsn_emit_data(mapping->source, out_buf);
    if (ret < 0) {
        fprintf(stderr, "[NSN] Failed to emit data\n");
        errno = EIO;
        return -1;
    }

    return (ssize_t)len;  // Simulate sendto() success

}

int close(int fildes)
{
    if(inside_nsn_code){
        return default_close(fildes);
    }

    socket_mapping_t *mapping = find_socket_mapping(fildes);
    if (mapping && mapping->is_nsn_socket) {
        // Destroy sink, source, and stream if they exist
        if (mapping->sink != NSN_INVALID_SNK) {
            inside_nsn_code = 1;
            nsn_destroy_sink(mapping->sink);
            inside_nsn_code = 0;
            mapping->sink = NSN_INVALID_SNK;
            mapping->sink_id = 0;
        }
        if (mapping->source != NSN_INVALID_SRC) {
            inside_nsn_code = 1;
            nsn_destroy_source(mapping->source);
            inside_nsn_code = 0;
            mapping->source = NSN_INVALID_SRC;
            mapping->source_id = 0;
        }
        if (mapping->stream != NSN_INVALID_STREAM_HANDLE) {
            inside_nsn_code = 1;
            nsn_destroy_stream(mapping->stream);
            inside_nsn_code = 0;
            mapping->stream = NSN_INVALID_STREAM_HANDLE;
        }

        // Remove socket mapping
        mapping->fd = 0; // Set as unused
        mapping->is_nsn_socket = 0;
        
        // Close INSANE
        inside_nsn_code = 1;
        nsn_close();
        inside_nsn_code = 0;
        return 0; //The original close function is called inside nsn_close()
    }

    return default_close(fildes); // Call the close socket function for non-NSN sockets
}


int __libc_start_main(int (*main)(int, char **, char **), int argc,
                      char **ubp_av, void (*init)(void), void (*fini)(void),
                      void (*rtld_fini)(void), void(*stack_end))
{
    __start_main = dlsym(RTLD_NEXT, "__libc_start_main");

    default_send = dlsym(RTLD_NEXT, "send");
    default_sendto = dlsym(RTLD_NEXT, "sendto");
    default_listen = dlsym(RTLD_NEXT, "listen");
    default_accept = dlsym(RTLD_NEXT, "accept");
    default_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
    default_bind = dlsym(RTLD_NEXT, "bind");
    default_select = dlsym(RTLD_NEXT, "select");
    default_fcntl = dlsym(RTLD_NEXT, "fcntl");
    default_setsockopt = dlsym(RTLD_NEXT, "setsockopt");
    default_getsockopt = dlsym(RTLD_NEXT, "getsockopt");
    default_read = dlsym(RTLD_NEXT, "read");
    default_write = dlsym(RTLD_NEXT, "write");
    default_connect = dlsym(RTLD_NEXT, "connect");
    default_socket = dlsym(RTLD_NEXT, "socket");
    default_close = dlsym(RTLD_NEXT, "close");

    return __start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}