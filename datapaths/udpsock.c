#include "../src/nsn_datapath.h"

#include <arpa/inet.h>
#include <netinet/in.h>

#define UDP_SOCKET_ADDR_MAX 64

static u16  s_port;
static char s_addr[UDP_SOCKET_ADDR_MAX]; 
static int  s_sockfd;
struct sockaddr_in sock_addr;


NSN_DATAPATH_INIT(udpsock)
{
    char *config   = ctx->configs;
    char *port_str = NULL;
    int fd = 0, flags = 0, reuseaddr = 0;

    printf("char *config: %s\n", config);

    // parse config, : separated, e.g. "<addr>:<port>"
    port_str = strchr(config, ':');
    if (port_str == NULL)      return -1;

    *port_str = '\0';
    s_port = atoi(port_str + 1);
    if (s_port == 0)      return -1;

    strncpy(s_addr, config, UDP_SOCKET_ADDR_MAX);

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        fprintf(stderr, "socket() failed\n");
        return -1;
    }

    flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        fprintf(stderr, "fcntl() failed\n");
        goto error;
    }

    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) == -1) {
        fprintf(stderr, "fcntl() failed\n");
        goto error;
    }

    reuseaddr = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) == -1) {
        fprintf(stderr, "setsockopt() failed\n");
        goto error;
    }

    memory_zero_struct(&sock_addr);
    sock_addr.sin_family      = AF_INET;
    sock_addr.sin_port        = htons(s_port);
    sock_addr.sin_addr.s_addr = inet_addr(s_addr);
    if (bind(fd, (struct sockaddr *)&sock_addr, sizeof(sock_addr)) == -1) {
        fprintf(stderr, "bind() failed\n");
        goto error;
    }

    s_sockfd = fd;
    return 0;

error:
    close(fd);
    return -1;
}

struct sockaddr_in send_addr;

NSN_DATAPATH_TX(udpsock)
{
    isize ret = 0;
    usize i;
    int tx_count = 0;

    memory_zero_struct(&send_addr);
    send_addr.sin_family      = AF_INET;
    send_addr.sin_port        = htons(9999);
    inet_pton(AF_INET, "10.0.0.213", &send_addr.sin_addr);

    for (i = 0; i < buf_count; i++) {
        ret = sendto(s_sockfd, bufs[i].data, bufs[i].size, 0, (struct sockaddr *)&send_addr, sizeof(send_addr));
        if (ret == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                printf("EAGAIN or EWOULDBLOCK\n");
            else 
                printf("sendto() failed: %s\n", strerror(errno));
        } else {
            tx_count++;
        }
    }

    return tx_count;
}

NSN_DATAPATH_RX(udpsock)
{
    isize ret = 0;
    usize i   = 0;
    while (*buf_count--) {
        ret = recvfrom(s_sockfd, bufs[i].data, bufs[i].size, 0, NULL, NULL);
        // if ok increment i, otherwise retry
        if (ret == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
        } else {
            bufs[i].size = ret;
            i++;
        }
    }

    return i;
}

NSN_DATAPATH_DEINIT(udpsock)
{
    nsn_unused(ctx);

    int res = 0;
    if (s_sockfd == -1) {
        printf("[udpsock] socket already closed\n");
        res = -1;
    }
    else {
        printf("[udpsock] closing socket\n");
        close(s_sockfd);
        s_sockfd = -1;
    }

    return res;
}