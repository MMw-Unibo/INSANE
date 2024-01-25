#include "../src/nsn_datapath.h"

#include <netinet/in.h>

struct udp_socket_config
{
    u16   port;
    char  addr[]; // IPv4 or IPv6 address
};

struct udp_socket
{
    int fd;
};

static struct udp_socket g_socket;

NSN_DATAPATH_INIT(udp_socket)
{
    struct udp_socket_config *config = ctx->configs;

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        return -1;
    }

    // set non-blocking
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        goto error;
    }

    flags |= O_NONBLOCK;
    if (fcntl(fd, F_SETFL, flags) == -1) {
        goto error;
    }

    // set reuseaddr
    int reuseaddr = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) == -1) {
        goto error;
    }

    // bind ui
    struct sockaddr_in addr;
    memory_zero_struct(&addr);
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(config->port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        goto error;
    }

    g_socket.fd = fd;
    return 0;

error:
    close(fd);
    return -1;
}