#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <insane/logger.h>

#define PORT 2509

void do_send(int sd, int num_msgs, struct sockaddr_in *d_addr) {
    char msg_buf[1024];
    for (int i = 0; i < num_msgs; i++) {
        int ret = sendto(sd, &msg_buf, sizeof(msg_buf), 0, (struct sockaddr *)d_addr,
                         sizeof(struct sockaddr));
        if (ret < 0) {
            perror("send: ");
        }
        LOG_DEBUG("Socket sendto: %d (%d bytes)", i, ret);
    }
    printf("All messages sent\n");
}

void do_receive(int sd, int num_msgs) {
    char    msg_buf[1024];
    ssize_t nb_rx = 0;
    int     i     = 0;
    while (i < num_msgs) {
        nb_rx = recvfrom(sd, &msg_buf, sizeof(msg_buf), 0, NULL, NULL);
        if (nb_rx > 0) {
            i++;
            LOG_DEBUG("Socket received %d (%u bytes)", i, nb_rx);
        }
    }
    printf("All messages received\n");
}

int main(int argc, char *argv[]) {
    if (argc != 4 && argc != 5) {
        printf("Usage: %s [c|s] <local_ip> <dest_ip> [num_msgs]\n", argv[0]);
        return -1;
    }

    int num_msgs = argc == 5 ? atoi(argv[4]) : 1000;

    // Prepare addresses
    struct sockaddr_in l_addr, d_addr;
    l_addr.sin_family = AF_INET;
    l_addr.sin_port   = htons(PORT);
    inet_aton(argv[2], &l_addr.sin_addr);

    d_addr.sin_family = AF_INET;
    d_addr.sin_port   = htons(PORT);
    inet_aton(argv[3], &d_addr.sin_addr);

    // Open async socket
    int sd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (sd < 0) {
        LOG_ERROR("Open socket for data: %s", strerror(errno));
        exit(1);
    }
    int ok = 1;
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (void *)&ok, sizeof(ok));

    // Bind socket
    if (bind(sd, (struct sockaddr *)&l_addr, sizeof(l_addr)) < 0) {
        LOG_ERROR("Bind socket: %s", strerror(errno));
        exit(1);
    }

    if (!strcmp(argv[1], "c")) {
        do_send(sd, num_msgs, &d_addr);
    } else if (!strcmp(argv[1], "s")) {
        do_receive(sd, num_msgs);
    } else {
        printf("Wrong role specified. Exiting...\n");
        return -1;
    }
}