#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h> // read(), write(), close()

#include <arpa/inet.h>
#include <netinet/in.h>

#include <sys/socket.h>

#include "lunar_s.h"

#define MAX          4096
#define NSEC_PER_SEC 1000000000ULL

int run = 1;

void handler(int signum) {
    run = 0;
}

struct header {
    int64_t timestamp;
    int     size;
    int     frame;
};

int64_t times[1000];
int64_t nb_frames = 0;

void func(int sockfd) {
    char          buff[MAX];
    int           n;
    int64_t       start, end;
    int           new_frame = 1;
    struct header hdr;
    int           bytes_read = 0;
    while (run) {
        n = recv(sockfd, buff, sizeof(buff), 0);
        if (n < 0) {
            printf("cannot recv\n");
        } else if (n > 0) {
            if (new_frame) {
                memcpy(&hdr, buff, sizeof(struct header));
                start     = get_realtime_ns();
                new_frame = 0;
                bytes_read += (n - sizeof(struct header));
            } else {
                bytes_read += n;
            }

            if (bytes_read == hdr.size) {
                times[nb_frames++] = get_realtime_ns() - hdr.timestamp;
                new_frame          = 1;
            }
        }
    }

    printf("times\n");
    for (int i = 0; i < nb_frames; i++) {
        printf("%ld\n", times[i]);
    }
}

int main(int argc, char *argv[]) {
    signal(SIGINT, handler);

    int                connfd;
    struct sockaddr_in servaddr, cli;

    int   opt;
    char *address = "127.0.0.1";
    int   port    = 9999;
    while ((opt = getopt(argc, argv, "a:p:")) != -1) {
        switch (opt) {
        case 'a':
            address = optarg;
            break;
        case 'p':
            port = atoi(optarg);
            break;
        default:
            fprintf(stderr, "Usage: %s -i <filename>\n", argv[0]);
            exit(1);
        }
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "canno open socket: %s\n", strerror(errno));
        exit(1);
    }

    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    } else
        printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin_family      = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(address);
    servaddr.sin_port        = htons(port);

    // connect the client socket to server socket
    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0) {
        printf("connection with the server failed...\n");
        exit(0);
    } else
        printf("connected to the server..\n");

    // function for chat
    func(sockfd);

    // close the socket
    close(sockfd);
}