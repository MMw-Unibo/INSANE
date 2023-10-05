#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h> // read(), write(), close()

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

#include "lunar_s.h"

int fd;
int filesize;

// Function designed for chat between client and server.
void func(int sockfd, int connfd) {
    int n;

    struct header {
        int64_t timestamp;
        int     size;
        int     frame;
    } hdr;

    printf("start\n");

    int optval = 1;
    if (setsockopt(connfd, SOL_SOCKET, SO_ZEROCOPY, &optval, sizeof(optval))) {
        printf("error\n");
        return;
    }

    for (int i = 0; i < 1; i++) {
        optval = 1;
        setsockopt(connfd, IPPROTO_TCP, TCP_CORK, &optval, sizeof(optval));

        hdr.size      = filesize;
        hdr.frame     = i + 1;
        hdr.timestamp = get_realtime_ns();

        ssize_t res = send(connfd, (void *)&hdr, sizeof(struct header), 0);
        printf("%ld\n", res);

        res = sendfile(connfd, fd, NULL, filesize);

        printf("%ld\n", res);

        optval = 0;
        setsockopt(connfd, IPPROTO_TCP, TCP_CORK, &optval, sizeof(optval));

        sleep(1);
        printf("next frame\n");
    }

    printf("end\n");
}

int main(int argc, char *argv[]) {
    int   opt;
    char *filename = "prova.png";
    char *address  = "127.0.0.1";
    int   port     = 9999;
    while ((opt = getopt(argc, argv, "i:a:p:")) != -1) {
        switch (opt) {
        case 'i':
            filename = optarg;
            break;
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

    // fd = open(filename, O_RDONLY, 0);
    // if (fd < 0) {
    //     perror("open");
    //     exit(1);
    // }

    // struct stat st;
    // if (fstat(fd, &st)) {
    //     perror("stat");
    //     exit(1);
    // }

    // filesize = st.st_size;

    int   x, y, n;
    char *data = stbi_load(filename, &x, &y, &n, 0);
    if (!data) {
        fprintf(stderr, "cannot open image: %s\n", filename);
        exit(EXIT_FAILURE);
    }

    size_t frame_size = x * y * n;

    printf("framesize = %0.2f\n", ((float)frame_size) / 1e6);

    int    flags = (O_CREAT | O_RDWR);
    mode_t mode  = (S_IRUSR | S_IRUSR);

    fd = shm_open("sendfile_test", flags, mode);
    if (fd == -1) {
        perror("shm_open");
        return -1;
    }

    if (ftruncate(fd, frame_size) == -1) {
        return -2;
    }

    filesize = frame_size;

    uint8_t *memory = mmap(0, frame_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    for (int i = 0; i < frame_size; i++) {
        *memory++ = *data++;
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "canno open socket: %s\n", strerror(errno));
        exit(1);
    }

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family      = AF_INET;
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);
    saddr.sin_port        = htons(port);

    // Binding newly created socket to given IP and verification
    if ((bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr))) != 0) {
        printf("socket bind failed...\n");
        exit(0);
    } else
        printf("Socket successfully binded..\n");

    // Now server is ready to listen and verification
    if ((listen(sockfd, 5)) != 0) {
        printf("Listen failed...\n");
        exit(0);
    } else
        printf("Server listening..\n");

    struct sockaddr_in caddr;
    socklen_t          caddrlen;
    // Accept the data packet from client and verification
    int connfd = accept(sockfd, (struct sockaddr *)&caddr, &caddrlen);
    if (connfd < 0) {
        perror("server accept failed: ");
        exit(0);
    } else
        printf("server accept the client...\n");

    // Function for chatting between client and server
    func(sockfd, connfd);

    // After chatting close the socket
    close(sockfd);
}
