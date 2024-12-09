#define _GNU_SOURCE

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "../src/nsn_memory.c"
#include "../src/nsn_string.c"
#include "../src/nsn_log.h"
#include "../src/nsn_ringbuf.h"
#include "../src/nsn_ringbuf.c"
#include "../src/nsn_os.h"
#include "../src/nsn_os_linux.c"

static volatile bool g_running = true;

void 
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        g_running = false;
    }
}

int main(int argc, char *argv[]) {

    // Expect an argument called "ecount" and one called "rxburst" (two integers)
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <ecount> <rxburst>\n", argv[0]);
        return -1;
    }

    // Parse the arguments
    u32 ecount = atoi(argv[1]);
    u32 rxburst = atoi(argv[2]);
    if(rxburst > 64) {
        fprintf(stderr, "rxburst must be <= 64\n");
        return -1;
    }

    // Allocate memory (file backed) using mmap and huge pages
    const char *filename = "/dev/hugepages/testring.dat";
    usize total_size =  2147483648; // (ecount * sizeof(u64)) + sizeof(nsn_ringbuf_t);
    
    // Open or create the file
    int fd = open(filename, O_RDWR | O_CREAT, 0666);
    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    // Set the file size
    if (ftruncate(fd, total_size) < 0) {
        perror("ftruncate");
        close(fd);
        exit(EXIT_FAILURE);
    }

    // Map the file into memory
    void* ring_memory = mmap(0, total_size, PROT_READ | PROT_WRITE,  MAP_SHARED | MAP_HUGETLB, fd, 0);
    if (ring_memory == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }
    
    // Create the ring buffer
    nsn_ringbuf_t *rb = nsn_ringbuf_create(ring_memory, str_lit("txring"), ecount);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return -1;
    }

    // Dequeue burst
    u32 n = 0;
    u64 data[64];
    while(g_running) {
        n = nsn_ringbuf_dequeue_burst(rb, &data, sizeof(u64), rxburst, NULL);
        if (n!=rxburst && n > 0) {
            fprintf(stderr, "Only dequeued %u\n", n);
        }  
        if (n>0) {
            printf("Dequeued %u: ", n);
            for (u32 i = 0; i < n; i++) {
                printf("%lu ", data[i]);
            }
            printf("\n");
        }
    }

    // Cleanup
    nsn_ringbuf_destroy(rb);
    munmap(ring_memory, total_size);
    close(fd);
    unlink(filename);

    return 0;
}