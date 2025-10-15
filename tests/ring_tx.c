#define _GNU_SOURCE

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "base/nsn_memory.c"
#include "base/nsn_string.c"
#include "common/nsn_log.h"
#include "common/nsn_ringbuf.h"
#include "common/nsn_ringbuf.c"
#include "base/nsn_os.h"
#include "base/nsn_os_linux.c"

static volatile bool g_running = true;

void 
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        g_running = false;
    }
}

int main(int argc, char *argv[]) {

    // Expect an argument called "ecount" and one called "txburst" (two integers)
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <ecount> <txburst>\n", argv[0]);
        return -1;
    }

    // Parse the arguments
    u32 ecount = atoi(argv[1]);
    u32 txburst = atoi(argv[2]);
    if(txburst > 64) {
        fprintf(stderr, "txburst must be <= 64\n");
        return -1;
    }


    // Allocate memory (file backed) using mmap and huge pages
    const char *filename = "/dev/hugepages/testring.dat";
    usize total_size = 2147483648; // (ecount * sizeof(u64)) + sizeof(nsn_ringbuf_t);
    
    // Open or create the file
    int fd = open(filename, O_RDWR, 0666);
    if (fd < 0) {
        perror("open");
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

    // Enqueue data one at time, sleep when done
    for(u32 i = 0; i < ecount; i++) {
        u64 data = i;
        while(nsn_ringbuf_enqueue_burst(rb, &data, sizeof(u64), 1, NULL) < 1);
    }  

    while(g_running) {
        sleep(2);
    }

    // B. Enqueue data in bursts (up to 64 elements)
    // u64 data[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 
    //               10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 
    //               20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 
    //               30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 
    //               40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 
    //               50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 
    //               60, 61, 62, 63};
    // while(g_running) {
    //     for(u32 i = 0; i < ecount; i++) {
    //         u64 data = i;
    //         nsn_ringbuf_enqueue_burst(rb, &data, 1, 1, NULL);
    //     }
    //     sleep(1);
    // }

    // Cleanup
    nsn_ringbuf_destroy(rb);
    munmap(ring_memory, total_size);
    close(fd);

    return 0;
}