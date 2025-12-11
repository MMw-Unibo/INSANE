#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <net/if.h>

#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/resource.h>

#include <linux/if_link.h>
#include <linux/if_ether.h>

#include <bpf/bpf.h>

#include <xdp/xsk.h>
#include <xdp/libxdp.h>

typedef int8_t         i8;
typedef int16_t        i16;
typedef int32_t        i32;
typedef int64_t        i64;

typedef uint8_t         u8;
typedef uint16_t        u16;
typedef uint32_t        u32;
typedef uint64_t        u64;
typedef unsigned int    uint;

// -----------------------------------------------------------------------------
// - Helpers
void
error_exit_(const char *msg, bool show_errno)
{
    char errbuf[1024];
    int n = snprintf(errbuf, sizeof(errbuf), "[error] %s", msg);
    if (show_errno) {
        snprintf(errbuf + n, sizeof(errbuf) - n, ": %s (%d)", strerror(errno), errno);
    }
    fprintf(stderr, "%s\n", errbuf);
    exit(EXIT_FAILURE);
}
#define error_exit(msg)     error_exit_((msg), true)

#define arg_eq(a, b)        (strcmp((a), (b)) == 0)

// -----------------------------------------------------------------------------
// - XDP Helpers

// --- Umem
typedef struct xsk_umem_info xsk_umem_info;
struct xsk_umem_info
{
    struct xsk_ring_prod     fq;
    struct xsk_ring_cons     cq;
    struct xsk_umem         *umem;
    void                    *buffer;
};

static xsk_umem_info *
xsk_config_umem(void *buffer, size_t size, uint32_t frame_size)
{
    xsk_umem_info *umem = calloc(1, sizeof(*umem));
    assert(umem && "failed to allocate umem");

    struct xsk_umem_config umem_cfg = {
        .fill_size      = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
        .comp_size      = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size     = frame_size,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags          = XSK_UMEM__DEFAULT_FLAGS,
    };

    int ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, &umem_cfg);
    if (ret) {
        error_exit("xsk_umem__create failed");
    }

    umem->buffer = buffer;
    return umem;
}

// --- XSK Socket Stats
typedef struct xsk_socket_stats xsk_socket_stats;
struct xsk_socket_stats
{
    uint64_t    timestamp;
    // RX Stats
    uint64_t    rx_packets;
    uint64_t    rx_bytes;
    uint64_t    rx_dropped;
    // TX Stats
    uint64_t    tx_packets;
    uint64_t    tx_bytes;
    uint64_t    tx_dropped;

    // Ring Stats
    uint64_t    rx_ring_full;
    uint64_t    rx_fill_ring_full;
    uint64_t    rx_compl_ring_full;
    uint64_t    tx_ring_full;
    uint64_t    tx_complete_ring_full;
    uint64_t    tx_poll;
    uint64_t    rx_poll;
    uint64_t    rx_alloc_failed;
    uint64_t    tx_alloc_failed;
};


// --- XSK Socket
typedef struct xsk_socket_info xsk_socket_info;
struct xsk_socket_info
{
    struct xsk_ring_prod     tx;
    struct xsk_ring_cons     rx;
    struct xsk_umem_info    *umem;
    struct xsk_socket       *xsk;

    uint64_t    *umem_frame_addrs;
    size_t       umem_frame_count;
    uint32_t     umem_frame_free;

    // NOTE: Some Stats
    // - outstanding_tx is used to track the number of outstanding packets that
    //   have been sent, i.e. packets that have been sent but not yet completed.
    uint32_t    outstanding_tx;

    xsk_socket_stats     stats;
    xsk_socket_stats     prev_stats;
};

static u64
xsk_alloc_umem_frame(xsk_socket_info *xsk_info)
{
    u64 frame;
    if (xsk_info->umem_frame_free == 0) return UINT64_MAX;

    frame = xsk_info->umem_frame_addrs[--xsk_info->umem_frame_free];
    xsk_info->umem_frame_addrs[xsk_info->umem_frame_free] = UINT64_MAX;
    return frame;
}

static xsk_socket_info *
xsk_socket_config(xsk_umem_info *umem, const char *ifname, uint ifqueue,
    int num_frames, int frame_size)
{
    struct xsk_socket_info *xsk_info = calloc(1, sizeof(*xsk_info));
    assert(xsk_info && "failed to allocate xsk_info");
    xsk_info->umem_frame_addrs = malloc(num_frames * sizeof(*xsk_info->umem_frame_addrs));

    xsk_info->umem = umem;

    struct xsk_socket_config xsk_cfg = {
        .rx_size        = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size        = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .xdp_flags      = XDP_FLAGS_HW_MODE, // 0, // TODO: Add XDP_FLAGS
        .bind_flags     = XDP_ZEROCOPY, // 0, // TODO: Add BIND_FLAGS
        // .xdp_flags      = XDP_FLAGS_SKB_MODE, // 0, // TODO: Add XDP_FLAGS
        // .bind_flags     = XDP_COPY, // 0, // TODO: Add BIND_FLAGS
        .libbpf_flags   = 0, // Load the default XDP program,
                             // change to XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD to
                             // inhibit loading
    };

    int ret = xsk_socket__create(&xsk_info->xsk, ifname,
                ifqueue, umem->umem, &xsk_info->rx, &xsk_info->tx,
                &xsk_cfg);
    if (ret) goto error_return;

    for (int i = 0; i < num_frames; ++i)    xsk_info->umem_frame_addrs[i] = i * frame_size;

    xsk_info->umem_frame_free = num_frames;

    uint idx;
    ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
            XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx);
    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)    goto error_return;

    for (int i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; ++i) {
        *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx) = xsk_alloc_umem_frame(xsk_info);
        ++idx;
    }

    // xsk_ring_prod__submit.
    // The first argument, &xsk_info->umem->fq, is a pointer to the fill queue
    // (fq) of the UMEM (User Memory) associated with the XDP socket (xsk).
    // The fill queue is a ring buffer that holds descriptors for frames that
    // are available to be filled with incoming packets.
    // The second argument, XSK_RING_PROD__DEFAULT_NUM_DESCS, is a constant that
    // specifies the number of descriptors to submit to the fill queue. This
    // constant typically defines a default number of descriptors that the ring
    // buffer can handle in one submission.
    // By calling this function, the code is effectively notifying the kernel
    // that a certain number of descriptors are ready to be used for receiving
    // packets. This is a crucial step in the packet processing pipeline,
    // ensuring that there are always available buffers for incoming data.
    xsk_ring_prod__submit(&xsk_info->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);

    return xsk_info;

error_return:
    free(xsk_info);
    errno = -ret;
    return NULL;
}

static xsk_socket_info *
init_xdp(const char *ifname, int ifqueue, int num_frames, int frame_size)
{
    struct bpf_object_open_opts opts = {
        .sz = sizeof(opts),
    };
    struct xdp_program_opts xdp_opts = {
        .sz = sizeof(xdp_opts),
        .fd = 0,
    };

    struct rlimit rlim =  {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim) < 0) {
        error_exit("setrlimit failed");
    }

    fprintf(stderr, "[info] allocating memory used as packets buffer\n");

    void *packet_buffer = NULL;
    size_t packet_buffer_size = num_frames * frame_size;
    if (posix_memalign(&packet_buffer, getpagesize(), packet_buffer_size) < 0) {
        error_exit("posix_memalign failed");
    }

    fprintf(stderr, "[info] configuring the UMEM\n");

    xsk_umem_info *umem_info = xsk_config_umem(packet_buffer, packet_buffer_size, frame_size);
    if (!umem_info) {
        error_exit("xsk_config_umem failed");
    }

    fprintf(stderr, "[info] configuring the XSK socket\n");

    struct xsk_socket_info *xsk_info =
        xsk_socket_config(umem_info, ifname, ifqueue, num_frames, frame_size);
    assert(xsk_info && "failed to configure xsk socket");

    return xsk_info;
}

static int
do_rx(xsk_socket_info *xsk_info, int batch_size, int num_frames)
{
    u32 idx_rx = 0;
    // Look for new packets using the RX ring:
    //  - rcvd: number of packets received
    //  - idx_rx: index of the last packet received
    uint rcvd = xsk_ring_cons__peek(&xsk_info->rx, batch_size, &idx_rx);
    if (!rcvd)  return 0;

    int ret;
    uint stock_frames =
        xsk_prod_nb_free(&xsk_info->umem->fq, xsk_info->umem_frame_free);
    if (stock_frames > 0) {
        uint idx_fq;
        ret = xsk_ring_prod__reserve(&xsk_info->umem->fq, stock_frames, &idx_fq);
        while (ret != (int)stock_frames)     ret = xsk_ring_prod__reserve(&xsk_info->umem->fq, rcvd, &idx_fq);

        for (uint i = 0; i < stock_frames; ++i) {
            *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx_fq) = xsk_alloc_umem_frame(xsk_info);
            ++idx_fq;
        }

        xsk_ring_prod__submit(&xsk_info->umem->fq, stock_frames);
    }

    // Process the packets:
    for (uint i = 0; i < rcvd; ++i) {
        const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&xsk_info->rx, idx_rx);
        u64 addr = desc->addr;
        u32 len  = desc->len;

        bool process_ok = true;
        {
            u8 *payload = xsk_umem__get_data(xsk_info->umem->buffer, addr);
            ((void)payload);
        }
        // Clean up the packet if it was not processed:
        if (!process_ok) {
            assert(xsk_info->umem_frame_free < num_frames && "umem frame free");
            xsk_info->umem_frame_addrs[xsk_info->umem_frame_free++] = addr;
        }
    }

    // Release the packets:
    xsk_ring_cons__release(&xsk_info->rx, rcvd);
    xsk_info->stats.rx_packets += rcvd;
    //----------------------------------------------------------------------
}

static void
debug_packet(u8 *payload, uint len)
{
    struct ethhdr *eth = (struct ethhdr *)payload;
    if (sizeof(*eth) > len) {
        printf("packet too small\n");
    } else {
        char printbuf[1024];
        snprintf(printbuf, sizeof(printbuf),
                 "received packet: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x (proto=0x%04x)\n",
                 eth->h_source[0], eth->h_source[1], eth->h_source[2],
                 eth->h_source[3], eth->h_source[4], eth->h_source[5],
                 eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
                 eth->h_dest[3], eth->h_dest[4], eth->h_dest[5],
                 ntohs(eth->h_proto)
                );
        fprintf(stderr, "%s", printbuf);
    }
}

// -----------------------------------------------------------------------------
#define NUM_FRAMES      1024
#define FRAME_SIZE      2048
#define RX_BATCH_SIZE   2

static bool g_running = true;

void signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        g_running = false;
    }
}

// -----------------------------------------------------------------------------
int
main(int argc, char *argv[])
{
    signal(SIGINT, signal_handler);

    // Default values
    char *ifname = "eth0";
    int ifqueue  = 0;

    int opt;
    while ((opt = getopt(argc, argv, "i:r:")) != -1) {
        switch (opt) {
            case 'i':
                ifname = optarg;
                break;
            default:
                printf("Usage: %s [-i interface]\n", argv[0]);
                error_exit("invalid option");
        }
    }

    xsk_socket_info *xsk_info = init_xdp(ifname, ifqueue, NUM_FRAMES, FRAME_SIZE);
    assert(xsk_info && "failed to initialize xdp");

    // Used only in the poll mode
    {
        struct pollfd fds[2];
        memset(fds, 0, sizeof(fds));
        fds[0].fd     = xsk_socket__fd(xsk_info->xsk);
        fds[0].events = POLLIN;
    }

    while (g_running) {
        do_rx(xsk_info, RX_BATCH_SIZE, NUM_FRAMES);
    }

    xsk_socket__delete(xsk_info->xsk);
    xsk_umem__delete(xsk_info->umem->umem);

    return EXIT_SUCCESS;
}
