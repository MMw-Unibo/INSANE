#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/queue.h>

//#include <insane/insane.h>
//#include <insane/logger.h>
#include <nsn/nsn.h>

#include "lunar_s.h"

//------------------------------------------------------------------------------
// utils
#define NSEC_TO_SEC 1000000000ULL

int64_t get_realtime_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    return ts.tv_sec * NSEC_TO_SEC + ts.tv_nsec;
}

int64_t get_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);

    return ts.tv_sec * NSEC_TO_SEC + ts.tv_nsec;
}

//------------------------------------------------------------------------------
// insane stuff
static nsn_stream_t s_stream;
static nsn_source_t s_source;
static nsn_sink_t   s_sink;

static int init_insane() {
    /* Init library */
    if (nsn_init() < 0) {
        fprintf(stderr, "Cannot init INSANE library\n");
        return -1;
    }

    /* Create stream */
    nsn_options_t options = {
        .datapath = NSN_QOS_DATAPATH_DEFAULT, .consumption = NSN_QOS_CONSUMPTION_POLL, .determinism = NSN_QOS_DETERMINISM_DEFAULT,
        .reliability = NSN_QOS_RELIABILITY_UNRELIABLE};

    s_stream = nsn_create_stream(options);
    if (s_stream == NSN_INVALID_STREAM_HANDLE) {
        fprintf(stderr, "nsn_create_stream() failed\n");
        return -2;
    }
    return 0;
}

//------------------------------------------------------------------------------
// lunar streaming
#define MTU           1400
#define END_STREAM    0
#define FRAME_START   1
#define NEXT_FRAGMENT 2
#define FRAME_END     3

// NOTE(garbu): only for testing.
#define MAX_FRAMES_IN_POOL 10
#define MAX_FRAME_SIZE     (7680 * 4320 * 3)

static struct frame s_first_frame;
static struct frame s_frames[MAX_FRAMES_IN_POOL];
static uint64_t     s_nb_frames;
static int64_t      s_send_times[1000];
static int64_t      s_nb_times;

struct lnr_s_header {
    int32_t frame_id;
    int32_t frame_size;
    int64_t timestamp;
    int32_t fragment_id;
    int32_t fragment_size;
    int8_t  flags;
} __attribute__((__packed__));

void lnr_streaming_open_server() {
    init_insane();

    s_source = nsn_create_source(s_stream, 0);
}

static int send_frame(struct frame *f) {
    size_t   frag_size      = MTU - sizeof(struct lnr_s_header);
    int      nb_bufs        = (f->size + frag_size -1) / frag_size;
    int64_t  ts             = get_realtime_ns();
    size_t   last_frag_size = frag_size;
    uint8_t *frame_data     = f->data;

    for (int i = 0; i < nb_bufs; i++) {
        nsn_buffer_t *buf = nsn_get_buffer(MTU, 0);
        if (nsn_buffer_is_valid(buf)) {
            struct lnr_s_header *hdr = (struct lnr_s_header *)buf->data;
            hdr->frame_id            = f->id;
            hdr->frame_size          = f->size;
            hdr->fragment_id         = i;

            if (i == 0) {
                hdr->flags         = FRAME_START;
                hdr->timestamp     = ts;
                hdr->fragment_size = frag_size;
            } else if (i < nb_bufs - 1) {
                hdr->flags         = NEXT_FRAGMENT;
                hdr->fragment_size = frag_size;
            } else {
                hdr->flags         = FRAME_END;
                size_t rem         = f->size % frag_size;
                hdr->fragment_size = (int32_t)((rem == 0) ? (int32_t) frag_size : (int32_t) rem);
            }

            uint8_t *buf_data = (uint8_t *)(hdr + 1);
            memcpy(buf_data, frame_data, hdr->fragment_size);
            buf->len = sizeof(*hdr) + hdr->fragment_size;
            /*printf("SENDER hdr: id=%d size=%d flags=%d buf->len=%zu idx=%zu data=%p\n",
                        hdr->frame_id, hdr->fragment_size, hdr->flags, buf->len, buf->index, (void*)buf->data);*/
            nsn_emit_data(s_source, buf);

            frame_data += last_frag_size;
            last_frag_size = hdr->fragment_size;
        }
    }

    return 0;
}

void lnr_streaming_connect() {
    init_insane();

    s_sink = nsn_create_sink(s_stream, 0, NULL);

    struct frame *f = NULL;
    for (int i = 0; i < MAX_FRAMES_IN_POOL; i++) {
        f       = &s_frames[i];
        f->data = malloc(MAX_FRAME_SIZE);
    }

    s_first_frame.data = malloc(MAX_FRAME_SIZE);
}

void lnr_streaming_disconnect() {
    struct frame *f = NULL;
    for (int i = 0; i < MAX_FRAMES_IN_POOL; i++) {
        f = &s_frames[i];
        free(f->data);
    }

    free(s_first_frame.data);

    nsn_destroy_sink(s_sink);
    nsn_close();
}

void lnr_start_loop(struct streaming_app *app) {
    do {
        //size_t size;

        struct frame f;
        if (app->generate(app->priv_data, &f) < 0) {
            // TODO(garbu): handle error in generation.
            return;
        }

        int64_t start = get_time_ns();
        send_frame(&f);
        s_send_times[s_nb_times++] = get_time_ns() - start;

    } while (app->wait_next(app->priv_data) >= 0);
}

struct frame *lnr_streaming_recv(int64_t *time) {
    int64_t       start_ts;
    int           state     = 0;
    struct frame *frame     = NULL;
    int           nb_frags = 0; //tot_frags = 0 

    // TODO(garbu): remove! only for testing.
    static int is_first = 1;

    do {
        nsn_buffer_t        *buf = nsn_consume_data(s_sink, NSN_BLOCKING);
        struct lnr_s_header *hdr = (struct lnr_s_header *)buf->data;

        switch (hdr->flags) {

        case FRAME_START:
            if (is_first) {
                frame    = &s_first_frame;
                is_first = 0;
            } else {
                frame = &s_frames[s_nb_frames % MAX_FRAMES_IN_POOL];
            }
            frame->id   = hdr->frame_id;
            frame->size = hdr->frame_size;
            frame->data      = malloc(frame->size);
            frame->frag_size = hdr->fragment_size;
            frame->ts        = hdr->timestamp;
            start_ts         = get_time_ns();

            break;

        case FRAME_END:
            if (frame) {
                frame->state = FRAME_REASSEMBLY_COMPLETE;
                //tot_frags    = hdr->fragment_id;
                state        = 2;
            }
            break;

        case END_STREAM:
            nsn_release_data(buf);
            *time = 0;
            return NULL;

        default:
            break;
        }

        if (frame) {
            printf("Copying offset for fragment\n");
            uint8_t *offset    = frame->data + (frame->frag_size * hdr->fragment_id);
            uint8_t *frag_data = (uint8_t *)(hdr + 1);
            memcpy(offset, frag_data, hdr->fragment_size);
            nb_frags++;
        }

        nsn_release_data(buf);
    } while (state != 2);

    frame->ts = get_realtime_ns() - frame->ts;
    *time     = get_time_ns() - start_ts;

    return frame;
}

void lnr_end_streaming() {
    nsn_buffer_t *buf = nsn_get_buffer(MTU, 0);
    if (nsn_buffer_is_valid(buf)) {
        struct lnr_s_header *hdr = (struct lnr_s_header *)buf->data;
        memset(hdr, 0, sizeof(*hdr));
        hdr->flags = END_STREAM;

        buf->len = sizeof(struct lnr_s_header);

        nsn_emit_data(s_source, buf);
    }

    printf("times\n");
    for (int i = 0; i < s_nb_times; i++) {
        printf("%ld\n", s_send_times[i]);
    }

    nsn_destroy_source(s_source);
    nsn_close();
}
