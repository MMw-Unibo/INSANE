#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/queue.h>

#include <insane/insane.h>
#include <insane/logger.h>

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

static int init_insane(nsn_stream_t *stream) {
    /* Init library */
    if (nsn_init() < 0) {
        fprintf(stderr, "Cannot init INSANE library\n");
        return -1;
    }

    /* Create stream */
    nsn_options_t options = {
        .datapath = datapath_slow, .consumption = consumption_high, .determinism = determinism_no};

    *stream = nsn_create_stream(&options);

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
    init_insane(&s_stream);

    s_source = nsn_create_source(&s_stream, 1);
}

static int send_frame(struct frame *f) {
    int      nb_bufs        = f->size / (MTU - sizeof(struct lnr_s_header *));
    int      frag_size      = MTU - sizeof(struct lnr_s_header);
    int64_t  ts             = get_realtime_ns();
    int      last_frag_size = frag_size;
    uint8_t *frame_data     = f->data;

    for (int i = 0; i < nb_bufs; i++) {
        nsn_buffer_t buf = nsn_get_buffer(s_source, MTU, 0);
        if (nsn_buffer_is_valid(&buf)) {
            struct lnr_s_header *hdr = (struct lnr_s_header *)buf.data;
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
                hdr->fragment_size = f->size % nb_bufs;
            }

            uint8_t *buf_data = (uint8_t *)(hdr + 1);
            memcpy(buf_data, frame_data, hdr->fragment_size);
            buf.len = MTU;
            nsn_emit_data(s_source, &buf);

            frame_data += last_frag_size;
            last_frag_size = hdr->fragment_size;
        }
    }

    return 0;
}

void lnr_streaming_connect() {
    init_insane(&s_stream);

    s_sink = nsn_create_sink(&s_stream, 1, NULL);

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

    // nsn_destroy_sink(s_sink);
    // nsn_close();
}

void lnr_start_loop(struct streaming_app *app) {
    do {
        size_t size;

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
    int           tot_frags = 0, nb_frags = 0;

    // TODO(garbu): remove! only for testing.
    static int is_first = 1;

    do {
        nsn_buffer_t         buf = nsn_consume_data(s_sink, 0);
        struct lnr_s_header *hdr = (struct lnr_s_header *)buf.data;

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
            // frame->data      = malloc(frame->size);
            frame->frag_size = hdr->fragment_size;
            frame->ts        = hdr->timestamp;
            start_ts         = get_time_ns();

            break;

        case FRAME_END:
            if (frame) {
                frame->state = FRAME_REASSEMBLY_COMPLETE;
                tot_frags    = hdr->fragment_id;
                state        = 2;
            }
            break;

        case END_STREAM:
            nsn_release_data(s_sink, &buf);
            *time = 0;
            return NULL;

        default:
            break;
        }

        if (frame) {
            char *offset    = frame->data + (frame->frag_size * hdr->fragment_id);
            char *frag_data = (char *)(hdr + 1);
            memcpy(offset, frag_data, hdr->fragment_size);
            nb_frags++;
        }

        nsn_release_data(s_sink, &buf);
    } while (state != 2);

    frame->ts = get_realtime_ns() - frame->ts;
    *time     = get_time_ns() - start_ts;

    return frame;
}

void lnr_end_streaming() {
    nsn_buffer_t buf = nsn_get_buffer(s_source, MTU, 0);
    if (nsn_buffer_is_valid(&buf)) {
        struct lnr_s_header *hdr = (struct lnr_s_header *)buf.data;
        memset(hdr, 0, sizeof(*hdr));
        hdr->flags = END_STREAM;

        buf.len = sizeof(struct lnr_s_header);

        nsn_emit_data(s_source, &buf);
    }

    printf("times\n");
    for (int i = 0; i < s_nb_times; i++) {
        printf("%ld\n", s_send_times[i]);
    }

    // nsn_destroy_source(s_source);
    // nsn_close();
}
