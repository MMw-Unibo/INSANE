#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lunar_s.h"

#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"

struct stream_stats {
    int64_t lat;
    int64_t time;
    int64_t drops;
};

static struct stream_stats g_stats[100000];

int set_quality(const char *q, int *w, int *h) {
    if (strcmp(q, "hd") == 0) {
        *w = 1280;
        *h = 720;
    } else if (strcmp(q, "fullhd") == 0) {
        *w = 1920;
        *h = 1080;
    } else if (strcmp(q, "2k") == 0) {
        *w = 2560;
        *h = 1440;
    } else if (strcmp(q, "4k") == 0) {
        *w = 3840;
        *h = 2160;
    } else if (strcmp(q, "8k") == 0) {
        *w = 7680;
        *h = 4320;
    } else {
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    int opt;
    int width  = 1920;
    int height = 1080;

    char *quality = "fullhd";

    while ((opt = getopt(argc, argv, "q:")) != -1) {
        switch (opt) {
        case 'q':
            quality = optarg;
            break;
        default:
            fprintf(stderr, "Usage: %s [-q [hd|fullhd|2k|4k|8k]]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (set_quality(quality, &width, &height) < 0) {
        printf("unknown image quality, use: hd|fullhd|2k|4k|8k\n");
    }

    printf("Starting client with quality: %s\n", quality);
    lnr_streaming_connect();

    struct frame *frame = NULL;
    //struct frame *ff    = NULL;

    int                  total_frames = 0;
    int                  first        = 1;
    int64_t              frame_time   = 0;
    struct stream_stats *stat;
    do {
        frame = lnr_streaming_recv(&frame_time);
        if (frame) {
            printf("RECEIVED FRAME\n");
            stat       = &g_stats[total_frames++];
            stat->lat  = frame->ts;
            stat->time = frame_time;

            if (first) {
                first = 0;
                //ff    = frame;
            }
            // lns_release_frame(frame->id);
        }
    } while (frame);

    // stbi_write_png("tmp.png", width, height, 3, ff->data, 3 * width);
    printf("lat, time\n");
    for (int64_t i = 0; i < total_frames; i++) {
        stat = &g_stats[i];
        printf("%ld,%ld\n", stat->lat, stat->time);
    }

    lnr_streaming_disconnect();

    return 0;
}
