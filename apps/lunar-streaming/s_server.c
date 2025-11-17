#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lunar_s.h"

#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"

#define RATE_16MS 16666667

struct app_data {
    char   *data;
    size_t  size;
    int     frame_id;
    int     tot_frame;
    int64_t rate;
};

int wait_next(void *self) {
    struct app_data *ad = self;

    int64_t now, last_time;
    now = last_time = get_realtime_ns();
    int done        = 0;

    if (ad->frame_id == ad->tot_frame)
        return -1;

    while (!done) {
        now = get_realtime_ns();
        if ((now - last_time) > ad->rate) {
            last_time = now;
            done      = 1;
        }
    }

    return 0;
}

int x, y, n;

int gen(void *self, struct frame *f) {
    struct app_data *ad = self;

    memset(f, 0, sizeof(*f));
    f->data = (uint8_t *)ad->data;
    f->id   = ad->frame_id++;
    f->size = ad->size;
    f->x    = x;
    f->y    = y;
    f->n    = n;

    return 0;
}

int main(int argc, char *argv[]) {
    int     opt;
    char   *filename  = "prova.png";
    int     nb_frames = 1;
    int64_t rate_ms   = RATE_16MS;

    while ((opt = getopt(argc, argv, "i:f:r:")) != -1) {
        switch (opt) {
        case 'i':
            filename = optarg;
            break;
        case 'f':
            nb_frames = atoi(optarg);
            break;
        case 'r':
            rate_ms = atoi(optarg);
            break;
        default:
            fprintf(stderr, "Usage: %s -i <filename> -f <frames> -r <rate_ms>\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    struct app_data *ad = malloc(sizeof(struct app_data));
    ad->tot_frame       = nb_frames;
    ad->frame_id        = 0;
    ad->rate            = rate_ms * 1000000ll;

    ad->data = (char *)stbi_load(filename, &x, &y, &n, 0);
    if (!ad->data) {
        fprintf(stderr, "cannot open image: %s\n", filename);
        exit(EXIT_FAILURE);
    }

    ad->size = x * y * n;

    printf("size = %0.2fMB\n", ((float)ad->size) / 1e6);

    struct streaming_app app = {.generate = gen, .wait_next = wait_next, .priv_data = ad};

    lnr_streaming_open_server();

    lnr_start_loop(&app);

    lnr_end_streaming();

    return 0;
}