#ifndef LUNAR_STREAMING_H
#define LUNAR_STREAMING_H

#define FRAME_REASSEMBLY_START    0
#define FRAME_REASSEMBLY_COMPLETE 1

#include <stdint.h>

struct frame {
    int32_t id;
    int32_t size;
    int64_t ts;
    int32_t frag_size;
    uint8_t state;
    int     x;
    int     y;
    int     n;

    uint8_t *data;

    struct frame *next;
};

int64_t get_time_ns();
int64_t get_realtime_ns();

struct streaming_app {
    int (*generate)(void *self, struct frame *f);
    int (*wait_next)(void *self);

    void *priv_data;
};

void lnr_streaming_open_server();
void lnr_end_streaming();
void lnr_streaming_connect();
void lnr_streaming_disconnect();

void lnr_start_loop(struct streaming_app *app);

struct frame *lnr_streaming_recv(int64_t *time);

#endif // LUNAR_STREAMING_H