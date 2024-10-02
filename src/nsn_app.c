// --- include files -----------------------------------------------------------
#include "nsn_types.h"
#include "nsn.h"
#include "nsn_os.h"
#include "nsn_os_inc.h"
#include "nsn_string.h"

// --- c files -----------------------------------------------------------------
#include "nsn.c"
#include "nsn_memory.c"
#include "nsn_os_inc.c"
#include "nsn_shm.c"
#include "nsn_string.c"
#include "nsn_ringbuf.c"

#define NSN_LOG_IMPLEMENTATION_H
#include "nsn_log.h"

int 
main(void)
{
    int res = 0;

    // This will become a parameter
    size_t buf_size = 64;

    i64 start = nsn_os_get_time_ns();
    if (nsn_init() < 0) {
        printf("nsn_init() failed\n");
        return -1;
    }
    i64 end = nsn_os_get_time_ns();
    printf("nsn_init() took %.2f us\n", (end - start) / 1000.0);

    nsn_stream_t stream = nsn_create_stream(NULL);
    if (stream == NSN_INVALID_STREAM_HANDLE) {
        printf("nsn_create_stream() failed\n");
        res = -1;
        goto cleanup;
    }

    nsn_source_t src = nsn_create_source(&stream, 0);
    if (src == NSN_INVALID_SRC) {
        printf("nsn_create_source() failed\n");
        res = -1;
        goto cleanup_w_stream;
    }

    nsn_source_t snk = nsn_create_sink(&stream, 0, NULL);
    if (src == NSN_INVALID_SNK) {
        printf("nsn_create_sink() failed\n");
        res = -1;
        goto cleanup_w_src;
    }

    // Get buffer and write there
    nsn_buffer_t out_buf = nsn_get_buffer(buf_size, NSN_BLOCKING);
    if(!out_buf.len) {
        printf("nsn_get_buffer() failed\n");
        res = -1;
        goto cleanup_w_src;
    }
    strcpy((char *)out_buf.data, "Hello, World!");

    // // Emit data
    int ok_buf = nsn_emit_data(src, out_buf);

    // // Check the outcome
    // // TODO: unimplemented
    nsn_unused(ok_buf);

    // Wait for a message on this sink
    // TODO: unimplemented
    sleep(1);

    nsn_destroy_sink(snk);
cleanup_w_src:
    nsn_destroy_source(src);
cleanup_w_stream:
    nsn_destroy_stream(stream);
cleanup:
    nsn_close();

    return res;
}
