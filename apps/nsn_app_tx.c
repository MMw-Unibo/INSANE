// --- include files -----------------------------------------------------------
// #include "nsn_types.h"
// #include "nsn.h"
// #include "nsn_os.h"
// #include "nsn_os_inc.h"
// #include "nsn_string.h"

// // --- c files -----------------------------------------------------------------
// #include "nsn.c"
// #include "nsn_memory.c"
// #include "nsn_os_inc.c"
// #include "nsn_shm.c"
// #include "nsn_string.c"
// #include "nsn_ringbuf.c"

// #define NSN_LOG_IMPLEMENTATION_H
// #include "nsn_log.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <nsn/nsn.h>

int 
main(void)
{
    int res = 0;

    // This will become a parameter
    size_t buf_size = 64;

    if (nsn_init() < 0) {
        printf("nsn_init() failed\n");
        return -1;
    }

    // Set the desired QoS
    nsn_options_t opts;
    opts.consumption =  NSN_QOS_CONSUMPTION_POLL;
    opts.datapath    =  NSN_QOS_DATAPATH_DEFAULT;
    opts.determinism =  NSN_QOS_DETERMINISM_DEFAULT;
    opts.reliability =  NSN_QOS_RELIABILITY_UNRELIABLE;

    nsn_stream_t stream = nsn_create_stream(opts);
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

    // Get buffer and write there
    nsn_buffer_t out_buf = nsn_get_buffer(buf_size, NSN_BLOCKING);
    if(!out_buf.len) {
        printf("nsn_get_buffer() failed\n");
        res = -1;
        goto cleanup_w_src;
    }
    strcpy((char *)out_buf.data, "Hello, World!");
    out_buf.len = strlen("Hello, World!") + 1;

    // Emit data
    int ok_buf = nsn_emit_data(src, out_buf);

    // Check the outcome
    // TODO: unimplemented
    ((void)ok_buf);

    sleep(1);

cleanup_w_src:
    nsn_destroy_source(src);
cleanup_w_stream:
    nsn_destroy_stream(stream);
cleanup:
    nsn_close();

    return res;
}
