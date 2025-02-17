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

#define NSN_LOG_IMPLEMENTATION
#include "nsn_log.h"

int 
main(void)
{
    int res = 0;

    i64 start = nsn_os_get_time_ns();
    if (nsn_init() < 0) {
        printf("nsn_init() failed\n");
        return -1;
    }
    i64 end = nsn_os_get_time_ns();
    printf("nsn_init() took %.2f us\n", (end - start) / 1000.0);

    // Set the desired QoS
    nsn_options_t opts;
    opts.consumption = NSN_QOS_CONSUMPTION_POLL;
    opts.datapath    = NSN_QOS_DATAPATH_DEFAULT;
    opts.determinism = NSN_QOS_DETERMINISM_DEFAULT;
    opts.reliability = NSN_QOS_RELIABILITY_UNRELIABLE;

    nsn_stream_t stream = nsn_create_stream(opts);
    if (stream == NSN_INVALID_STREAM_HANDLE) {
        printf("nsn_create_stream() failed\n");
        res = -1;
        goto cleanup;
    }

    // Create sink
    nsn_source_t snk = nsn_create_sink(&stream, 0, NULL);
    if (snk == NSN_INVALID_SNK) {
        printf("nsn_create_sink() failed\n");
        res = -1;
        goto cleanup_w_stream;
    }

    // Wait for a message on this sink
    nsn_buffer_t in_buf = nsn_consume_data(snk, NSN_BLOCKING);
    if (in_buf.len == 0) {
        printf("nsn_consume_data() failed\n");
        res = -1;
        goto cleanup_w_snk;
    }

    // Print the message
    printf("Received: %s\n", (char *)in_buf.data);

    // Release the buffer
    nsn_release_data(in_buf);

    // Sleep for a while
    sleep(1);

cleanup_w_snk:
    nsn_destroy_sink(snk);
cleanup_w_stream:
    nsn_destroy_stream(stream);
cleanup:
    nsn_close();

    return res;
}
