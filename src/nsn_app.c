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
