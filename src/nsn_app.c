// --- include files -----------------------------------------------------------
#include "nsn_types.h"
#include "nsn.h"
#include "nsn_os.h"
#include "nsn_os_inc.h"

// --- c files -----------------------------------------------------------------
#include "nsn.c"
#include "nsn_memory.c"
#include "nsn_os_inc.c"

int 
main(void)
{
    i64 start = nsn_os_get_time_ns();
    nsn_init();
    i64 end = nsn_os_get_time_ns();
    printf("nsn_init() took %.2f us\n", (end - start) / 1000.0);

    nsn_deinit();

    return 0;
}
