#ifndef INSANE_BUFFER_H
#define INSANE_BUFFER_H

#include <stdbool.h>
#include <stdint.h>

//--------------------------------------------------------------------------------------------------
// INSANE Buffer
//--------------------------------------------------------------------------------------------------
typedef struct nsn_buffer {
    int      index;
    uint8_t *data;
    int      len;
} nsn_buffer_t;

//--------------------------------------------------------------------------------------------------

bool nsn_buffer_is_valid(nsn_buffer_t *buf);

#endif // INSANE_BUFFER_H