#include <insane/buffer.h>

//--------------------------------------------------------------------------------------------------
inline bool nsn_buffer_is_valid(nsn_buffer_t *buf) {
    return buf->index >= 0;
}