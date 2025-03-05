#ifndef NSN_MM_H
#define NSN_MM_H

#include "base/nsn_memory.h"
#include "base/nsn_shm.h"
#include "base/nsn_string.h"

#include "common/nsn_ringbuf.h"
#include "common/nsn_temp.h"
#include "common/nsn_zone.h"

typedef struct nsn_mem_manager_cfg nsn_mem_manager_cfg_t;
struct nsn_mem_manager_cfg
{
    string_t     shm_name;
    usize        shm_size;
    usize        io_buffer_pool_size;
    usize        io_buffer_size;
};

//  The memory manager is responsible for creating and managing the shared 
//  memory.
//  It uses a Page Allocator to allocate memory from the shared memory.
//  In particular, the managed memory is used to store:
//   - The io buffer pools: used to store the packets received and transmitted 
//     from and to the data plane and the applications
//   - The ring buffers: use to exchange the pointers to the io buffers between 
//     the data plane and the applications
typedef struct nsn_mem_manager nsn_mem_manager_t;
struct nsn_mem_manager
{
    nsn_shm_t           *shm;
    fixed_mem_arena_t   *shm_arena;
    // The list of zones is the first block of the shared memory
    nsn_mm_zone_list_t  *zones;
};

nsn_mem_manager_t  *nsn_memory_manager_create  (mem_arena_t *arena, nsn_mem_manager_cfg_t *cfg);
void                nsn_memory_manager_destroy (nsn_mem_manager_t *mem);

nsn_mm_zone_t      *nsn_memory_manager_create_zone (nsn_mem_manager_t *mem, string_t name, usize size, usize type);

nsn_ringbuf_pool_t *nsn_memory_manager_create_ringbuf_pool (nsn_mem_manager_t *mem, string_t name, usize count, usize esize, usize ecount); 
nsn_ringbuf_pool_t *nsn_memory_manager_get_ringbuf_pool    (nsn_mem_manager_t* mem);
nsn_ringbuf_t      *nsn_memory_manager_create_ringbuf      (nsn_ringbuf_pool_t* pool, string_t ring_name);
nsn_ringbuf_t      *nsn_memory_manager_lookup_ringbuf      (nsn_mem_manager_t* mem, string_t ring_name);
int                 nsn_memory_manager_destroy_ringbuf     (nsn_ringbuf_pool_t* pool, string_t ring_name);

#endif // NSN_MM_H