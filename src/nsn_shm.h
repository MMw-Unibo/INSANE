#ifndef NSN_SHARED_MEMORY_H
#define NSN_SHARED_MEMORY_H

#include "nsn_log.h"
#include "nsn_memory.h"
#include "nsn_types.h"

#define NSN_SHM_NAME_MAX 32

typedef struct nsn_shm nsn_shm_t;
struct nsn_shm 
{
    char    name[NSN_SHM_NAME_MAX];

    nsn_shm_t   *base;

    int     fd;
    usize   size;
    usize   used;
    atu32   ref_count;
} nsn_cache_aligned;

nsn_shm_t *nsn_shm_alloc(mem_arena_t *arena, const char *name, usize size);
nsn_shm_t *nsn_shm_attach(const char *name, usize size);
void       nsn_shm_detach(nsn_shm_t *shm);
void       nsn_shm_release(nsn_shm_t *shm);

static inline void *nsn_shm_rawdata(nsn_shm_t *shm) { return ((byte *)shm->base) + sizeof(nsn_shm_t); }
static inline usize nsn_shm_size(nsn_shm_t *shm)    { return shm->size - sizeof(nsn_shm_t); }

#endif // NSN_SHARED_MEMORY_H