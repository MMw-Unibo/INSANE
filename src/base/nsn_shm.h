#ifndef NSN_SHARED_MEMORY_H
#define NSN_SHARED_MEMORY_H

#include "nsn_memory.h"
#include "nsn_types.h"

#include "common/nsn_log.h"

#define NSN_SHM_NAME_MAX 32

typedef struct nsn_shm nsn_shm_t;
struct nsn_shm 
{
    char    name[NSN_SHM_NAME_MAX];

    byte   *data;

    int     fd;
    usize   size;
    usize   used;
    atu32   ref_count;
} nsn_cache_aligned;

nsn_shm_t *nsn_shm_alloc(mem_arena_t *arena, const char *name, usize size);
nsn_shm_t *nsn_shm_attach(mem_arena_t *arena, const char *name, usize size);
void       nsn_shm_detach(nsn_shm_t *shm);
int        nsn_shm_release(nsn_shm_t *shm);

static inline void *nsn_shm_rawdata(nsn_shm_t *shm)                 { return shm->data; }
static inline usize nsn_shm_size(nsn_shm_t *shm)                    { return shm->size; }
static inline void *nsn_shm_get_ptr(nsn_shm_t *shm, usize offset)   { return shm->data + offset; }
static inline void *nsn_shm_get_free_ptr(nsn_shm_t *shm)            { return shm->data + shm->used; }

#endif // NSN_SHARED_MEMORY_H