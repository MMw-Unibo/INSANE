#ifndef NSN_SHARED_MEMORY_H
#define NSN_SHARED_MEMORY_H

#include "nsn_types.h"
#include "nsn_log.h"

#define NSN_SHM_NAME_MAX 32

struct nsn_shm 
{
    char name[NSN_SHM_NAME_MAX];

    struct nsn_shm *base;

    int    fd;
    usize  size;
    usize  used;
    atu32  ref_count;
} nsn_cache_aligned;

struct nsn_shm *nsn_shm_alloc(const char *name, usize size);
struct nsn_shm *nsn_shm_attach(const char *name, usize size);
void nsn_shm_detach(struct nsn_shm *shm);
void nsn_shm_release(struct nsn_shm *shm);

static inline void *nsn_shm_rawdata(struct nsn_shm *shm) { return ((byte *)shm->base) + sizeof(struct nsn_shm); }
static inline usize nsn_shm_size(struct nsn_shm *shm)    { return shm->size - sizeof(struct nsn_shm); }

#endif // NSN_SHARED_MEMORY_H