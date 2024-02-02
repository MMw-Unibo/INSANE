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
nsn_shm_t *nsn_shm_attach(mem_arena_t *arena, const char *name, usize size);
void       nsn_shm_detach(nsn_shm_t *shm);
int        nsn_shm_release(nsn_shm_t *shm);

static inline void *nsn_shm_rawdata(nsn_shm_t *shm) { return ((byte *)shm->base) + sizeof(nsn_shm_t); }
static inline usize nsn_shm_size(nsn_shm_t *shm)    { return shm->size - sizeof(nsn_shm_t); }

// --- Shared Memory Page Allocator --------------------------------------------
//  This allocator is used to allocate pages from a shared memory region. It is
//  not thread safe, so it should be used only from a single thread.
//  The allocator is not freeing the pages, it is just keeping track of the
//  allocated pages. The pages are freed when the shared memory is released.
typedef struct nsn_shm_page_allocator nsn_shm_page_allocator_t;
struct nsn_shm_page_allocator
{
    nsn_shm_t *shm;
    usize      page_size;
    usize      page_count;
    usize      page_pos;
};

nsn_shm_page_allocator_t *nsn_shm_page_allocator_from_shm(mem_arena_t *arena, nsn_shm_t *shm, usize page_size);
void nsn_shm_page_allocator_release(nsn_shm_page_allocator_t *allocator);

void *nsn_shm_page_alloc(nsn_shm_page_allocator_t *allocator);
void  nsn_shm_page_free(nsn_shm_page_allocator_t *allocator, void *page);

#endif // NSN_SHARED_MEMORY_H