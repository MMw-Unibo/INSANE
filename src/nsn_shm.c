#include "nsn_shm.h"

static void *
_nsn_shm_create_with_flags(const char *name, usize size, int flags, int mode, int *out_fd)
{
    usize len = strlen(name);
    if (len >= NSN_SHM_NAME_MAX) {
        return NULL;
    }

    // TODO: use OS layer
    int shm_fd = shm_open(name, flags, mode);
    if (shm_fd == -1) {
        log_error("shm_open() failed to create mem '%s': %s\n", name, strerror(errno));
        return NULL;
    }

    if (ftruncate(shm_fd, size) == -1) {
        goto error;
    }

    void *buffer = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (!buffer) {
        goto error;
    }

    *out_fd = shm_fd;
    return buffer;

error:
    shm_unlink(name);
    return NULL;
}

nsn_shm_t *
nsn_shm_alloc(mem_arena_t *arena, const char *name, usize size)
{
    nsn_shm_t *shm = NULL;

    int fd;
    void *buffer = _nsn_shm_create_with_flags(name, size, O_CREAT | O_EXCL | O_RDWR, S_IRUSR, &fd);
    if (!buffer) {
        goto done;
    }

    shm = mem_arena_push_struct(arena, nsn_shm_t);
    strncpy(shm->name, name, NSN_SHM_NAME_MAX - 1);
    shm->base = buffer;
    shm->size = size;
    shm->fd   = fd;
    at_fadd(&shm->ref_count, 1, mo_rlx);
 
done:
    return shm;
}

nsn_shm_t *
nsn_shm_attach(mem_arena_t *arena, const char *name, usize size)
{
    nsn_shm_t *shm = NULL;

    int fd;
    void *buffer = _nsn_shm_create_with_flags(name, size, O_RDWR, 0, &fd);
    if (!buffer) {
        goto done;
    }

    shm = mem_arena_push_struct(arena, nsn_shm_t);
    shm->base = buffer;
    shm->size = size;
    shm->fd   = fd;
    strncpy(shm->name, name, NSN_SHM_NAME_MAX - 1);
    at_fadd(&shm->ref_count, 1, mo_rlx);

done:
    return shm;
}

void 
nsn_shm_detach(nsn_shm_t *shm)
{
    if (shm) {
        at_fsub(&shm->ref_count, 1, mo_rlx);
        munmap((void *)shm->base, shm->size);
        close(shm->fd);
    }
}

int
nsn_shm_release(nsn_shm_t *shm)
{
    if (shm) {
        nsn_shm_t tmp;
        memcpy(&tmp, shm, sizeof(nsn_shm_t));
        if (at_fsub(&shm->ref_count, 1, mo_rlx) == 0) {
            munmap((void *)shm->base, shm->size);
            shm_unlink(shm->name);
            close(shm->fd);
            return 0;
        }
    } 

    return -1;
}

// --- Shared Memory Page Allocator --------------------------------------------

nsn_shm_page_allocator_t *
nsn_shm_page_allocator_from_shm(mem_arena_t *arena, nsn_shm_t *shm, usize page_size)
{
    nsn_shm_page_allocator_t *allocator = mem_arena_push_struct(arena, nsn_shm_page_allocator_t);
    allocator->shm        = shm;
    allocator->page_size  = page_size;
    allocator->page_count = nsn_shm_size(shm) / page_size;
    allocator->page_pos   = 0;

    return allocator;
}

void 
nsn_shm_page_allocator_release(nsn_shm_page_allocator_t *allocator)
{
    // TODO: implement
    nsn_unused(allocator);
}

void 
*nsn_shm_page_alloc(nsn_shm_page_allocator_t *allocator)
{
    nsn_unused(allocator);    
    return NULL;
}

void  nsn_shm_page_free(nsn_shm_page_allocator_t *allocator, void *page)
{
    nsn_unused(allocator);
    nsn_unused(page);
}