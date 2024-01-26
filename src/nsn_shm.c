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

struct nsn_shm *
nsn_shm_alloc(const char *name, usize size)
{
    struct nsn_shm *result = NULL;

    int fd;
    void *buffer = _nsn_shm_create_with_flags(name, size, O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IRUSR, &fd);
    if (!buffer) {
        goto done;
    }

    result = buffer;
    memory_zero_struct(result);
    strncpy(result->name, name, NSN_SHM_NAME_MAX - 1);
    result->base = buffer;
    result->size = size;
    result->used = sizeof(struct nsn_shm);
    result->fd   = fd;
    at_fadd(&result->ref_count, 1, mo_rlx);
 
done:
    return result;
}

struct nsn_shm *
nsn_shm_attach(const char *name, usize size)
{
    struct nsn_shm *result = NULL;

    int fd;
    void *buffer = _nsn_shm_create_with_flags(name, size, O_RDWR, 0, &fd);
    if (!buffer) {
        goto done;
    }

    result = buffer;
    at_fadd(&result->ref_count, 1, mo_rlx);

done:
    return result;
}

void 
nsn_shm_detach(struct nsn_shm *shm)
{
    if (shm) {
        at_fsub(&shm->ref_count, 1, mo_rlx);
        munmap((void *)shm->base, shm->size);
        close(shm->fd);
    }
}

void 
nsn_shm_release(struct nsn_shm *shm)
{
    struct nsn_shm tmp;
    memcpy(&tmp, shm, sizeof(struct nsn_shm));
    if (shm) {
        munmap((void *)tmp.base, tmp.size);
        shm_unlink(tmp.name);
        close(tmp.fd);
    }
}

