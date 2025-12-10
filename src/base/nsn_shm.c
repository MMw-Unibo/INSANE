#include "nsn_shm.h"

static void *
_nsn_shm_create_with_flags(const char *name, usize size, int flags, int mode, int *out_fd)
{
    usize len = strlen(name);
    if (len >= NSN_SHM_NAME_MAX) {
        return NULL;
    }

    // TODO: use OS layer
    // int shm_fd = shm_open(name, flags, mode);

    char fullpath[128];
    snprintf(fullpath, sizeof(fullpath), "%s/%s", NSN_HUGETLBFS_PATH, name);

    int shm_fd = open(fullpath, flags, mode);
    if (shm_fd == -1) {
        log_error("shm_open() failed to create mem '%s': %s\n", name, strerror(errno));
        return NULL;
    }

    if (ftruncate(shm_fd, size) == -1) {
        log_error("ftruncate() failed to create mem '%s': %s\n", name, strerror(errno));
        goto error;
    }

    // Set the MAP_HUGETLB flag to use 2MB huge pages
    void *buffer = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED | MAP_HUGETLB, shm_fd, 0);
    // void *buffer = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (!buffer) {
        log_error("mmap() failed to create mem '%s': %s\n", name, strerror(errno));
        goto error;
    }

    *out_fd = shm_fd;
    return buffer;

error:
    close(shm_fd);
    shm_unlink(fullpath);
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
    shm->data = buffer;
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
    shm->data = buffer;
    shm->size = size;
    shm->fd   = fd;
    strcpy(shm->name, name);
    at_fadd(&shm->ref_count, 1, mo_rlx);

done:
    return shm;
}

void 
nsn_shm_detach(nsn_shm_t *shm)
{
    if (shm) {
        at_fsub(&shm->ref_count, 1, mo_rlx);
        munmap((void *)shm->data, shm->size);
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
            munmap((void *)shm->data, shm->size);
            // shm_unlink(shm->name);
            close(shm->fd);

            // remove the file
            char fullpath[128];
            snprintf(fullpath, sizeof(fullpath), "%s/%s", NSN_HUGETLBFS_PATH, shm->name);
            unlink(fullpath);
            return 0;
        }
    } 

    return -1;
}