#include "nsn_os.h"

// --- Library -----------------------------------------------------------------

struct nsn_os_module
nsn_os_load_library(const char *path, int flags)
{
    int mode = NsnOsLibraryFlag_Lazy;
    if (flags & NsnOsLibraryFlag_Now) {
        mode = RTLD_NOW;
    }

    struct nsn_os_module result = {0};
    result.handle = dlopen(path, mode);
    return result;
}

void *nsn_os_get_proc_address(struct nsn_os_module module, const char *name)
{
    return dlsym(module.handle, name);
}

void nsn_os_unload_library(struct nsn_os_module module)
{
    dlclose(module.handle);
}

// --- Memory ------------------------------------------------------------------

void *
nsn_os_allocate_memory(usize size, int flags)
{
    void *ptr = nsn_os_reserve_memory(size, flags);
    if (ptr) {
        nsn_os_commit_memory(ptr, size);
    }
    return ptr;   
}

void *
nsn_os_reserve_memory(usize size, int flags)
{
    int mmap_flags = 0;
    if (flags & NsnOsMemoryFlag_Shared) {
        mmap_flags |= MAP_SHARED;
    } 
    if (flags & NsnOsMemoryFlag_Private) {
        mmap_flags |= MAP_PRIVATE;
    }
    if (flags & NsnOsMemoryFlag_Anonymous) {
        mmap_flags |= MAP_ANONYMOUS;
    }
    if (flags & NsnOsMemoryFlag_HugePage) {
        mmap_flags |= MAP_HUGETLB;
    }

    void *ptr = mmap(0, size, PROT_READ | PROT_WRITE,  mmap_flags, -1, 0);
    return ptr;
}

void 
nsn_os_commit_memory(void *address, usize size)
{
    mprotect(address, size, PROT_READ | PROT_WRITE);
}

void nsn_os_decommit_memory(void *address, usize size)
{
    mprotect(address, size, PROT_NONE);
}

void nsn_os_release_memory(void *address, usize size)
{
    munmap(address, size);
}

// --- Process -----------------------------------------------------------------

int 
nsn_os_get_process_id(void)
{
    return getpid();
}

// --- Thread ------------------------------------------------------------------

struct nsn_os_thread 
nsn_os_thread_create(nsn_os_thread_proc proc, void *arg)
{
    struct nsn_os_thread thread;
    memory_zero_struct(&thread);

    if (pthread_create(&thread.handle, 0, proc, arg) == 0) {
        thread = NSN_OS_INVALID_THREAD_HANDLE;
    }

    return thread;
}

int
nsn_os_mutex_init(struct nsn_mutex *mutex)
{
    return pthread_mutex_init(&mutex->handle, 0);    
}

int
nsn_os_conditional_variable_init(struct nsn_conditional_variable *cv)
{
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
    int result = pthread_cond_init(&cv->handle, &attr);
    pthread_condattr_destroy(&attr);
    return result;
}
