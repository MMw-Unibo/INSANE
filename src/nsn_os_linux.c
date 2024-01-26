#include "nsn_os.h"

// --- Time --------------------------------------------------------------------
i64 
nsn_os_get_time_ns(void)
{
    struct timespec ts = {0};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (i64)ts.tv_sec * 1000000000 + (i64)ts.tv_nsec;
}

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

// --- File --------------------------------------------------------------------
struct nsn_file
nsn_os_file_open(string8 filename, enum nsn_file_flag flags)
{
    int mode = 0;
    if (flags & NsnFileFlag_Read) {
        mode |= O_RDONLY;
    }
    if (flags & NsnFileFlag_Write) {
        mode |= O_WRONLY;
    }
    if (flags & NsnFileFlag_Create) {
        mode |= O_CREAT;
    }
    if (flags & NsnFileFlag_Truncate) {
        mode |= O_TRUNC;
    }
    if (flags & NsnFileFlag_Append) {
        mode |= O_APPEND;
    }

    struct nsn_file result = {0};
    result.handle = open((const char *)filename.data, mode, 0644);
    return result;
}

bool 
nsn_file_valid(struct nsn_file file)
{
    return file.handle != -1;
}


string8 
nsn_os_read_entire_file(struct mem_arena *arena, struct nsn_file file)
{
    string8 result = {0};

    struct stat file_stat = {0};
    if (fstat(file.handle, &file_stat) == -1) {
        return result;
    }

    result.len  = file_stat.st_size;
    result.data = mem_arena_push_array(arena, u8, result.len);

    if ((usize)read(file.handle, result.data, result.len) != result.len) {
        result.data = NULL;
        result.len  = 0;
    }

    return result;
}
