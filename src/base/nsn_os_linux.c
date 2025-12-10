#include "nsn_os.h"

// --- Time --------------------------------------------------------------------
u64 
nsn_os_get_cycles(void)
{
    u64 hi, low;
    __asm__ __volatile__ ("rdtsc" : "=a"(low), "=d"(hi));
    return (hi << 32) | low;
}

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
        // RTLD_NOW: Resolve all symbols at load time.
        // RTLD_GLOBAL: Symbols are available for relocation processing of other modules.
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

size_t nsn_os_default_page_size(void)
{
    return sysconf(_SC_PAGESIZE);
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

    if (pthread_create(&thread.handle, 0, proc, arg) != 0) {
        thread = NSN_OS_INVALID_THREAD_HANDLE;
    }

    return thread;
}

int
nsn_os_thread_join(struct nsn_os_thread thread)
{
    return pthread_join(thread.handle, 0);
}

struct nsn_os_thread
nsn_os_get_current_thread(void)
{
    struct nsn_os_thread thread = {
        .handle = pthread_self()
    };

    return thread;
}

int 
nsn_os_current_thread_id(void)
{
    return gettid();
}

int
nsn_os_mutex_init(struct nsn_mutex *mutex)
{
    return pthread_mutex_init(&mutex->handle, 0);    
}

void
nsn_os_mutex_lock(struct nsn_mutex *mutex)
{
    pthread_mutex_lock(&mutex->handle);
}

void
nsn_os_mutex_unlock(struct nsn_mutex *mutex)
{
    pthread_mutex_unlock(&mutex->handle);
}

int
nsn_os_cnd_init(struct nsn_cnd *cv)
{
    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
    int result = pthread_cond_init(&cv->handle, &attr);
    pthread_condattr_destroy(&attr);
    return result;
}

int
nsn_os_cnd_destroy(struct nsn_cnd *cv)
{
    return pthread_cond_destroy(&cv->handle);
}

int
nsn_os_cnd_wait(struct nsn_cnd *cv, struct nsn_mutex *mutex)
{
    return pthread_cond_wait(&cv->handle, &mutex->handle);
}

int
nsn_os_cnd_signal(struct nsn_cnd *cv)
{
    return pthread_cond_signal(&cv->handle);
}

// --- File --------------------------------------------------------------------
nsn_file_t
nsn_os_file_open(string_t filename, enum nsn_file_flag flags)
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

    nsn_file_t result = {0};
    result.handle = open((const char *)filename.data, mode, 0644);
    return result;
}

bool 
nsn_file_valid(nsn_file_t file)
{
    return file.handle != -1;
}

string_t 
nsn_os_read_entire_pseudofile(mem_arena_t *arena, nsn_file_t file)
{
    // a pseudofile is a file that is not a real file, but a file-like interface to a kernel subsystem
    // for example /proc/cpuinfo, /proc/meminfo, /proc/self/maps, etc.

    char buffer[4096];
    bool is_first = true;
    u8 *start     = NULL;
    usize len     = 0;
    while (true) {
        ssize_t bytes_read = read(file.handle, buffer, sizeof(buffer));
        if (bytes_read == -1) {
            log_error("Failed to read pseudofile: %s", strerror(errno));
            return (string_t){0};
        }
        if (bytes_read == 0) {
            break;
        }

        if (is_first) {
            start   = mem_arena_push_array(arena, u8, bytes_read);
            is_first = false;
        } else {
            start = mem_arena_push_array(arena, u8, len + bytes_read);
        }

        memory_copy(start, buffer, bytes_read);
        len += bytes_read;        
    }

    return (string_t){ start, len };
}

string_t
nsn_os_read_entire_file(mem_arena_t *arena, nsn_file_t file)
{
    string_t result = {0};

    struct stat file_stat = {0};
    if (fstat(file.handle, &file_stat) == -1) {
        log_error("Failed to get file stat: %s", strerror(errno));
        return result;
    }

    // log_debug("Reading file: %s, size: %ld", file_stat.st_size, file_stat.st_size);

    result.len  = file_stat.st_size;
    result.data = mem_arena_push_array(arena, u8, result.len);

    if ((usize)read(file.handle, result.data, result.len) != result.len) {
        log_error("Failed to read file: %s", strerror(errno));
        result.data = NULL;
        result.len  = 0;
    }

    return result;
}

void       
nsn_os_file_close(nsn_file_t file)
{
    close(file.handle);
}

void
nsn_os_file_delete(string_t filename)
{
    unlink(to_cstr(filename));
}