#ifndef NSN_OS_H
#define NSN_OS_H

#include "nsn_memory.h"
#include "nsn_string.h"
#include "nsn_types.h"

// --- Time --------------------------------------------------------------------
u64 nsn_os_get_cycles(void);
i64 nsn_os_get_time_ns(void);

// --- Library -----------------------------------------------------------------
struct nsn_os_module
{
#if NSN_OS_LINUX
    void *handle;
#else
# error "Unsupported operating system"
#endif
};

enum nsn_os_library_flag {
    NsnOsLibraryFlag_None = 0,
    NsnOsLibraryFlag_Lazy = 1 << 0,
    NsnOsLibraryFlag_Now  = 1 << 1,
};

struct nsn_os_module nsn_os_load_library(const char *path, int flags);
void *nsn_os_get_proc_address(struct nsn_os_module, const char *name);
void nsn_os_unload_library(struct nsn_os_module module);

// --- Memory ------------------------------------------------------------------

enum nsn_os_memory_flag {
    /// @brief Share this mapping.  Updates to the mapping are visible to other 
    /// processes mapping the same region.
    NsnOsMemoryFlag_Shared = 1 << 0,
    /// @brief The mapping is private (copy-on-write) and changes are not 
    /// visible to other processes mapping the same region.
    NsnOsMemoryFlag_Private = 1 << 1,
    /// @brief The mapping is not backed by any file.
    NsnOsMemoryFlag_Anonymous = 1 << 3,
    /// @brief The mapping should be made using "huge pages".
    NsnOsMemoryFlag_HugePage = 1 << 4,
};

void *nsn_os_allocate_memory(usize size, int flags);
void *nsn_os_reserve_memory(usize size, int flags);
void  nsn_os_commit_memory(void *address, usize size);
void  nsn_os_decommit_memory(void *address, usize size);
void  nsn_os_release_memory(void *address, usize size);

// --- Process -----------------------------------------------------------------

int nsn_os_get_process_id(void);

// --- Thread ------------------------------------------------------------------

typedef struct nsn_os_thread nsn_os_thread_t;
struct nsn_os_thread
{
#if NSN_OS_LINUX
    pthread_t handle;
#else
# error "Unsupported operating system"
#endif
};

typedef void *(*nsn_os_thread_proc)(void *arg);

#define NSN_OS_INVALID_THREAD_HANDLE ((struct nsn_os_thread){0})

struct nsn_os_thread nsn_os_thread_create(nsn_os_thread_proc proc, void *arg);
int nsn_os_thread_join(struct nsn_os_thread thread);
struct nsn_os_thread nsn_os_get_current_thread(void);
int nsn_os_current_thread_id(void);

typedef struct nsn_mutex nsn_mutex_t;
struct nsn_mutex
{
#if NSN_OS_LINUX
    pthread_mutex_t     handle;
#elif NSN_OS_WINDOWS
    CRITICAL_SECTION    handle;
#else
# error "Unsupported operating system"
#endif
};

// #define NSN_OS_INVALID_MUTEX_HANDLE ((struct nsn_mutex){0})

#if NSN_OS_LINUX
# define NSN_OS_MUTEX_INITIALIZER ((struct nsn_mutex){.handle = PTHREAD_MUTEX_INITIALIZER})
#elif NSN_OS_WINDOWS
# define NSN_OS_MUTEX_INITIALIZER ((struct nsn_mutex){0})
#else
# error "Unsupported operating system"
#endif

int  nsn_os_mutex_init(struct nsn_mutex *mutex);
void nsn_os_mutex_lock(struct nsn_mutex *mutex);
void nsn_os_mutex_unlock(struct nsn_mutex *mutex);

struct nsn_conditional_variable
{
#if NSN_OS_LINUX
    pthread_cond_t handle;
#else
# error "Unsupported operating system"
#endif
};

// #define NSN_OS_INVALID_CONDITIONAL_VARIABLE_HANDLE ((struct nsn_conditional_variable){0})

int nsn_os_conditional_variable_create(struct nsn_conditional_variable *cv);

// --- File --------------------------------------------------------------------

typedef struct nsn_file nsn_file_t;
struct nsn_file
{
#if NSN_OS_LINUX
    int handle;
#else
# error "Unsupported operating system"
#endif
};

enum nsn_file_flag {
    NsnFileFlag_None     = 0,
    NsnFileFlag_Read     = 1 << 0,
    NsnFileFlag_Write    = 1 << 1,
    NsnFileFlag_Create   = 1 << 2,
    NsnFileFlag_Truncate = 1 << 3,
    NsnFileFlag_Append   = 1 << 4,
};

nsn_file_t nsn_os_file_open(string_t filename, enum nsn_file_flag flags);
bool       nsn_file_valid(nsn_file_t file);
string_t   nsn_os_read_entire_file(mem_arena_t *arena, nsn_file_t file);
void       nsn_os_file_close(nsn_file_t file);

#endif // NSN_OS_H