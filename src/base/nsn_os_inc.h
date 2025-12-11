#ifndef NSN_OS_INC_H
#define NSN_OS_INC_H

#if !defined(arena_impl_reserve)
# define arena_impl_reserve  nsn_os_reserve_memory
#endif
#if !defined(arena_impl_release)
# define arena_impl_release  nsn_os_release_memory
#endif
#if !defined(arena_impl_commit)
# define arena_impl_commit   nsn_os_commit_memory
#endif

#include "nsn_os.h"

#if NSN_OS_LINUX
#else
# error "Unsupported operating system"
#endif

#endif // NSN_OS_INC_H