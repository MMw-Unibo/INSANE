#ifndef NSN_PLATFORM_H
#define NSN_PLATFORM_H

#if defined(__linux__)
# define NSN_OS_LINUX   1
#elif defined(_WIN32) || defined(_WIN64)
# define NSN_OS_WINDOWS 1
#else
# error "Unsupported platform"
#endif

#if defined(__GNUC__)
# define NSN_COMPILER_GCC   1
#elif defined(__clang__)
# define NSN_COMPILER_CLANG 1
#else
# error "Unsupported compiler"
#endif

#if NSN_COMPILER_GCC || NSN_COMPILER_CLANG
# if defined(__x86_64__) || defined(__amd64__)
#  define NSN_ARCH_X86_64   1
# elif defined(__i386__)
#  define NSN_ARCH_X86      1
# else
#  error "Unsupported architecture"
# endif
#else
# error "Unsupported compiler"
#endif

#if NSN_ARCH_X86_64 || NSN_ARCH_X86
# define NSN_CACHE_LINE_SIZE 64
#else
# error "Unsupported architecture"
#endif

#if NSN_COMPILER_GCC || NSN_COMPILER_CLANG
# define nsn_align(x)           __attribute__((aligned(x)))
# define nsn_cache_aligned      nsn_align(NSN_CACHE_LINE_SIZE)
# define nsn_force_inline       __attribute__((always_inline))
# define nsn_no_inline          __attribute__((noinline))
# define nsn_packed             __attribute__((packed))
# define nsn_likely(x)          __builtin_expect(!!(x), 1)
# define nsn_unlikely(x)        __builtin_expect(!!(x), 0)
# define nsn_thread_local       __thread
# define nsn_fallthrough        __attribute__((fallthrough)) 
# if NSN_ARCH_X86_64 || NSN_ARCH_X86
#  define nsn_pause()           __asm__ __volatile__("pause")
# else
#  error "Unsupported architecture"
# endif
#else
# error "Unsupported compiler"
#endif

#endif // NSN_PLATFORM_H