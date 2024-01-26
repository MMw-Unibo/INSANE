#include "nsn_memory.h"
#include "nsn_os_inc.h"

#if !defined(arena_impl_reserve)
#error arena_impl_reserve must be defined to use base memory.
#endif
#if !defined(arena_impl_release)
#error arena_impl_release must be defined to use base memory.
#endif
#if !defined(arena_impl_commit)
#error arena_impl_commit must be defined to use base memory.
#endif

struct mem_arena *
mem_arena_alloc_with_alignement(usize size, usize align)
{
    usize aligned_size = align_to(size, NSN_ARENA_DEFAULT_GRANULARITY);
    printf("aligned_size: %zu\n", aligned_size);
    
    void *base = arena_impl_reserve(aligned_size, NsnOsMemoryFlag_Anonymous | NsnOsMemoryFlag_Private);
    assert(base && "Failed to allocate memory");
    assert(NSN_ARENA_DEFAULT_COMMIT_GRANULARITY >= sizeof(struct mem_arena) && "Commit granularity must be greater than the size of the arena header");
    nsn_os_commit_memory(base, NSN_ARENA_DEFAULT_COMMIT_GRANULARITY);

    struct mem_arena *arena = base;
    arena->base    = base;
    arena->size    = aligned_size;
    arena->pos     = sizeof(struct mem_arena);
    arena->com_pos = NSN_ARENA_DEFAULT_COMMIT_GRANULARITY;
    arena->align   = align;

    return arena;
}

void 
mem_arena_release(struct mem_arena *arena)
{
    arena_impl_release(arena->base, arena->size);
}

void *
mem_arena_push_no_zero(struct mem_arena *arena, usize size)
{
    void *ptr = NULL;
    // calculate the aligned position
    byte *base            = (byte *)arena->base;
    usize post_align_pos  = align_to(arena->pos, arena->align);
    // usize alignement_size = post_align_pos - arena->pos;
    if (post_align_pos + size <= arena->size)
    {
        ptr        = base + post_align_pos;
        arena->pos = post_align_pos + size;
        if (arena->pos > arena->com_pos)
        {
            // align the size to commit to a multiple of the granularity
            usize commit_size = arena->pos - arena->com_pos;
            commit_size       = align_to(commit_size, NSN_ARENA_DEFAULT_COMMIT_GRANULARITY);
            arena_impl_commit(base + arena->com_pos, commit_size);
            arena->com_pos   += commit_size;
        }
    }
    else
    {
        assert(0 && "Not implemented");
    }

    return ptr;
}

void *
mem_arena_push(struct mem_arena *arena, usize size)
{
    void *ptr = mem_arena_push_no_zero(arena, size);
    memory_zero(ptr, size);
    return ptr;
}

void 
mem_arena_pop(struct mem_arena *arena, usize size)
{
    arena->pos -= size;
}

void
mem_arena_clear(struct mem_arena *arena)
{
    arena->pos = sizeof(struct mem_arena);
}

void
mem_arena_set_pos(struct mem_arena *arena, usize pos)
{
    arena->pos = pos;
}

void
print_arena(struct mem_arena *arena)
{
    printf("arena->base:    %p\n", (void *)arena->base);
    printf("arena->size:    %zu\n", arena->size);
    printf("arena->pos:     %zu\n", arena->pos);
    printf("arena->com_pos: %zu\n", arena->com_pos);
    printf("arena->align:   %zu\n", arena->align);
}