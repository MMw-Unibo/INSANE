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

mem_arena_t *
mem_arena_alloc_with_alignement(usize size, usize align)
{
    usize aligned_size = align_to(size, MEM_ARENA_DEFAULT_GRANULARITY);
    printf("aligned_size: %zu\n", aligned_size);
    
    void *base = arena_impl_reserve(aligned_size, NsnOsMemoryFlag_Anonymous | NsnOsMemoryFlag_Private);
    assert(base && "Failed to allocate memory");
    assert(MEM_ARENA_DEFAULT_COMMIT_GRANULARITY >= sizeof(mem_arena_t) && "Commit granularity must be greater than the size of the arena header");
    nsn_os_commit_memory(base, MEM_ARENA_DEFAULT_COMMIT_GRANULARITY);

    mem_arena_t *arena = base;
    arena->base    = base;
    arena->size    = aligned_size;
    arena->pos     = sizeof(mem_arena_t);
    arena->com_pos = MEM_ARENA_DEFAULT_COMMIT_GRANULARITY;
    arena->align   = align;

    return arena;
}

void 
mem_arena_release(mem_arena_t *arena)
{
    arena_impl_release(arena->base, arena->size);
}

void *
mem_arena_push_no_zero(mem_arena_t *arena, usize size)
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
            commit_size       = align_to(commit_size, MEM_ARENA_DEFAULT_COMMIT_GRANULARITY);
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
mem_arena_push(mem_arena_t *arena, usize size)
{
    void *ptr = mem_arena_push_no_zero(arena, size);
    memory_zero(ptr, size);
    return ptr;
}

void 
mem_arena_pop(mem_arena_t *arena, usize size)
{
    arena->pos -= size;
}

void
mem_arena_clear(mem_arena_t *arena)
{
    arena->pos = sizeof(mem_arena_t);
}

void
mem_arena_set_pos(mem_arena_t *arena, usize pos)
{
    arena->pos = pos;
}

void
print_arena(mem_arena_t *arena)
{
    printf("arena->base:    %p\n", (void *)arena->base);
    printf("arena->size:    %zu\n", arena->size);
    printf("arena->pos:     %zu\n", arena->pos);
    printf("arena->com_pos: %zu\n", arena->com_pos);
    printf("arena->align:   %zu\n", arena->align);
}

// --- Fixed Size Memory Arena -------------------------------------------------
fixed_mem_arena_t *
fixed_mem_arena_alloc_with_alignement(void *memory, usize size, usize align)
{
    void *base = memory;
    assert(base && "Failed to allocate memory");

    fixed_mem_arena_t *arena = base;
    arena->base  = base;
    arena->size  = size;
    arena->pos   = sizeof(fixed_mem_arena_t);
    arena->align = align;

    return arena;
}

void *
fixed_mem_arena_push_no_zero(fixed_mem_arena_t *arena, usize size)
{
    void *ptr = NULL;
    byte *base            = (byte *)arena->base;
    usize post_align_pos  = align_to(arena->pos, arena->align);
    assert(post_align_pos + size <= arena->size && "Not enough space in the fixed memory arena");

    ptr        = base + post_align_pos;
    arena->pos = post_align_pos + size;

    return ptr;
}

void *
fixed_mem_arena_push(fixed_mem_arena_t *arena, usize size)
{
    void *ptr = fixed_mem_arena_push_no_zero(arena, size);
    memory_zero(ptr, size);
    return ptr;
}

void
fixed_mem_arena_pop(fixed_mem_arena_t *arena, usize size)
{
    arena->pos -= size;
}

void
fixed_mem_arena_clear(fixed_mem_arena_t *arena)
{
    arena->pos = sizeof(fixed_mem_arena_t);
}

void 
fixed_mem_arena_set_pos(fixed_mem_arena_t *arena, usize pos)
{
    arena->pos = pos;
}
