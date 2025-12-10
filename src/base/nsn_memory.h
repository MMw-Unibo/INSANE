#ifndef NSN_MEMORY_H
#define NSN_MEMORY_H

#include "nsn_types.h"

// --- Memory Arena ------------------------------------------------------------

typedef struct mem_arena mem_arena_t;
struct mem_arena {
    mem_arena_t *base;

    usize   size;
    usize   pos;
    usize   com_pos;
    usize   align;
} nsn_cache_aligned;

#define MEM_ARENA_DEFAULT_ALIGNEMENT            sizeof(void *)
#define MEM_ARENA_DEFAULT_GRANULARITY           megabytes(1)    // 
#define MEM_ARENA_DEFAULT_SIZE                  gigabytes(8)
#define MEM_ARENA_DEFAULT_COMMIT_GRANULARITY    kilobytes(4)    // Page size

#define NSN_HUGETLBFS_PATH "/dev/hugepages"

mem_arena_t *mem_arena_alloc_with_alignement(usize size, usize align);
#define mem_arena_alloc(size)       mem_arena_alloc_with_alignement(size, MEM_ARENA_DEFAULT_ALIGNEMENT)
#define mem_arena_alloc_default()   mem_arena_alloc(MEM_ARENA_DEFAULT_SIZE)
void mem_arena_release(mem_arena_t *arena);

void *mem_arena_push_no_zero(mem_arena_t *arena, usize size);
void *mem_arena_push(mem_arena_t *arena, usize size);
void  mem_arena_pop(mem_arena_t *arena, usize size);
void  mem_arena_clear(mem_arena_t *arena);
void  mem_arena_set_pos(mem_arena_t *arena, usize pos);

void print_arena(mem_arena_t *arena);

#define mem_arena_push_struct_no_zero(arena, type)          (type *)mem_arena_push_no_zero(arena, sizeof(type))
#define mem_arena_push_struct(arena, type)                  (type *)mem_arena_push(arena, sizeof(type))
#define mem_arena_push_array_no_zero(arena, type, count)    (type *)mem_arena_push_no_zero(arena, sizeof(type) * (count))
#define mem_arena_push_array(arena, type, count)            (type *)mem_arena_push(arena, sizeof(type) * (count))

// --- Temp Memory Arena 

typedef struct temp_mem_arena temp_mem_arena_t;
struct temp_mem_arena {
    mem_arena_t *arena;
    usize        pos;
};

static inline temp_mem_arena_t temp_mem_arena_begin(mem_arena_t *arena)  { temp_mem_arena_t temp; temp.arena = arena; temp.pos = arena->pos; return temp; }
static inline void             temp_mem_arena_end(temp_mem_arena_t temp) { temp.arena->pos = temp.pos; }

// --- Fixed Size Memory Arena -------------------------------------------------
//  In the fixed size memory arena, the arena is not owining the memory, it is 
//  just a wrapper around it, thus it cannot grow or shrink and it cannot be
//  released.
typedef struct fixed_mem_arena fixed_mem_arena_t;
struct fixed_mem_arena {
    fixed_mem_arena_t *base;

    usize size;
    usize pos;
    usize align;
} nsn_cache_aligned;

fixed_mem_arena_t *fixed_mem_arena_alloc_with_alignement(void *memory, usize size, usize align);
#define fixed_mem_arena_alloc(memory, size)       fixed_mem_arena_alloc_with_alignement(memory, size, MEM_ARENA_DEFAULT_ALIGNEMENT)

void *fixed_mem_arena_push_no_zero(fixed_mem_arena_t *arena, usize size);
void *fixed_mem_arena_push(fixed_mem_arena_t *arena, usize size);
void  fixed_mem_arena_pop(fixed_mem_arena_t *arena, usize size);
void  fixed_mem_arena_clear(fixed_mem_arena_t *arena);
void  fixed_mem_arena_set_pos(fixed_mem_arena_t *arena, usize pos);

#define fixed_mem_arena_push_struct_no_zero(arena, type)          (type *)fixed_mem_arena_push_no_zero(arena, sizeof(type))
#define fixed_mem_arena_push_struct(arena, type)                  (type *)fixed_mem_arena_push(arena, sizeof(type))
#define fixed_mem_arena_push_array_no_zero(arena, type, count)    (type *)fixed_mem_arena_push_no_zero(arena, sizeof(type) * (count))
#define fixed_mem_arena_push_array(arena, type, count)            (type *)fixed_mem_arena_push(arena, sizeof(type) * (count))

#endif // NSN_MEMORY_H