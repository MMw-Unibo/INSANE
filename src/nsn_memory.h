#ifndef NSN_MEMORY_H
#define NSN_MEMORY_H

#include "nsn_types.h"

typedef struct mem_arena mem_arena;
struct mem_arena {
    mem_arena *base;

    usize size;
    usize pos;
    usize com_pos;
    usize align;
} nsn_cache_aligned;

#define NSN_ARENA_DEFAULT_ALIGNEMENT            sizeof(void *)
#define NSN_ARENA_DEFAULT_GRANULARITY           megabytes(1)    // 
#define NSN_ARENA_DEFAULT_SIZE                  gigabytes(8)
#define NSN_ARENA_DEFAULT_COMMIT_GRANULARITY    kilobytes(4)    // Page size

mem_arena *mem_arena_alloc_with_alignement(usize size, usize align);
#define mem_arena_alloc(size)       mem_arena_alloc_with_alignement(size, NSN_ARENA_DEFAULT_ALIGNEMENT)
#define mem_arena_alloc_default()   mem_arena_alloc(NSN_ARENA_DEFAULT_SIZE)
void mem_arena_release(mem_arena *arena);

void *mem_arena_push_no_zero(mem_arena *arena, usize size);
void *mem_arena_push(mem_arena *arena, usize size);
void  mem_arena_pop(mem_arena *arena, usize size);
void  mem_arena_clear(mem_arena *arena);
void  mem_arena_set_pos(mem_arena *arena, usize pos);

void print_arena(mem_arena *arena);

#define mem_arena_push_struct_no_zero(arena, type)          (type *)mem_arena_push_no_zero(arena, sizeof(type))
#define mem_arena_push_struct(arena, type)                  (type *)mem_arena_push(arena, sizeof(type))
#define mem_arena_push_array_no_zero(arena, type, count)    (type *)mem_arena_push_no_zero(arena, sizeof(type) * (count))
#define mem_arena_push_array(arena, type, count)            (type *)mem_arena_push(arena, sizeof(type) * (count))

typedef struct temp_mem_arena temp_mem_arena;
struct temp_mem_arena {
    struct mem_arena *arena;
    usize pos;
};

static inline temp_mem_arena temp_mem_arena_begin(mem_arena *arena)  { temp_mem_arena temp; temp.arena = arena; temp.pos = arena->pos; return temp; }
static inline void           temp_mem_arena_end(temp_mem_arena temp) { temp.arena->pos = temp.pos; }

#endif // NSN_MEMORY_H