#ifndef NSN_ARENA_H
#define NSN_ARENA_H

#include "nsn_types.h"

typedef struct nsn_arena nsn_arena;
struct nsn_arena {
    struct nsn_arena *base;

    usize size;
    usize pos;
    usize com_pos;
    usize align;
} nsn_cache_aligned;

#define NSN_ARENA_DEFAULT_ALIGNEMENT            sizeof(void *)
#define NSN_ARENA_DEFAULT_GRANULARITY           megabytes(1)    // 
#define NSN_ARENA_DEFAULT_SIZE                  gigabytes(8)
#define NSN_ARENA_DEFAULT_COMMIT_GRANULARITY    kilobytes(4)    // Page size

struct nsn_arena *nsn_arena_alloc_with_alignement(usize size, usize align);
#define nsn_arena_alloc(size)       nsn_arena_alloc_with_alignement(size, NSN_ARENA_DEFAULT_ALIGNEMENT)
#define nsn_arena_alloc_default()   nsn_arena_alloc(NSN_ARENA_DEFAULT_SIZE)
void nsn_arena_release(struct nsn_arena *arena);

void *nsn_arena_push_no_zero(struct nsn_arena *arena, usize size);
void *nsn_arena_push(struct nsn_arena *arena, usize size);
void  nsn_arena_pop(struct nsn_arena *arena, usize size);
void  nsn_arena_clear(struct nsn_arena *arena);
void  nsn_arena_set_pos(struct nsn_arena *arena, usize pos);

void print_arena(struct nsn_arena *arena);

#define nsn_arena_push_struct_no_zero(arena, type)          (type *)nsn_arena_push_no_zero(arena, sizeof(type))
#define nsn_arena_push_struct(arena, type)                  (type *)nsn_arena_push(arena, sizeof(type))
#define nsn_arena_push_array_no_zero(arena, type, count)    (type *)nsn_arena_push_no_zero(arena, sizeof(type) * (count))
#define nsn_arena_push_array(arena, type, count)            (type *)nsn_arena_push(arena, sizeof(type) * (count))

struct nsn_temp_arena {
    struct nsn_arena *arena;
    usize pos;
};

static inline struct nsn_temp_arena nsn_temp_arena_begin(struct nsn_arena *arena)  { struct nsn_temp_arena temp; temp.arena = arena; temp.pos = arena->pos; return temp; }
static inline void                  nsn_temp_arena_end(struct nsn_temp_arena temp) { temp.arena->pos = temp.pos; }

#endif // NSN_ARENA_H