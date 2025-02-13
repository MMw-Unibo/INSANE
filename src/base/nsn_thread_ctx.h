#ifndef NSN_THREAD_CTX_H
#define NSN_THREAD_CTX_H

#include "nsn_types.h"
#include "nsn_memory.h"

typedef struct nsn_thread_ctx nsn_thread_ctx_t;
struct nsn_thread_ctx {
    bool         is_main_thread;
    mem_arena_t *scratch_arenas[2];
};

nsn_thread_local nsn_thread_ctx_t *nsn_tctx = NULL;

nsn_thread_ctx_t
nsn_thread_ctx_alloc()
{
    nsn_thread_ctx_t ctx;
    memory_zero_struct(&ctx);
    for (usize i = 0; i < array_count(ctx.scratch_arenas); ++i)
        ctx.scratch_arenas[i] = mem_arena_alloc(gigabytes(2));
 
    return ctx;
}

void
nsn_thread_ctx_release(nsn_thread_ctx_t *ctx)
{
    for (usize i = 0; i < array_count(ctx->scratch_arenas); ++i)
        mem_arena_release(ctx->scratch_arenas[i]);
}

void
nsn_thread_set_ctx(nsn_thread_ctx_t *ctx)
{
    nsn_tctx = ctx;
}

nsn_thread_ctx_t *
nsn_thread_ctx_get()
{
    return nsn_tctx;
}

temp_mem_arena_t
nsn_thread_scratch_begin(mem_arena_t **conflics, usize count)
{
    nsn_thread_ctx_t *ctx = nsn_thread_ctx_get();
    temp_mem_arena_t scratch;
    memory_zero_struct(&scratch);
    for (usize i = 1; i < array_count(ctx->scratch_arenas); ++i) {
        bool conflict_found = false;
        for (usize j = 0; j < count; ++j) {
            if (ctx->scratch_arenas[i] == conflics[j]) {
                conflict_found = true;
                break;
            }
        }
        if (!conflict_found) {
            scratch.arena = ctx->scratch_arenas[i];
            scratch.pos   = scratch.arena->pos;
            break;
        }
    }

    return scratch;
}

#define nsn_thread_scratch_end(scratch)     temp_mem_arena_end(scratch)

#endif // NSN_THREAD_CTX_H