#include "nsn_app_inner.h"

bool 
app_pool_init_slot(
    nsn_app_pool_t *pool, int app_slot, 
    nsn_mem_manager_cfg_t* mem_cfg
) {
    if (app_slot < 0) {
        return false;
    }
    // TODO: maybe restrict the access permissions to those two processes with mprotect?)
    nsn_app_t *app = &pool->apps[app_slot];
    app->arena     = mem_arena_alloc(megabytes(500));
    if (!app->arena) {
        log_error("Failed to create memory arena for app %d\n", app->app_id);
        return false;
    }

    log_debug("Created memory arena for app %d at %p\n base %u (%p)\n pos %u\n com_pos %u\n", 
              app->app_id, app->arena, app->arena->base, 
              (char*)app->arena->base, app->arena->pos, app->arena->com_pos);

    char shm_name_app[NSN_SHM_NAME_MAX];
    snprintf(shm_name_app, NSN_SHM_NAME_MAX, "%s_%d", mem_cfg->shm_name.data, app->app_id);
    mem_cfg->shm_name = str_lit(shm_name_app);

    app->mem = nsn_memory_manager_create(app->arena, mem_cfg);
    if (!app->mem) {
        log_error("Failed to create shared memory for app \n");
        return false;
    }

    return true;
}

int 
app_pool_try_alloc_slot(nsn_app_pool_t *pool, int app_id)
{
    for (usize i = 0; i < pool->count; i++) {
        if (pool->free_apps_slots[i]) {
            pool->free_apps_slots[i]  = false;
            pool->apps[i].app_id      = app_id;
            pool->used               += 1;
            return (int)i;
        }
    }
    return -1;
}

bool 
app_pool_try_alloc_and_init_slot(
    nsn_app_pool_t *pool, int app_id, 
    nsn_mem_manager_cfg_t mem_cfg
) {
    int slot = app_pool_try_alloc_slot(pool, app_id);
    if (slot < 0) {
        return false;
    }
    return app_pool_init_slot(pool, slot, &mem_cfg);
}