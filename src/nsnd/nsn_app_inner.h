#ifndef NSN_APP_INNER_H
#define NSN_APP_INNER_H

#include "base/nsn_memory.h"
#include "base/nsn_string.h"

#include "nsn_mm.h"

typedef struct nsn_app nsn_app_t;
struct nsn_app
{
    nsn_app_t *next;
    nsn_app_t *prev;

    int               app_id;
    mem_arena_t       *arena;
    nsn_mem_manager_t *mem;
};

typedef struct nsn_app_list nsn_app_list_t;
struct nsn_app_list
{
    nsn_app_t   *head;
    nsn_app_t   *tail;
    usize        count;
};

typedef struct nsn_app_pool nsn_app_pool_t;
struct nsn_app_pool
{
    mem_arena_t *arena;
    nsn_app_t   *apps;
    bool        *free_apps_slots;
    usize        count; // MAX apps handled by the daemon
    usize        used;
};

// nsn_app_pool_t *nsn_app_pool_create (usize pool_size);

bool app_pool_init_slot               (nsn_app_pool_t *pool, int app_slot, nsn_mem_manager_cfg_t* mem_cfg);
int  app_pool_try_alloc_slot          (nsn_app_pool_t *pool, int app_id);
bool app_pool_try_alloc_and_init_slot (nsn_app_pool_t *pool, int app_id, nsn_mem_manager_cfg_t mem_cfg);

#endif // NSN_APP_INNER_H