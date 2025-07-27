#ifndef NSN_ZONE_H
#define NSN_ZONE_H

#include "base/nsn_string.h"

// --- Named Memory Zone -------------------------------------------------------
enum nsn_mm_zone_type
{
    NSN_MM_ZONE_TYPE_IO_BUFFER_POOL,
    NSN_MM_ZONE_TYPE_RINGS,
};

typedef struct nsn_mm_zone nsn_mm_zone_t;
struct nsn_mm_zone
{
    char         name[32];
    u32          type;
    // The offset of the zone in the shared memory
    usize        base_offset;
    // The total size of the zone, including the header
    usize        total_size;
    // The size of the zone, excluding the header
    usize        size;
    // The offset of zone data, relative to the shared memory
    usize        first_block_offset;
    // The offset of the next zone in the list
    usize        next_zone_offset; 
} nsn_cache_aligned;

typedef struct nsn_mm_zone_list nsn_mm_zone_list_t;
struct nsn_mm_zone_list
{
    usize          head_offset;
    usize          count;
} nsn_cache_aligned;

static inline void* 
nsn_mm_zone_get_ptr(nsn_mm_zone_t *zone)
{
    return ((char*)zone) + (zone->first_block_offset - zone->base_offset);
}

void
nsn_zone_list_add_tail(nsn_mm_zone_list_t *list, nsn_mm_zone_t *zone)
{
    byte *memory = (byte *)list;
    if (list->count == 0)
    {
        list->head_offset      = (usize)zone - (usize)memory;
        list->count            = 1;
        zone->next_zone_offset = 0;
    }
    else
    {
        nsn_mm_zone_t *last_zone = (nsn_mm_zone_t *)(memory + list->head_offset);
        while (last_zone->next_zone_offset != 0)
        {
            last_zone = (nsn_mm_zone_t *)(memory + last_zone->next_zone_offset);
        }
        last_zone->next_zone_offset = (usize)zone - (usize)memory;
        list->count++;
    }
}

nsn_mm_zone_t *
nsn_find_zone_by_name(nsn_mm_zone_list_t *zones, string_t name)
{
    // if the list is empty, return NULL
    if (zones->count == 0)
        return NULL;
    
    byte *memory        = (byte *)zones;
    nsn_mm_zone_t *zone = NULL;
    for (usize offset = zones->head_offset; offset != 0; offset = zone->next_zone_offset)
    {
        zone = (nsn_mm_zone_t *)(memory + offset);
        if (cstr_eq(zone->name, name))
        {
            return zone;
        }
    }

    return NULL;
}

bool nsn_zone_exists(nsn_mm_zone_list_t *zones, string_t name)
{
    return nsn_find_zone_by_name(zones, name) != NULL;
}

void print_zone(nsn_mm_zone_t *zone)
{
    printf("Zone: %s\n", zone->name);
    printf("  type: %u\n", zone->type);
    printf("  base_offset: %zu\n", zone->base_offset);
    printf("  total_size: %zu\n", zone->total_size);
    printf("  size: %zu\n", zone->size);
    printf("  first_block_offset: %zu\n", zone->first_block_offset);
}

#endif // NSN_ZONE_H