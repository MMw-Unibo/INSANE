#include "nsn_mm.h"

nsn_mem_manager_t *
nsn_memory_manager_create(mem_arena_t *arena, nsn_mem_manager_cfg_t *cfg)
{
    // TODO(garbu): create a shared memory for the data plane using the config 
    //              to determine the size of the shared memory. 
    //              In the shared memory, we have both the memory buffer and the
    //              ring buffers used for the receive and transmit queues.
    nsn_shm_t *shm = nsn_shm_alloc(arena, to_cstr(cfg->shm_name), cfg->shm_size);
    if (!shm) {
        log_error("Failed to create shared memory\n");
        return NULL;
    }

    // Create the memory manager
    nsn_mem_manager_t *mem = mem_arena_push_struct(arena, nsn_mem_manager_t);
    mem->shm       = shm;
    mem->shm_arena = fixed_mem_arena_alloc(nsn_shm_rawdata(shm), nsn_shm_size(shm));
    mem->zones     = fixed_mem_arena_push_struct(mem->shm_arena, nsn_mm_zone_list_t);
    
    // The data in the shared memory will be allocated using a list of zones
    // each zone will have a header with the size of the zone, the name of the zone, the type of the zone, 
    // the pointer to the next zone, the pointer to the previous zone, and the pointer to the first block of the zone.

    usize total_zone_size = cfg->io_buffer_pool_size * cfg->io_buffer_size;
    nsn_mm_zone_t *tx_zone = nsn_memory_manager_create_zone(mem, str_lit(NSN_CFG_DEFAULT_TX_IO_BUFS_NAME), total_zone_size, NSN_MM_ZONE_TYPE_IO_BUFFER_POOL,cfg->io_buffer_size );
    if (!tx_zone) {
        log_error("failed to create the tx_zone\n");
        return NULL;
    }
    
    // The metadata associated with the actual data slots (e.g., pkt len) is kept in a separate zone
    total_zone_size = cfg->io_buffer_pool_size * sizeof(nsn_meta_t);
    nsn_mm_zone_t *tx_meta_zone = nsn_memory_manager_create_zone(mem, str_lit(NSN_CFG_DEFAULT_TX_META_NAME), total_zone_size, NSN_MM_ZONE_TYPE_IO_BUFFER_POOL, cfg->io_buffer_size);
    if (!tx_meta_zone) {
        log_error("failed to create the tx_meta_zone\n");
        return NULL;
    }

    // Create a pool of ring buffers inside the ring zone. In the current design, all the rings have the same size.
    // TODO: The free_slots can be split into a tx/rx couple of rings, if we decide to keep both the tx and rx memory areas separated. Now we keep 1 zone for slots (tx_zone) and 1 ring for its indexing (NSN_CFG_DEFAULT_FREE_SLOTS_RING_NAME).
    usize max_rings               = 8;
    usize total_free_slots        = /*2 * */cfg->io_buffer_pool_size;
    nsn_ringbuf_pool_t *ring_pool = nsn_memory_manager_create_ringbuf_pool(mem, str_lit(NSN_CFG_DEFAULT_RINGS_ZONE_NAME), max_rings, sizeof(usize), total_free_slots);

    // Create the ring that keeps the free slot descriptors.
    nsn_ringbuf_t *free_slots_ring = nsn_memory_manager_create_ringbuf(ring_pool, str_lit(NSN_CFG_DEFAULT_FREE_SLOTS_RING_NAME));
    if (!free_slots_ring) {
        log_error("Failed to create the free_slots ring\n");
        // TODO: Should we clean the things we created so far? E.g., zones etc?
        return NULL;
    }
    log_trace("Successfully created the free_slots ring at %p with name %s\n", free_slots_ring, free_slots_ring->name);
    
    // Fill the ring buffer with the index of the tx slots 
    for (usize i = 0; i < total_free_slots - 1; ++i) {
        nsn_ringbuf_enqueue_burst(free_slots_ring, &i, sizeof(i), 1, NULL);
    } 

    return mem;
}

void
nsn_memory_manager_destroy(nsn_mem_manager_t *mem)
{
    at_fadd(&mem->shm->ref_count, -1, mo_rlx);
    nsn_shm_release(mem->shm);
}

// The zone is created in the shared memory and the pointer to the zone is returned.
// The shared memory works as a linear memory, so the zone is created at the end of the memory, after the last zone.
// Zones are rounded to the next multiple of the page size.
nsn_mm_zone_t *
nsn_memory_manager_create_zone(
    nsn_mem_manager_t *mem, string_t name, 
    usize size, usize type, usize slot_alignment
) {
    if (nsn_zone_exists(mem->zones, name)) {
        log_warn("zone with name " str_fmt " already exists\n", str_varg(name));
        return NULL; 
    }

    // round the size to the next multiple of the page size
    usize page_size = (type == NSN_MM_ZONE_TYPE_IO_BUFFER_POOL? (1ULL << 21) : nsn_os_default_page_size());
    usize zone_size = align_to(size + sizeof(nsn_mm_zone_t), page_size);

    // create the zone in the shared memory
    usize base_offset   = mem->shm_arena->pos;
    nsn_mm_zone_t *zone = fixed_mem_arena_push(mem->shm_arena, zone_size);
    if (!zone) {
        return NULL;
    }

    // Initialize the zone. To ensure proper alignement and avoid cross-page memory slots,
    // we must ensure that the first slot is aligned to the slot size. Hence, the first block offset
    // is set to the base_offset + sizeof(nsn_mm_zone_t) + the missing bytes to achieve the alignment.
    // TODO: Would be even better, in case of slot_alignment < sizeof(nsn_mm_zone_t), to increase the
    // slot_alignment to the next power of 2 that is greater than sizeof(nsn_mm_zone_t).
    usize padding = sizeof(nsn_mm_zone_t);
    if (sizeof(nsn_mm_zone_t) < slot_alignment) {
        padding = align_to(sizeof(nsn_mm_zone_t), slot_alignment);
        void* zone_aligned = (void*)((usize)zone & 0xFFFFFFFFFFF00000);
        usize base_offset_aligned = (usize)zone - (usize)zone_aligned;
        padding -= base_offset_aligned;
    }
    
    zone->base_offset        = base_offset;
    zone->total_size         = zone_size;
    zone->size               = zone->total_size - padding;
    zone->type               = type;
    zone->first_block_offset = base_offset + padding;
    strncpy(zone->name, to_cstr(name), sizeof(zone->name) - 1);

    // add the zone to the list of zones
    nsn_zone_list_add_tail(mem->zones, zone);

    return zone;
}

nsn_ringbuf_pool_t *
nsn_memory_manager_create_ringbuf_pool(
    nsn_mem_manager_t *mem, string_t name, 
    usize count, usize esize, usize ecount
) {
    usize zone_size = sizeof(nsn_ringbuf_pool_t)           // the size of the pool header
                    + (count * sizeof(bool))               // keeps track of the free slots
                    + sizeof(nsn_ringbuf_t) * count        // the number of ring buffers
                    + (esize * ecount) * count;            // the size of the elements in the ring buffers

    nsn_mm_zone_t *zone = nsn_memory_manager_create_zone(mem, name, zone_size, NSN_MM_ZONE_TYPE_RINGS, esize);
    if (!zone) {
        log_error("Failed to create zone for ring buffer pool\n");
        return NULL;
    }

    nsn_ringbuf_pool_t *pool = (nsn_ringbuf_pool_t *)nsn_mm_zone_get_ptr(zone);
    pool->zone              = zone;
    pool->count             = count;
    pool->esize             = esize;
    pool->ecount            = ecount;
    pool->free_slots_count  = count;
    strncpy(pool->name, to_cstr(name), sizeof(pool->name) - 1);

    return pool;
}

nsn_ringbuf_pool_t * 
nsn_memory_manager_get_ringbuf_pool(nsn_mem_manager_t* mem) 
{
    nsn_mm_zone_t* zone = nsn_find_zone_by_name(mem->zones, str_lit("rings_zone"));
    if (!zone) {
        log_error("Zone \"rings_zone\" not found\n");
        return NULL;
    }

    return (nsn_ringbuf_pool_t*)nsn_mm_zone_get_ptr(zone);
}

// @param pool: the pool of ring buffers
// @param ring_name: the name of the ring buffer
// @return: a pointer to the ring buffer
// The size of each ring is fixed and set at pool creation
nsn_ringbuf_t * 
nsn_memory_manager_create_ringbuf(nsn_ringbuf_pool_t* pool, string_t ring_name) 
{
    if(pool->free_slots_count == 0) {
        log_error("No more free slots in the ring buffer pool\n");
        return NULL;
    }

    // check which slots are free
    bool* ring_tracker = (bool*)(pool + 1);

    // find a free slot
    int slot = -1;
    for (usize i = 0; i < pool->count; ++i) {
        if (ring_tracker[i] == false) {
            ring_tracker[i] = true;
            slot            = i;
            break;
        }
    }

    // create the ring buffer in the shared memory
    char* ring_data     = (char*)(ring_tracker + pool->count);  
    usize ring_size     = sizeof(nsn_ringbuf_t) + (pool->ecount * pool->esize);
    nsn_ringbuf_t* ring = nsn_ringbuf_create(&ring_data[slot*ring_size], ring_name, pool->ecount);

    // fill in the descriptorsfor this ring in the pool    
    pool->free_slots_count--;

    log_debug("Ring buffer %.*s created at %p\n", str_varg(ring_name), ring);
    return ring;
}

// @param mem: the memory manager
// @param ring_name: the name of the ring buffer to retrieve
// @return: a pointer to the ring buffer, NULL if the ring buffer was not found
nsn_ringbuf_t *
nsn_memory_manager_lookup_ringbuf(nsn_mem_manager_t* mem, string_t ring_name) 
{
    nsn_ringbuf_pool_t* pool = nsn_memory_manager_get_ringbuf_pool(mem);
    if (!pool) {
        log_error("Failed to get the ring buffer pool\n");
        return NULL;
    }
    
    // check which slots are free
    bool* ring_tracker = (bool*)(pool + 1);
    char* ring_data = (char*)(ring_tracker + pool->count);  
    usize ring_size = sizeof(nsn_ringbuf_t) + (pool->ecount * pool->esize);

    // find the ring buffer to destroy
    nsn_ringbuf_t* ring = 0;
    for (usize i = 0; i < pool->count; i++) {
        if (ring_tracker[i] == true) {
            ring = (nsn_ringbuf_t*)(&ring_data[i*ring_size]);
            if (strcmp(ring->name, to_cstr(ring_name)) == 0) {
                break;
            } else {
                ring = NULL;
            }
        }
    }

    if (!ring) {
        log_error("Lookup: Ring buffer %.*s not found\n", str_varg(ring_name));
        return NULL;
    }

    return ring;
}

// @param pool: the pool of ring buffers
// @param ring_name: the name of the ring buffer to destroy
// @return: 0 if the ring buffer was destroyed, <0 otherwise (errno value)
int 
nsn_memory_manager_destroy_ringbuf(nsn_ringbuf_pool_t* pool, string_t ring_name) 
{
    if (!pool) {
        log_error("Invalid ring buffer pool\n");
        return -1;
    }

    // check which slots are free
    bool* ring_tracker = (bool*)(pool + 1);
    char* ring_data = (char*)(ring_tracker + pool->count);  
    usize ring_size = sizeof(nsn_ringbuf_t) + (pool->ecount * pool->esize);

    // find the ring buffer to destroy
    nsn_ringbuf_t* ring = 0;
    for (usize i = 0; i < pool->count; i++) {
        if (ring_tracker[i] == true) {
            ring = (nsn_ringbuf_t*)(&ring_data[i*ring_size]);
            if (strcmp(ring->name, to_cstr(ring_name)) == 0) {
                break;
            } else {
                ring = NULL;
            }
        }
    }

    if (!ring) {
        log_error("Lookup: Ring buffer %.*s not found\n", str_varg(ring_name));
        return -1;
    }

    // destroy the ring buffer
    int error = nsn_ringbuf_destroy(ring);
    if (!error) {
        pool->free_slots_count++;
    }

    return -error;
}
