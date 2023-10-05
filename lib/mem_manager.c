#include "mem_manager.h"

#include <fcntl.h>
#include <sys/mman.h>

#include <rte_errno.h>
#include <rte_mbuf.h>

#include "common.h"

#include "insane/logger.h"

//--------------------------------------------------------------------------------------------------
i32 mem_manager__init(nsn_memmanager_t *mm, const char *name) {
    if (!mm) {
        return -1;
    }

    LOG_TRACE("Mapping the memory for control path");

    nsn_meminfo_t *info = &mm->info;

    memset(mm, 0, sizeof(*mm));
    strncpy(info->shm_name, name, SHM_MAX_PATH);

    info->shm_fd = shm_open(info->shm_name, O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IRUSR);
    if (info->shm_fd == -1) {
        LOG_ERROR("shm_open: %s (%s)", strerror(errno), info->shm_name);
        return -1;
    }

    if (ftruncate(info->shm_fd, TOTAL_SHM_SIZE) == -1) {
        return -2;
    }

    info->buffer = mmap(NULL, TOTAL_SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, info->shm_fd, 0);
    if (info->buffer == MAP_FAILED) {
        return -3;
    }

    info->shm_size    = TOTAL_SHM_SIZE;
    info->used_memory = 0;

    //    const size_t queue_struct_total_size = (sizeof(nsn_queue_t) + sizeof(i32a) *
    //    (MAX_PKT_BURST));

    /* Tx queues for DPDK */
    LOG_TRACE("Allocating queues for DPDK (occup=%ld, total=%ld)", info->used_memory,
              info->shm_size);
    // mm->tx_info[mempool_dpdk].tx_cons = (nsn_queue_t *)(info->buffer);
    // info->used_memory += queue_struct_total_size;

    // mm->tx_info[mempool_dpdk].tx_prod = (nsn_queue_t *)(info->buffer + info->used_memory);
    // info->used_memory += queue_struct_total_size;
    nsn_meminfo_tx_t *mm_tx = &mm->tx_info[mempool_dpdk];

    mm_tx->tx_meta = (nsn_pktmeta_t *)(info->buffer + info->used_memory);
    info->used_memory += (sizeof(nsn_pktmeta_t) * MAX_PKT_BURST);

    // nsn_queue__init(mm->tx_info[mempool_dpdk].tx_cons, "tx_cons_dpdk", MAX_PKT_BURST,
    //                 nsn_qtype_mpmc);
    // nsn_queue__init(mm->tx_info[mempool_dpdk].tx_prod, "tx_prod_dpdk", MAX_PKT_BURST,
    //                 nsn_qtype_mpmc);

    // for (size_t i = 0; i < mm->tx_info[mempool_dpdk].tx_cons->size; i++) {
    // nsn_queue__push(mm->tx_info[mempool_dpdk].tx_cons, i);
    // }

    /* Tx queues for Sockets */
    LOG_TRACE("Allocating queues for Sockets (occup=%ld, total=%ld)", info->used_memory,
              info->shm_size);
    // mm->tx_info[mempool_socket].tx_cons = (nsn_queue_t *)(info->buffer);
    // info->used_memory += queue_struct_total_size;

    // mm->tx_info[mempool_socket].tx_prod = (nsn_queue_t *)(info->buffer + info->used_memory);
    // info->used_memory += queue_struct_total_size;

    mm_tx = &mm->tx_info[mempool_socket];

    mm->tx_info[mempool_socket].tx_meta = (nsn_pktmeta_t *)(info->buffer + info->used_memory);
    info->used_memory += (sizeof(nsn_pktmeta_t) * MAX_PKT_BURST);

    // nsn_queue__init(mm->tx_info[mempool_socket].tx_cons, "tx_cons_socket", MAX_PKT_BURST,
    //                 nsn_qtype_mpmc);
    // nsn_queue__init(mm->tx_info[mempool_socket].tx_prod, "tx_prod_socket", MAX_PKT_BURST,
    //                 nsn_qtype_mpmc);

    // for (size_t i = 0; i < mm->tx_info[mempool_socket].tx_cons->size; i++) {
    // nsn_queue__push(mm->tx_info[mempool_socket].tx_cons, i);
    // }

    return 0;
}

//--------------------------------------------------------------------------------------------------
void mem_manager__add_mempool(nsn_memmanager_t *mm, void *mempool,
                              mempool_type_t mptype) // NOTE(lr) Do we need a lock here?
{
    switch (mptype) {

    case mempool_dpdk: {
        // DOES THIS WORK LOL!
        mm->dpdk_pool = (struct rte_mempool *)mempool;

        // DPDK requires the io_ctx to be shared
        mm->dpdk_ctx = (nsn_ioctx_dpdk_t *)(mm->info.buffer + mm->info.used_memory);
        mm->info.used_memory += sizeof(nsn_ioctx_dpdk_t);

        for (size_t i = 0; i < MAX_PKT_BURST; i++) {
            mm->dpdk_ctx->tx_mbuf[i] = rte_pktmbuf_alloc(mempool);
            if (mm->dpdk_ctx->tx_mbuf[i] == NULL) {
                LOG_ERROR("cannot get mbuf_pool: %s (%d)", rte_strerror(rte_errno), rte_errno);
                break;
            }
        }

        const unsigned flags     = 0; // RING_F_SP_ENQ | RING_F_SC_DEQ;
        const unsigned ring_size = MAX_PKT_BURST;

        nsn_meminfo_tx_t *mm_tx = &mm->tx_info[mempool_dpdk];

        mm_tx->tx_cons = rte_ring_create("tx_cons_dpdk", ring_size, rte_socket_id(), flags);
        mm_tx->tx_prod = rte_ring_create("tx_prod_dpdk", ring_size, rte_socket_id(), flags);

        for (size_t i = 0; i < rte_ring_get_capacity(mm_tx->tx_cons); i++) {
            rte_ring_enqueue(mm_tx->tx_cons, (void *)i);
        }

    } break;
    case mempool_socket: {
        mm->socket_pool = (nsn_meminfo_t *)mempool;

        for (size_t i = 0; i < RX_SOCK_SLOTS; i++) {
            mm->socket_ctx.rx_mbuf[i] = &((struct nsn_mbuf *)mm->socket_pool->buffer)[i];
        }
        for (size_t i = 0; i < TX_SOCK_SLOTS; i++) {
            mm->socket_ctx.tx_mbuf[i] =
                &((struct nsn_mbuf *)mm->socket_pool->buffer)[RX_SOCK_SLOTS + i];
        }
        mm->socket_pool->used_memory = (TX_SOCK_SLOTS + RX_SOCK_SLOTS) * NSN_SLOT_SIZE;

        const unsigned flags     = 0; // RING_F_SP_ENQ | RING_F_SC_DEQ;
        const unsigned ring_size = MAX_PKT_BURST;

        nsn_meminfo_tx_t *mm_tx = &mm->tx_info[mempool_socket];

        mm_tx->tx_cons = rte_ring_create("tx_cons_socket", ring_size, rte_socket_id(), flags);
        mm_tx->tx_prod = rte_ring_create("tx_prod_socket", ring_size, rte_socket_id(), flags);

        for (size_t i = 0; i < rte_ring_get_capacity(mm_tx->tx_cons); i++) {
            rte_ring_enqueue(mm_tx->tx_cons, (void *)i);
        }

        /* Rx index queue for sockets */
        // We need this queue here becasue we do not have chunks. With chunks,
        // we derived the index for the next slot free to receive using chuncks
        // (with a loop on them, which are few). Here, that would mean to loop
        // over all the slots to check if they are free. As that is expensive,
        // we instead rely on a queue of free slots for reception, avoiding the
        // loop.
        const size_t free_rx_idx_size = (sizeof(nsn_queue_t) + sizeof(i32a) * (RX_SOCK_SLOTS));
        // mm->socket_ctx.free_rx_idx    = (nsn_queue_t *)(mm->info.buffer + mm->info.used_memory);
        mm->socket_ctx.free_rx_idx = rte_ring_create(
            "free_rx_index_socket", RX_SOCK_SLOTS, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);

        // mm->info.used_memory += free_rx_idx_size;
        // nsn_queue__init(mm->socket_ctx.free_rx_idx, "free_rx_index_socket", RX_SOCK_SLOTS,
        //                 nsn_qtype_spsc);

        for (size_t i = 0; i < mm->socket_ctx.free_rx_idx->size; i++) {
            // nsn_queue__push(mm->socket_ctx.free_rx_idx, i);
            rte_ring_enqueue(mm->socket_ctx.free_rx_idx, (void *)(i64)i);
        }
    } break;
    }
}

//--------------------------------------------------------------------------------------------------
i32 mem_manager__consume(nsn_memmanager_t *mm, bool blocks, nsn_buffer_t *buf,
                         mempool_type_t mptype) {
    if (blocks) {
        // buf->index = nsn_queue__pop(mm->tx_info[mptype].tx_prod);
        while (rte_ring_dequeue(mm->tx_info[mptype].tx_prod, (void **)&buf->index) < 0) {
            SPIN_LOOP_PAUSE();
        }

    } else {
        // i32 tmp_index = nsn_queue__try_pop(mm->tx_info[mptype].tx_prod);
        i32 tmp_index;
        i32 res = rte_ring_dequeue(mm->tx_info[mptype].tx_prod, (void **)&tmp_index);
        if (res < 0) {
            return -1;
        }
        buf->index = tmp_index;
    }

    // TODO: This is where Garbu's idea about "interface" should work
    switch (mptype) {
    case mempool_dpdk:
        buf->data = (uint8_t *)mm->dpdk_ctx->tx_mbuf[buf->index];
        break;
    case mempool_socket:
        buf->data = (uint8_t *)mm->socket_ctx.tx_mbuf[buf->index];
        break;
    }

    return 0;
}

//--------------------------------------------------------------------------------------------------
void mem_manager__release(nsn_memmanager_t *mm, nsn_buffer_t *buf, mempool_type_t mptype) {
    // nsn_queue__push(mm->tx_info[mptype].tx_cons, buf->index);
    rte_ring_enqueue(mm->tx_info[mptype].tx_cons, (void *)(i64)buf->index);
}

//--------------------------------------------------------------------------------------------------
nsn_buffer_t mem_manager__acquire(nsn_memmanager_t *mm, mempool_type_t mptype) {
    nsn_buffer_t buf;
    // buf.index = nsn_queue__pop(mm->tx_info[mptype].tx_cons);
    while (rte_ring_dequeue(mm->tx_info[mptype].tx_cons, (void **)&buf.index) < 0) {
        SPIN_LOOP_PAUSE();
    }

    // TODO: This is where Garbu's idea about "interface" should work
    switch (mptype) {
    case mempool_dpdk:
        buf.data = (uint8_t *)mm->dpdk_ctx->tx_mbuf[buf.index];
        break;
    case mempool_socket:
        buf.data = (uint8_t *)mm->socket_ctx.tx_mbuf[buf.index];
        break;
    }

    return buf;
}

//--------------------------------------------------------------------------------------------------
void mem_manager__submit(nsn_memmanager_t *mm, nsn_buffer_t *buf, mempool_type_t mptype) {
    // nsn_queue__push(mm->tx_info[mptype].tx_prod, buf->index);
    rte_ring_enqueue(mm->tx_info[mptype].tx_prod, (void *)(i64)buf->index);
}

//--------------------------------------------------------------------------------------------------
void mem_manager__delete(nsn_memmanager_t *mm) {
    munmap(mm->info.buffer, mm->info.shm_size);

    shm_unlink(mm->info.shm_name);

    close(mm->info.shm_fd);
}