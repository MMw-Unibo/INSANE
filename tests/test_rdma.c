#include <endian.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <infiniband/verbs.h>

void *buf = NULL;
// struct ibv_comp_channel *channel = NULL;
struct ibv_context *context = NULL;
struct ibv_pd      *pd      = NULL;
struct ibv_mr      *mr      = NULL;
// NOTE(garbu): if we may want to use the timestamp we must switch to the
// struct ibv_cq_ext.
struct ibv_cq    *cq  = NULL;
struct ibv_qp    *qp  = NULL;
struct ibv_qp_ex *qpx = NULL;

int access_flags;
int size;
int send_flags;
int rx_depth;

//----------------------------------------------------------------------------------------------
// init ctx
int init_ibv_context() {
    access_flags = IBV_ACCESS_LOCAL_WRITE;
    size         = 4096 * 4096;
    send_flags   = IBV_SEND_SIGNALED;
    rx_depth     = 256;

    int res = posix_memalign(&buf, page_size, size);
    if (res < 0 || !buf) {
        printf("cannot allocate aligned memory: %s\n", strerror(errno));
        return -1;
    }

    context = ibv_open_device(ib_dev);
    if (!context) {
        printf("cannot get context for %s\n", name);
        goto clean_buf;
    }

    pd = ibv_alloc_pd(context);
    if (!pd) {
        printf("cannot allocate PD\n");
        goto clean_device;
    }

    // DevMem flag: interesting, check it out

    const uint32_t reliable_conn_caps_mask = IBV_ODP_SUPPORT_SEND | IBV_ODP_SUPPORT_RECV;

    struct ibv_device_attr_ex attrx;

    if (ibv_query_device_ex(context, NULL, &attrx)) {
        printf("cannot query device attributes\n");
    } else {
        if (attrx.completion_timestamp_mask) {
            printf("Such a beautiful Mellanox\n");
        }
        if (attrx.max_dm_size) {
            printf("Awesome, we can use DM\n");
        }
    }

    mr = ibv_reg_mr(pd, buf, size, access_flags);
    if (!mr) {
        printf("cannot register a memory region\n");
        goto clean_pd;
    }

    cq = ibv_create_cq(context, rx_depth + 1, NULL, NULL, 0);
    if (!cq) {
        printf("cannot create a completion queue (CQ)\n");
        goto clean_mr;
    }

    //------------------------------------------------------------------------------------------
    // init QP
    {
        struct ibv_qp_attr      attr;
        struct ibv_qp_init_attr init_attr = {
            .send_cq = cq,
            .recv_cq = cq,
            .cap =
                {
                    .max_send_wr  = 1, // Work request, i.e., queue size
                    .max_recv_wr  = rx_depth,
                    .max_send_sge = 1,
                    .max_recv_sge = 1,
                },
            .qp_type = IBV_QPT_RC,
        };

        struct ibv_qp_init_attr_ex init_attr_ex;
        memset(&init_attr_ex, 0, sizeof(init_attr_ex));
        init_attr_ex.send_cq          = cq;
        init_attr_ex.recv_cq          = cq;
        init_attr_ex.cap.max_send_wr  = 1;
        init_attr_ex.cap.max_recv_wr  = rx_depth;
        init_attr_ex.cap.max_send_sge = 1;
        init_attr_ex.cap.max_recv_sge = 1;
        init_attr_ex.qp_type          = IBV_QPT_RC;
        init_attr_ex.comp_mask        = IBV_QP_INIT_ATTR_PD | IBV_QP_INIT_ATTR_SEND_OPS_FLAGS;
        init_attr_ex.pd               = pd;
        init_attr_ex.send_ops_flags   = IBV_QP_EX_WITH_SEND;

        qp = ibv_create_qp_ex(context, &init_attr_ex);
        if (!qp) {
            printf("cannot create a Queue Pair (QP)\n");
            goto clean_cq;
        }

        qpx = ibv_qp_to_qp_ex(qp);

        ibv_query_qp(qp, &attr, IBV_QP_CAP, &init_attr);
        if (init_attr.cap.max_inline_data >= size)
            send_flags |= IBV_SEND_INLINE;
    }

    //------------------------------------------------------------------------------------------
    // Modify QP
    {
        struct ibv_qp_attr attr = {
            .qp_state        = IBV_QPS_INIT,
            .pkey_index      = 0,
            .port_num        = port,
            .qp_access_flags = 0,
        };

        if (ibv_modify_qp(qp, &attr,
                          IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS)) {
            fprintf(stderr, "Failed to modify QP to INIT\n");
            goto clean_qp;
        }
    }

    return 0;

clean_qp:
    ibv_destroy_qp(qp);

clean_cq:
    ibv_destroy_cq(cq);

clean_mr:
    ibv_dereg_mr(mr);

clean_pd:
    ibv_dealloc_pd(pd);

clean_device:
    ibv_close_device(context);

clean_buf:
    free(buf);

    // channel = ibv_create_comp_channel()

    return -1;
}

int main() {
    int num_devices;

    struct ibv_device **dev_list = ibv_get_device_list(&num_devices);
    if (!dev_list) {
        perror("failed to get IB devices list");
        return -1;
    }

    int page_size = sysconf(_SC_PAGESIZE);
    printf("%i\n", page_size);

    struct ibv_device *ib_dev = dev_list[0];
    const char        *name   = ibv_get_device_name(ib_dev);

    int res = init_ibv_context();
    if (res < 0)
        goto exit;

    //----------------------------------------------------------------------------------------------
    // clean
    free(buf);

exit:
    ibv_free_device_list(dev_list);

    return 0;
}
