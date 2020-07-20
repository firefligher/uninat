#ifndef _UNINAT_QUEUE_WORKER_H_
#define _UNINAT_QUEUE_WORKER_H_

#include <stdint.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "cmdline.h"
#include "table.h"

#define UNINAT_QUEUE_WORKER_FLAG_NFQ_HANDLE_INITIALIZED     0x01
#define UNINAT_QUEUE_WORKER_FLAG_QUEUE_HANDLE_INITIALIZED   0x02
#define UNINAT_QUEUE_WORKER_FLAG_WORKER_DATA_INITIALIZED    0x04
#define UNINAT_QUEUE_WORKER_FLAG_PACKET_BUFFER_INITIALIZED  0x08
#define UNINAT_QUEUE_WORKER_FLAG_NFQ_FD_INITIALIZED         0x10

struct uninat_queue_worker {
    /** (Internal) */
    int __flags;

    /** (Internal) */
    void *__worker_data;

    /** (Internal) */
    void *__packet_buffer;

    struct nfq_handle *nfq_handle;
    struct nfq_q_handle *queue_handle;
    int nfq_fd;
};


int uninat_queue_worker_initialize(
    struct uninat_queue_worker *wkr,
    int queue_number,
    struct uninat_table **table_ptr,
    enum uninat_cmdline_mode execution_mode,
    int verbose);

void uninat_queue_worker_cleanup(struct uninat_queue_worker *wkr);

int uninat_queue_worker_process(struct uninat_queue_worker *wkr);

#endif
