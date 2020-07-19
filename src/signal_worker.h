#ifndef _UNINAT_SIGNAL_WORKER_H_
#define _UNINAT_SIGNAL_WORKER_H_

struct uninat_signal_worker_params {
    int signal_number;

    void (*handler_fn) (void *);
    void *user_data;
};

void *uninat_signal_worker_loop(void *params);

#endif
