#include "signal_worker.h"

#include <stddef.h>
#include <pthread.h>
#include <signal.h>

void *uninat_signal_worker_loop(void *params) {
    struct uninat_signal_worker_params *swp;
    sigset_t signal_mask;
    int received_signal_number;

    swp = (struct uninat_signal_worker_params *)params;

    /* Setting up the signal mask: We want to receive the specified signal. */

    sigemptyset(&signal_mask);
    sigaddset(&signal_mask, swp->signal_number);

    /*
     * By default, no thread receives any signal because they inherit their
     * signal configuration from the initial thread.
     *
     * We need to unblock our signal mask to receive the configuration signal.
     */

    pthread_sigmask(SIG_UNBLOCK, &signal_mask, NULL);

    /* Now, just waiting for incoming signals in a loop. */

    while (1) {
        if (sigwait(&signal_mask, &received_signal_number) != 0)
            continue;

        if (received_signal_number != swp->signal_number)
            continue;

        /*
         * If the received signal is the one that we are waiting for, we just
         * call the configured callback function.
         */

        swp->handler_fn(swp->user_data);
    }

    return NULL;
}
