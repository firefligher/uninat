#include <stdio.h>
#include <stdlib.h>

#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include "cmdline.h"
#include "signal_worker.h"

static void __refresh_configuration(void *);

int main(int argc, char *argv[]) {
    sigset_t signal_mask;
    pthread_t signal_thread;
    struct uninat_cmdline cmd_args;
    struct uninat_signal_worker_params signal_thread_args;

    /* Parsing the command-line arguments */

    if (uninat_cmdline_parse(&cmd_args, argc, argv) == 0) {
        fprintf(stderr, "err:\tFailed parsing the command-line arguments!\n");
        return EXIT_FAILURE;
    }

    uninat_cmdline_cleanup(&cmd_args);

    /*
     * It is important that we configure the main thread to discard any
     * incoming signals (that we are allowed to ignore) before we spawn other
     * threads.
     * Otherwise they will inherit the initial signal configuration.
     */

    sigfillset(&signal_mask);
    pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);

    /*
     * Spawning the signal worker that will trigger the configuration
     * refreshing.
     */

    signal_thread_args.handler_fn = &__refresh_configuration;
    signal_thread_args.signal_number = SIGUSR1;
    signal_thread_args.user_data = NULL;

    pthread_create(&signal_thread, NULL, &uninat_signal_worker_loop, &signal_thread_args);

    while (1) {
        pause();
    }

    return EXIT_SUCCESS;
}

static void __refresh_configuration(void *ignored) {
    printf("Refreshing the configuration requested...\n");
}
