#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/file.h>

#include <pthread.h>
#include <signal.h>
#include <unistd.h>

#include "cmdline.h"
#include "signal_worker.h"
#include "table.h"

/** The command-lines that have been specified when launching this process. */
static struct uninat_cmdline __cmd_args;

/** The table whose mapping rules are applied at the moment. */
static struct uninat_table *__current_table;

/**
 * These tables will be referenced by the __current_table pointer.
 *
 * Since we want to exchange them on the fly without further process
 * synchronization, we need two of them: One is referenced by __current_table,
 * while the other one can be configured.
 */
static struct uninat_table __table_1, __table_2;

static void __refresh_config(void *unused);

int main(int argc, char *argv[]) {
    sigset_t signal_mask;
    pthread_t signal_thread;
    struct uninat_signal_worker_params signal_thread_args;

    /*
     * Cleaning the two uninat_table entries manually. This ensures that we
     * always encounter the same behavior when calling uninat_table_clean on
     * them.
     */

    memset(&__table_1, 0, sizeof(struct uninat_table));
    memset(&__table_2, 0, sizeof(struct uninat_table));

    /* Parsing the command-line arguments */

    if (uninat_cmdline_parse(&__cmd_args, argc, argv) == 0) {
        fprintf(stderr, "err:\tFailed parsing the command-line arguments!\n");
        return EXIT_FAILURE;
    }

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

    signal_thread_args.handler_fn = &__refresh_config;
    signal_thread_args.signal_number = SIGUSR1;
    signal_thread_args.user_data = NULL;

    pthread_create(&signal_thread, NULL, &uninat_signal_worker_loop, &signal_thread_args);

    while (1) {
        pause();
    }

    uninat_cmdline_cleanup(&__cmd_args);
    
    return EXIT_SUCCESS;
}

static void __refresh_config(void *unused) {
    int table_fd;
    FILE *table_stream;
    struct uninat_table *inactive_table, *active_table;

    fprintf(stderr, "info:\tRequested refreshing the configuration.\n");

    /*
     * We need to open the configuration file and acquire a lock, before it is
     * safe to read and parse its contents. Otherwise, those informations could
     * become updated before we parsed them completely, which could cause
     * inconsistency.
     *
     * NOTE: We need to open the file using libc's fopen function because we
     *       use fread in the table parser.
     */

    table_stream = fopen(__cmd_args.table_file, "r");

    if (table_stream == NULL) {
        fprintf(
            stderr,
            "err:\tFailed opening the table file at \"%s\"!\n",
            __cmd_args.table_file);

        return;
    }

    table_fd = fileno(table_stream);

    if (table_fd == -1) {
        fprintf(
            stderr,
            "err:\tFailed deriving file descriptor from the FILE stream for "
                "the table file at \"%s\"!\n",
            __cmd_args.table_file);

        return;
    }

    if (flock(table_fd, LOCK_EX) != 0) {
        fprintf(
            stderr,
            "err:\tFailed acquiring lock for table file at \"%s\"!\n",
            __cmd_args.table_file);

        close(table_fd);
        return;
    }

    /*
     * Now, we need to determine which one of the __table_1/__table_2-pair is
     * not referenced by __current_table, because we can only safely edit the
     * not-referenced one.
     *
     * Then we can just parse the previously opened file descriptor to that
     * (unused) structure, switch the active table reference and clean up.
     */

    if (__current_table == &__table_1) {
        active_table = &__table_1;
        inactive_table = &__table_2;
    } else {
        active_table = &__table_2;
        inactive_table = &__table_1;
    }

    if (uninat_table_read(inactive_table, table_stream) == 0) {
        fprintf(
            stderr,
            "err:\tFailed reading table file at \"%s\"!\n",
            __cmd_args.table_file);

        flock(table_fd, LOCK_UN);
        close(table_fd);

        return;
    }

    /*
     * NOTE: Synchronization is required on hosts where the following statement
     *       is non-atomic.
     */

    __current_table = inactive_table;

    /* Cleanup begins here. */

    uninat_table_cleanup(active_table);

    if (flock(table_fd, LOCK_UN) != 0) {
        fprintf(
            stderr,
            "warn:\tFailed unlocking table file at \"%s\"!\n",
            __cmd_args.table_file);
    }

    if (fclose(table_stream) != 0) {
        fprintf(
            stderr,
            "warn:\tFailed closing FILE stream to table file at \"%s\"!\n",
            __cmd_args.table_file);
    }

    fprintf(
        stderr,
        "info:\tParsed %d table entries from \"%s\".\n",
        __current_table->entry_count,
        __cmd_args.table_file);
}
