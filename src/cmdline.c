#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "cmdline.h"

static struct option long_options[] = {
    { "table-file", required_argument, NULL, 't' },
    { "queue",      required_argument, NULL, 'q' },
    { "mode",       required_argument, NULL, 'm' }
};

#define MODE_BUF_LENGTH 16

int uninat_cmdline_parse(struct uninat_cmdline *dst, int argc, char *argv[]) {
    int v, idx;

    /* Always ensuring that there is no random data in dst */

    memset(dst, 0, sizeof(struct uninat_cmdline));

    /* Iterating over the parsed arguments. */

    while ((v = getopt_long(argc, argv, "t:q:m:", long_options, &idx)) != -1) {
        size_t optarg_len, mode_buf_len, i;
        char mode_buf[MODE_BUF_LENGTH];

        /*
         * TODO: Trim the command-line argument parameters.
         */

        switch (v) {
        case 't':
            optarg_len = strlen(optarg);
            dst->table_file = malloc(optarg_len + 1);

            if (!dst->table_file) {
                fprintf(stderr, "err:\tFailed allocating memory!\n");
                return 0;
            }

            dst->__flags |= UNINAT_CMDLINE_FLAG_TABLE_FILE_ALLOCATED;
            memcpy(dst->table_file, optarg, optarg_len + 1);
            break;

        case 'q':
            dst->queue_number = strtol(optarg, NULL, 10);
            break;

        case 'm':
            memset(mode_buf, 0, MODE_BUF_LENGTH);
            optarg_len = strlen(optarg);

            if (optarg_len > MODE_BUF_LENGTH - 1) {
                /*
                 * Always copy one character less than the mode_buf size,
                 * because otherwise the terminating null-character could be
                 * replaced.
                 */

                memcpy(mode_buf, optarg, MODE_BUF_LENGTH - 1);
                mode_buf_len = MODE_BUF_LENGTH - 1;
            } else {
                /* Copy one character more than the optarg, because we want to
                 * include the terminating null character (which is not stricly
                 * mandatory, because we already zero'ed the memory above).
                 */

                memcpy(mode_buf, optarg, optarg_len + 1);
                mode_buf_len = optarg_len;
            }

            /* Converting everything to UPPERCASE */

            for (i = 0; i < mode_buf_len; i++) {
                mode_buf[i] = toupper(mode_buf[i]);
            }

            /* Evaluation of the mode */

            if (strcmp("PREROUTING", mode_buf) == 0) {
                dst->execution_mode = UNINAT_CMDLINE_MODE_PREROUTING;
            } else if (strcmp("POSTROUTING", mode_buf) == 0) {
                dst->execution_mode = UNINAT_CMDLINE_MODE_POSTROUTING;
            } else {
                fprintf(
                    stderr,
                    "err:\tInvalid execution mode: \"%s\"; only "
                        "\"PREROUTING\" and \"POSTROUTING\" allowed!\n",
                    optarg);
                return 0;
            }
            break;

        default:
            break;
        }
    }

    /*
     * TODO: Validate that all required parameters have been set and display an
     * error, if that's not the case.
     */

    return 1;
}

void uninat_cmdline_cleanup(struct uninat_cmdline *cmdline) {
    if (cmdline->__flags & UNINAT_CMDLINE_FLAG_TABLE_FILE_ALLOCATED) {
        free(cmdline->table_file);
        cmdline->__flags &= ~UNINAT_CMDLINE_FLAG_TABLE_FILE_ALLOCATED;
    }
}
