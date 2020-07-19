#ifndef _UNINAT_CMDLINE_H_
#define _UNINAT_CMDLINE_H_

#define UNINAT_CMDLINE_FLAG_TABLE_FILE_ALLOCATED    0x01

struct uninat_cmdline {
    /* (Internal) */
    int _flags;

    /* Path to the mapping table configuration file. (heap) */
    char *table_file;

    /* NFQUEUE queue number */
    int queue_number;
};

/**
 * Parse the command-line arguments.
 *
 * A structure that has been passed to this function should be always cleaned
 * up with the <code>uninat_cmdline_cleanup</code> function afterwards.
 *
 * @param dst   The structure that will be used for storing the parsed
 *              information.
 *
 * @param argc  The number of elements in argv.
 * @param argv  An array of the command-line arguments.
 *
 * @returns Either a positive value, if successful, otherwise zero.
 */
int uninat_cmdline_parse(struct uninat_cmdline *dst, int argc, char *argv[]);

/**
 * Releases the (potentially) allocated buffers of the passed structure.
 *
 * @param cmdline   The structure that the cleanup will be performed on.
 */
void uninat_cmdline_cleanup(struct uninat_cmdline *cmdline);

#endif
