#ifndef _UNINAT_CMDLINE_H_
#define _UNINAT_CMDLINE_H_

#define UNINAT_CMDLINE_FLAG_TABLE_FILE_ALLOCATED    0x01

enum uninat_cmdline_mode {
    /**
     * Specifies that the target UniNAT instance handles packets at iptable's
     * PREROUTING state.
     *
     * The address translation rule for the source/destination host address is
     * determined by the IPv4 source address of the handled packet.
     */
    UNINAT_CMDLINE_MODE_PREROUTING = 0x00,

    /**
     * Specifies that the target UniNAT instance handles packets at iptable's
     * POSTROUTING state.
     *
     * The address translation rule for the source/destination host address is
     * determined by the IPv4 destination address of the handled packet.
     */
    UNINAT_CMDLINE_MODE_POSTROUTING
};

struct uninat_cmdline {
    /** (Internal) */
    int __flags;

    /** Path to the mapping table configuration file. (heap) */
    char *table_file;

    /** NFQUEUE queue number */
    int queue_number;

    /** The execution mode of this UniNAT instance. */
    enum uninat_cmdline_mode *execution_mode;
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
