#ifndef _UNINAT_TABLE_H_
#define _UNINAT_TABLE_H_

#include <stddef.h>
#include <stdio.h>

#include "mapping.h"

#define UNINAT_TABLE_FLAG_ENTRIES_ALLOCATED 0x01

struct uninat_table {
    /** (Internal) */
    int __flags;

    size_t entry_count;
    uninat_mapping *entries;
};

/**
 * Reads the UniNAT table from the specified source file descriptor and stores
 * the result at the specified uninat_table instance.
 *
 * After performing this operation, you should always ensure that the specified
 * uninat_table instance will be cleaned up by the
 * <code>uninat_table_cleanup</code> function.
 *
 * @param dst           The destination for the table entries that have been
 *                      read and parsed from the specified source file
 *                      descriptor.
 *
 * @param src_stream    The file stream that will be used for reading and
 *                      parsing the table entries.
 *
 * @return Either a positive value, if the function succeeded, otherwise zero.
 */
int uninat_table_read(struct uninat_table *dst, FILE *src_stream);

/**
 * Releases any (potentially) allocated memory of the specified uninat_table
 * instance.
 */
void uninat_table_cleanup(struct uninat_table *tbl);

#endif
