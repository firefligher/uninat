#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#include "mapping.h"
#include "table.h"

#define MALLOC_BLOCK_ELEMENTS   256

int uninat_table_read(struct uninat_table *dst, FILE *src_stream) {
    size_t max_entries;

    /* Cleaning the table structure */

    memset(dst, 0, sizeof(struct uninat_table));

    /* Allocating memory for the table entries */

    dst->entries = malloc(MALLOC_BLOCK_ELEMENTS * sizeof(uninat_mapping));

    if (dst->entries == NULL) {
        fprintf(stderr, "err:\tFailed allocating memory\n");
        return 0;
    }

    dst->__flags |= UNINAT_TABLE_FLAG_ENTRIES_ALLOCATED;
    max_entries = MALLOC_BLOCK_ELEMENTS;

    /* Iterating until reading fails */

    while (1) {
        int result, original_mask, replacement_mask;

        /* TODO: Improve parsing (comments) */

        result = fscanf(
            src_stream,
            " %hhu.%hhu.%hhu.%hhu/%hhu %hhu.%hhu.%hhu.%hhu/%hhu ",
            
            ((char *)(&dst->entries[dst->entry_count].original_addr) + 0),
            ((char *)(&dst->entries[dst->entry_count].original_addr) + 1),
            ((char *)(&dst->entries[dst->entry_count].original_addr) + 2),
            ((char *)(&dst->entries[dst->entry_count].original_addr) + 3),
            &original_mask,

            ((char *)(&dst->entries[dst->entry_count].replacement_addr) + 0),
            ((char *)(&dst->entries[dst->entry_count].replacement_addr) + 1),
            ((char *)(&dst->entries[dst->entry_count].replacement_addr) + 2),
            ((char *)(&dst->entries[dst->entry_count].replacement_addr) + 3),
            &replacement_mask);

        if (result != 10) {
            break;
        }

        /* Adjusting the address masks */

        dst->entries[dst->entry_count].original_mask =
            htonl(0xFFFFFFFF & (0xFFFFFFFF << (32 - original_mask)));

        dst->entries[dst->entry_count].replacement_mask =
            htonl(0xFFFFFFFF & (0xFFFFFFFF << (32 - replacement_mask)));

        dst->entry_count++;

        /*
         * Check, if we need to allocate more memory for the next table entry.
         */

        if (max_entries <= dst->entry_count) {
            uninat_mapping *new_entries;
            max_entries += MALLOC_BLOCK_ELEMENTS;

            new_entries = realloc(
                dst->entries,
                max_entries * sizeof(uninat_mapping));

            if (new_entries == NULL) {
                fprintf(stderr, "err:\tReallocating memory failed!\n");
                
                free(dst->entries);
                dst->__flags &= ~UNINAT_TABLE_FLAG_ENTRIES_ALLOCATED;
                
                return 0;
            }

            dst->entries = new_entries;
        }
    }

    return 1;
}

void uninat_table_cleanup(struct uninat_table *tbl) {
    if (tbl->__flags & UNINAT_TABLE_FLAG_ENTRIES_ALLOCATED) {
        free(tbl->entries);
        tbl->__flags &= ~UNINAT_TABLE_FLAG_ENTRIES_ALLOCATED;
    }
}
