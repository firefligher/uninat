#include <stdlib.h>

#include "cmdline.h"

int uninat_cmdline_parse(struct uninat_cmdline *dst, int argc, char *argv[]) {
    return 0;
}

void uninat_cmdline_cleanup(struct uninat_cmdline *cmdline) {
    if (cmdline->_flags & UNINAT_CMDLINE_FLAG_TABLE_FILE_ALLOCATED) {
        free(cmdline->table_file);
        cmdline->_flags &= ~UNINAT_CMDLINE_FLAG_TABLE_FILE_ALLOCATED;
    }
}
