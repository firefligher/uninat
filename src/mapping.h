#ifndef _UNINAT_MAPPING_H_
#define _UNINAT_MAPPING_H_

#include <stdint.h>

typedef struct {
    uint32_t original_addr;
    uint32_t original_mask;
    uint32_t replacement_addr;
    uint32_t replacement_mask;
} uninat_mapping;

#endif
