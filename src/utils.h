#ifndef _HNS_UTILS_H
#define _HNS_UTILS_H

#include <stdbool.h>
#include <stdint.h>

#define HNS_APP_NAME "Handshake"
#define HNS_MAX_PATH 10
#define HNS_MAX_PATH_LEN 4 * HNS_MAX_PATH + 1

bool
hns_read_u32(uint32_t *, uint8_t *, bool);

bool
hns_read_varint(uint32_t *, uint8_t *);
#endif
