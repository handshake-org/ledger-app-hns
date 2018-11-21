#include <stdbool.h>
#include <stdint.h>
#include "ledger.h"
#include "utils.h"

bool
hns_read_u32(uint32_t * out, uint8_t * in, bool be) {
  *out = 0;

  if (be) {
    *out |= ((uint32_t) in[0]) << 24;
    *out |= ((uint32_t) in[1]) << 16;
    *out |= ((uint32_t) in[2]) << 8;
    *out |=  (uint32_t) in[3];
  } else {
    *out |= ((uint32_t) in[3]) << 24;
    *out |= ((uint32_t) in[2]) << 16;
    *out |= ((uint32_t) in[1]) << 8;
    *out |=  (uint32_t) in[0];
  }

  return true;
}

bool
hns_read_varint(uint32_t * out, uint8_t * in) {
  uint8_t first = *(in++);

  if (first < 0xFD) {
    *out += first;
  } else if (first == 0xFD) {
    *out = *in | (*(in + 1) << 8);
  } else if (first == 0xFE) {
    *out = hns_read_u32(out, in, false);
  } else {
    THROW(INVALID_PARAMETER);
    return false;
  }

  return true;
}
