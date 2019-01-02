#ifndef _HNS_UTILS_H
#define _HNS_UTILS_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "apdu.h"
#include "blake2b.h"
#include "ledger.h"

#define HNS_APP_NAME "Handshake"
#define HNS_MAX_PATH 10
#define HNS_MAX_PATH_LEN 4 * HNS_MAX_PATH + 1

#define HNS_MAX_INPUTS 5
#define HNS_MAX_OUTPUTS 5
#define HNS_MAX_SCRIPT 25

typedef uint32_t hns_varint_t;

typedef struct hns_input_s {
  uint8_t prevout[36];
  uint8_t val[8];
  uint8_t seq[4];
  uint8_t script[HNS_MAX_SCRIPT];
  hns_varint_t script_len;
} hns_input_t;

// TODO: handle more addr & covenant data
typedef struct hns_output_s {
  uint8_t val[8];
  uint8_t addr_data[24];
  uint8_t covenant_data[20];
  uint8_t addr_len;
  hns_varint_t covenant_len;
} hns_output_t;

typedef struct hns_transaction_s {
  bool init;
  blake2b_ctx blake;
  uint8_t ins_len;
  uint8_t outs_len;
  uint8_t parse_pos;
  uint8_t in_pos;
  uint8_t out_pos;
  uint8_t store_len;
  uint8_t store[20];
  uint8_t p_hash[32];
  uint8_t s_hash[32];
  uint8_t o_hash[32];
  uint8_t tx_hash[32];
  uint8_t ver[4];
  uint8_t locktime[4];
  hns_input_t ins[HNS_MAX_INPUTS];
  hns_output_t outs[HNS_MAX_OUTPUTS];
} hns_transaction_t;

typedef union {
  hns_transaction_t tx;
} global_ctx_t;

extern global_ctx_t global;

static inline bool
size_varint(hns_varint_t val) {
  if (val < 0xfd)
    return 1;

  if (val <= 0xffff)
    return 3;

  return 5;
}

static inline size_t
size_varsize(size_t val) {
  return size_varint((hns_varint_t)val);
}

static inline bool
read_u8(uint8_t ** buf, uint8_t * len, uint8_t * u8) {
  if (*len < 1)
    return false;

  *u8 = (*buf)[0];
  *buf += 1;
  *len -= 1;

  return true;
}

static inline bool
read_u16(uint8_t ** buf, uint8_t * len, uint16_t * u16, bool be) {
  if (*len < 2)
    return false;

  if (be) {
    *u16 = 0;
    *u16 |= ((uint16_t) (*buf)[0]) << 8;
    *u16 |=  (uint16_t) (*buf)[1];
  } else {
    memmove(u16, *buf, 2);
  }

  *buf += 2;
  *len -= 2;

  return true;
}

static inline bool
read_u32(uint8_t ** buf, uint8_t * len, uint32_t * u32, bool be) {
  if (*len < 4)
    return false;

  if (be) {
    *u32 = 0;
    *u32 |= ((uint32_t) (*buf)[0]) << 24;
    *u32 |= ((uint32_t) (*buf)[1]) << 16;
    *u32 |= ((uint32_t) (*buf)[2]) << 8;
    *u32 |=  (uint32_t) (*buf)[3];
  } else {
    memmove(u32, *buf, 4);
  }

  *buf += 4;
  *len -= 4;

  return true;
}

static inline bool
read_varint(uint8_t ** buf, uint8_t * len, hns_varint_t * varint) {
  uint8_t prefix = *(buf)[0];
  *buf += 1;
  *len -= 1;

  switch (prefix) {
    case 0xff: {
      THROW(HNS_EX_U64_NOT_SUPPORTED);
      break;
    }

    case 0xfe: {
      uint32_t v;

      if (!read_u32(buf, len, &v, true)) {
        *buf -= 1;
        *len += 1;
        return false;
      }

      if (v <= 0xffff) {
        *buf -= 5;
        *len += 5;
        return false;
      }

      *varint = v;

      break;
    }

    case 0xfd: {
      uint16_t v;

      if (!read_u16(buf, len, &v, true)) {
        *buf -= 1;
        *len += 1;
        return false;
      }

      if (v < 0xfd) {
        *buf -= 3;
        *len += 3;
        return false;
      }

      *varint = v;

      break;
    }

    default: {
      *varint = prefix;
      break;
    }
  }

  return true;
}

static inline bool
read_varsize(uint8_t ** buf, uint8_t * len, size_t * val) {
  hns_varint_t v;

  if (!read_varint(buf, len, &v))
    return false;

  if (v < 0) {
    uint8_t sz = size_varint(v);

    buf -= sz;
    len += sz;

    return false;
  }

  *val = v;

  return true;
}

static inline bool
read_bytes(uint8_t ** buf, uint8_t * len, uint8_t * out, size_t sz) {
  if (*len < sz)
    return false;

  memmove(out, *buf, sz);

  *buf += sz;
  *len -= sz;

  return true;
}

static inline bool
read_varbytes(
  uint8_t ** buf,
  uint8_t * len,
  uint8_t * out,
  size_t out_sz,
  size_t * out_len
) {
  size_t sz;
  size_t offset;

  if (!read_varsize(buf, len, &sz))
    return false;

  offset = size_varsize(sz);

  if (out_sz < sz) {
    *buf -= offset;
    *len += offset;
    return false;
  }

  if (!read_bytes(buf, len, out, sz)) {
    *buf -= offset;
    *len += offset;
    return false;
  }

  *out_len = sz;

  return true;
}

static inline bool
read_bip32_path(
  uint8_t ** buf,
  uint8_t * len,
  uint8_t * depth,
  uint32_t * path
) {
  if (*len < 1 || *len > HNS_MAX_PATH_LEN)
    return false;

  if (!read_u8(buf, len, depth))
    return false;

  if (*depth > HNS_MAX_PATH) {
    *buf -= 1;
    *len += 1;
    return false;
  }

  uint8_t i;

  for (i = 0; i < *depth; i++) {
    if (!read_u32(buf, len, &path[i], true)) {
      *buf -= 4 + (4 * i);
      *len += 4 + (4 * i);
      return false;
    }
  }

  return true;
}

static inline size_t
write_u8(uint8_t ** buf, uint8_t u8) {
  if (buf == NULL || *buf == NULL)
    return 0;

  *(buf)[0] = u8;
  *(buf) += 1;

  return 1;
}

static inline size_t
write_u16(uint8_t ** buf, uint16_t u16, bool be) {
  if (buf == NULL || *buf == NULL)
    return 0;

  if (be) {
    *(buf)[0] = (uint8_t)u16;
    *(buf)[1] = (uint8_t)(u16 >> 8);
  } else {
    memmove(*buf, &u16, 2);
  }

  *buf += 2;

  return 2;
}

static inline size_t
write_u32(uint8_t ** buf, uint32_t u32, bool be) {
  if (buf == NULL || *buf == NULL)
    return 0;

  if (be) {
    *(buf)[0] = (uint8_t)u32;
    *(buf)[1] = (uint8_t)(u32 >> 8);
    *(buf)[2] = (uint8_t)(u32 >> 16);
    *(buf)[3] = (uint8_t)(u32 >> 24);
  } else {
    memmove(*buf, &u32, 4);
  }

  *buf += 4;

  return 4;
}

static inline size_t
write_bytes(uint8_t ** buf, const uint8_t * bytes, size_t sz) {
  if (buf == NULL || *buf == NULL)
    return 0;

  memmove(*buf, bytes, sz);
  *buf += sz;

  return sz;
}

static inline size_t
write_varint(uint8_t ** buf, hns_varint_t val) {
  if (buf == NULL || *buf == NULL)
    return 0;

  if (val < 0xfd) {
    write_u8(buf, (uint8_t)val);
    return 1;
  }

  if (val <= 0xffff) {
    write_u8(buf, 0xfd);
    write_u16(buf, (uint16_t)val, true);
    return 3;
  }

  write_u8(buf, 0xfe);
  write_u32(buf, (uint32_t)val, true);
  return 5;
}

static inline size_t
write_varsize(uint8_t ** buf, size_t val) {
  return write_varint(buf, (uint64_t)val);
}

static inline size_t
write_varbytes(uint8_t ** buf, const uint8_t * bytes, size_t sz) {
  if (buf == NULL || *buf == NULL)
    return 0;

  size_t s = 0;
  s += write_varsize(buf, sz);
  s += write_bytes(buf, bytes, sz);

  return s;
}
#endif
