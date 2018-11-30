#ifndef _HNS_UTILS_H
#define _HNS_UTILS_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "ledger.h"

#define HNS_APP_NAME "Handshake"
#define HNS_MAX_PATH 10
#define HNS_MAX_PATH_LEN 4 * HNS_MAX_PATH + 1

// TODO(boymanjor): consider dynamic allocation or different limits
#define HNS_MAX_INPUTS 50
#define HNS_MAX_OUTPUTS 50
#define HNS_MAX_SCRIPT 10000

typedef uint64_t hns_varint_t;

typedef struct hns_prevout_s {
  uint8_t hash[32];
  uint32_t index;
} hns_prevout_t;

typedef struct hns_input_s {
  hns_prevout_t prevout;
  uint64_t val;
  uint32_t seq;
  uint8_t script[HNS_MAX_SCRIPT];
  hns_varint_t script_len;
} hns_input_t;

typedef struct hns_addr_s {
  uint8_t ver;
  uint8_t len;
  uint8_t * data;
} hns_addr_t;

typedef struct hns_covenant_s {
  uint8_t type;
  hns_varint_t len;
  uint8_t * items;
} hns_covenant_t;

typedef struct hns_output_s {
  uint64_t val;
  hns_addr_t addr;
  hns_covenant_t covenant;
} hns_output_t;

typedef struct hns_transaction_s {
  uint32_t ver;
  uint32_t locktime;
  hns_input_t ins[HNS_MAX_INPUTS];
  hns_output_t outs[HNS_MAX_OUTPUTS];
  hns_varint_t ins_len;
  hns_varint_t outs_len;
} hns_transaction_t;

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
read_u64(uint8_t ** buf, uint8_t * len, uint64_t * u64, bool be) {
  if (*len < 8)
    return false;

  if (be) {
    *u64 = 0;
    *u64 |= ((uint64_t) (*buf)[0]) << 56;
    *u64 |= ((uint64_t) (*buf)[1]) << 48;
    *u64 |= ((uint64_t) (*buf)[2]) << 40;
    *u64 |= ((uint64_t) (*buf)[3]) << 32;
    *u64 |= ((uint64_t) (*buf)[4]) << 24;
    *u64 |= ((uint64_t) (*buf)[5]) << 16;
    *u64 |= ((uint64_t) (*buf)[6]) << 8;
    *u64 |=  (uint64_t) (*buf)[7];
  } else {
    memmove(u64, *buf, 8);
  }

  *buf += 8;
  *len -= 8;

  return true;
}

static inline bool
read_varint(uint8_t ** buf, uint8_t * len, uint64_t * varint) {
  uint8_t prefix = *(buf)[0];
  *buf += 1;
  *len -= 1;

  switch (prefix) {
    case 0xff: {
      if(!read_u64(buf, len, varint, true)) {
        *buf -= 1;
        *len += 1;
        return false;
      }

      if (*varint <= 0xffffffff) {
        *buf -= 9;
        *len += 9;
        return false;
      }

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
      uint8_t v;

      if (!read_u8(buf, len, &v)) {
        *buf -= 1;
        *len += 1;
        return false;
      }

      *varint = v;

      break;
    }
  }

  return true;
}

static inline bool
read_varsize(uint8_t ** buf, uint8_t * len, size_t * val) {
  size_t v;

  if (!read_varint(buf, len, (uint64_t *)&v))
    return false;

  // TODO(boymanjor): handle buf rewind
  if ((int32_t)v < 0) {
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

  if (!read_varsize(buf, len, &sz))
    return false;

  if (out_sz < sz)
    return false;

  // TODO(boymanjor): handle buf rewind
  if (!read_bytes(buf, len, out, sz))
    return false;

  *out_len = sz;

  return true;
}

static inline bool
read_prevout(uint8_t ** buf, uint8_t * len, hns_prevout_t * p) {
  if (*len < 36)
    return false;

  if (!read_bytes(buf, len, p->hash, sizeof(p->hash)))
    return false;

  if (!read_u32(buf, len, &p->index, true)) {
    *buf -= 32;
    *len += 32;
    return false;
  }

  return true;
}

static inline bool
read_addr(uint8_t ** buf, uint8_t * len, hns_addr_t * a) {
  // TODO(boymanjor): handle p2sh
  if (*len < 22)
    return false;

  if (!read_u8(buf, len, &a->ver))
    return false;

  if (!read_u8(buf, len, &a->len)) {
    *buf -= 1;
    *len += 1;
    return false;
  }

  if (!read_u8(buf, len, a->data)) {
    *buf -= 2;
    *len += 2;
    return false;
  }

  return true;
}

static inline bool
read_covenant(uint8_t ** buf, uint8_t * len, hns_covenant_t * c) {
  if (*len < 2)
    return false;

  if (!read_u8(buf, len, &c->type))
    return false;

  if (!read_varint(buf, len, &c->len)) {
    *buf -= 1;
    *len += 1;
    return false;
  }

  if (!read_bytes(buf, len, c->items, c->len)) {
    *buf -= 1 + c->len;
    *len += 1 + c->len;
    return false;
  }

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
write_u64(uint8_t ** buf, uint64_t u64, bool be) {
  if (buf == NULL || *buf == NULL)
    return 0;

  if (be) {
    *(buf)[0] = (uint8_t)u64;
    *(buf)[1] = (uint8_t)(u64 >> 8);
    *(buf)[2] = (uint8_t)(u64 >> 16);
    *(buf)[3] = (uint8_t)(u64 >> 24);
    *(buf)[4] = (uint8_t)(u64 >> 32);
    *(buf)[5] = (uint8_t)(u64 >> 40);
    *(buf)[6] = (uint8_t)(u64 >> 48);
    *(buf)[7] = (uint8_t)(u64 >> 56);
  } else {
    memmove(*buf, &u64, 8);
  }

  *buf += 8;

  return 8;
}

static inline size_t
write_bytes(uint8_t ** buf, const uint8_t * bytes, size_t sz) {
  if (buf == NULL || *buf == NULL)
    return 0;

  memmove(*buf, bytes, sz);
  *buf += sz;

  return sz;
}

static inline bool
size_varint(hns_varint_t val) {
  if (val < 0xfd)
    return 1;

  if (val <= 0xffff)
    return 3;

  if (val <= 0xffffffff)
    return 5;

  return 9;
}

static inline size_t
size_varsize(size_t val) {
  return size_varint((hns_varint_t)val);
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

  if (val <= 0xffffffff) {
    write_u8(buf, 0xfe);
    write_u32(buf, (uint32_t)val, true);
    return 5;
  }

  write_u8(buf, 0xff);
  write_u64(buf, (uint64_t)val, true);

  return 9;
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
