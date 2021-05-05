/**
 * utils.h - helper constants and functions for hns
 * Copyright (c) 2018, Boyma Fahnbulleh (MIT License).
 * https://github.com/handshake-org/ledger-app-hns
 */
#ifndef _HNS_UTILS_H
#define _HNS_UTILS_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "ledger.h"

/**
 * General constants.
 */
#define HNS_APP_NAME "HANDSHAKE"

/**
 * Constants for parsing BIP44 paths.
 */
#define HNS_HARDENED 0x80000000u
#define HNS_BIP44_ACCT_DEPTH 3
#define HNS_BIP44_ADDR_DEPTH 5
#define HNS_BIP44_PURPOSE (HNS_HARDENED | 0x2cu)   // 44'
#define HNS_BIP44_MAINNET (HNS_HARDENED | 0x14e9u) // 5353'
#define HNS_BIP44_TESTNET (HNS_HARDENED | 0x14eau) // 5354'
#define HNS_BIP44_REGTEST (HNS_HARDENED | 0x14ebu) // 5355'
#define HNS_BIP44_SIMNET  (HNS_HARDENED | 0x14ecu) // 5356'
#define HNS_MAX_DEPTH LEDGER_MAX_DEPTH

/**
 * Bitflags for BIP44 path info.
 */
#define HNS_BIP44_NON_ADDR 0x01 // 01
#define HNS_BIP44_NON_STD 0x02  // 10

/**
 * Used in buffer io functions to specify big-endianness.
 */
#define HNS_BE true

/**
 * Used in buffer io functions to specify little-endianness.
 */
#define HNS_LE false

/**
 * Varint
 */
typedef uint32_t hns_varint_t;

/**
 * Helpers
 */

static inline void
bin_to_hex(char *hex, uint8_t *bin, uint8_t len) {
  static uint8_t const lookup[] = "0123456789abcdef";
  uint8_t i;

  for (i = 0; i < len; i++) {
    hex[2*i+0] = lookup[(bin[i]>>4) & 0x0f];
    hex[2*i+1] = lookup[(bin[i]>>0) & 0x0f];
  }

  hex[2*len] = '\0';
}

/**
 * See: https://github.com/LedgerHQ/ledger-app-btc/blob/08c7f5dfc324d39afe3df8b7fb80f5c7c0990f79/src/btchip_bcd.c#L23
 *
 * Note: ledger-app-btc stores output values in big-endian format, while
 * ledger-app-hns uses little-endian. This function converts the amount
 * to big-endian before processing.
 */

#define LOOP_1_SIZE 15
#define LOOP_2_SIZE 6
#define TMP_SIZE (LOOP_1_SIZE + LOOP_2_SIZE)

static inline uint8_t
hex_to_dec(char *dec, uint8_t *hex) {
  uint8_t i,j;
  uint8_t amt[8];
  uint8_t tmp[TMP_SIZE];
  uint8_t ntmp = TMP_SIZE;
  uint8_t smin = ntmp - 2;

  for (i = 0; i < 8; i++)
    amt[i] = hex[8 - 1 - i];

  for (i = 0; i < TMP_SIZE; i++)
    tmp[i] = 0;

  for (i = 0; i < 8; i++) {
    for (j = 0; j < 8; j++) {
      uint8_t k;
      uint16_t shift = (((amt[i] & 0xff) & ((1 << (7 - j)))) != 0) ? 1 : 0;

      for (k = smin; k < ntmp; k++)
        tmp[k] += ((tmp[k] >= 5) ? 3 : 0);

      if (tmp[smin] >= 8)
        smin -= 1;

      for (k = smin; k < ntmp - 1; k++)
        tmp[k] = ((tmp[k] << 1) & 0x0f) | ((tmp[k + 1] >= 8) ? 1 : 0);

      tmp[ntmp - 1] = ((tmp[ntmp - 1] << 1) & 0x0f) | (shift == 1 ? 1 : 0);
    }
  }

  uint8_t non_zero = 0;
  uint8_t offset = 0;
  uint8_t target_offset = 0;

  for (i = 0; i < LOOP_1_SIZE; i++) {
    if (!non_zero && (tmp[offset] == 0)) {
      offset++;
    } else {
      non_zero = 1;
      dec[target_offset++] = tmp[offset++] + '0';
    }
  }

  if (target_offset == 0)
    dec[target_offset++] = '0';

  uint8_t work_offset = offset;
  uint8_t period = 0;

  for (i = 0; i < LOOP_2_SIZE; i++) {
    uint8_t all_zero = 1;

    for (j = i; j < LOOP_2_SIZE; j++) {
      if (tmp[work_offset + j] != 0) {
        all_zero = 0;
        break;
      }
    }

    if (all_zero)
      break;

    if (!period) {
      dec[target_offset++] = '.';
      period = 1;
    }

    dec[target_offset++] = tmp[offset++] + '0';
  }

  dec[target_offset] = '\0';

  return target_offset;
}

/**
 * See: https://github.com/LedgerHQ/ledger-app-btc/blob/08c7f5dfc324d39afe3df8b7fb80f5c7c0990f79/src/btchip_transaction.c#L38
 *
 * Note: the above function accepts big-endian integers.
 * add_u64 accepts little-endian integers.
 */

static inline uint8_t
add_u64(uint8_t *target, uint8_t *a, uint8_t *b) {
  uint8_t carry = 0;
  uint8_t i;

  for (i = 0; i < 8; i++) {
    unsigned short val = a[i] + b[i] + (carry ? 1 : 0);
    carry = (val > 255);
    target[i] = (val & 255);
  }

  return carry;
}

/**
 * See: https://github.com/LedgerHQ/ledger-app-btc/blob/08c7f5dfc324d39afe3df8b7fb80f5c7c0990f79/src/btchip_transaction.c#L51
 *
 * Note: the above function accepts big-endian integers.
 * sub_u64 accepts little-endian integers.
 */

static inline uint8_t
sub_u64(uint8_t *target, uint8_t *a, uint8_t *b) {
  uint8_t borrow = 0;
  uint8_t i;

  for (i = 0; i < 8; i++) {
    unsigned short ta = a[i];
    unsigned short tb = b[i];

    if (borrow) {
      if (ta <= tb) {
        ta += (255 + 1) - 1;
      } else {
        borrow = 0;
        ta--;
      }
    }

    if (ta < tb) {
      borrow = 1;
      ta += 255 + 1;
    }

    target[i] = (uint8_t)(ta - tb);
  }

  return borrow;
}


/**
 * The following functions are buffer io related.
 */

static inline uint8_t
size_varint(hns_varint_t val) {
  if (val < 0xfd)
    return 1;

  if (val <= 0xffff)
    return 3;

  if (val <= 0xffffffff)
    return 5;

  return 0;
}

static inline uint8_t
size_varsize(size_t val) {
  return size_varint((hns_varint_t)val);
}

static inline bool
read_u8(volatile uint8_t **buf, uint16_t *len, uint8_t *u8) {
  if (*len < 1)
    return false;

  *u8 = (*buf)[0];
  *buf += 1;
  *len -= 1;

  return true;
}

static inline bool
read_u16(volatile uint8_t **buf, uint16_t *len, uint16_t *u16, bool be) {
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
read_u32(volatile uint8_t **buf, uint16_t *len, uint32_t *u32, bool be) {
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
read_varint(volatile uint8_t **buf, uint16_t *len, hns_varint_t *varint) {
  if (*len < 1)
    return false;

  uint8_t prefix = (*buf)[0];
  *buf += 1;
  *len -= 1;

  switch (prefix) {
    case 0xff:
      return false;

    case 0xfe: {
      uint32_t v;

      if (!read_u32(buf, len, &v, HNS_LE)) {
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

      if (!read_u16(buf, len, &v, HNS_LE)) {
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

    default:
      *varint = prefix;
      break;
  }

  return true;
}

static inline bool
peek_varint(volatile uint8_t **buf, uint16_t *len, hns_varint_t *varint) {
  if (!read_varint(buf, len, varint))
    return false;

  uint8_t sz = size_varint(*varint);

  *buf -= sz;
  *len += sz;

  return true;
}

static inline bool
read_varsize(volatile uint8_t **buf, uint16_t *len, size_t *val) {
  hns_varint_t v;

  if (!read_varint(buf, len, &v))
    return false;

  *val = v;

  return true;
}

static inline bool
read_bytes(volatile uint8_t **buf, uint16_t *len, volatile uint8_t *out, size_t sz) {
  if (*len < sz)
    return false;

  memmove(out, *buf, sz);

  *buf += sz;
  *len -= sz;

  return true;
}

static inline bool
read_varbytes(
  volatile uint8_t **buf,
  uint16_t *len,
  uint8_t *out,
  size_t out_sz,
  size_t *out_len
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
read_bip44_path(
  volatile uint8_t **buf,
  uint16_t *len,
  uint8_t *depth,
  uint32_t *path,
  uint8_t *info
) {
  if (*len < 1)
    return false;

  if (!read_u8(buf, len, depth))
    return false;

  if (*depth > HNS_MAX_DEPTH) {
    *buf -= 1;
    *len += 1;
    return false;
  }

  /**
   * Returns info regarding whether the parsed path
   * leads to a standard BIP44 address or is non-standard.
   * - Setting the lsb indicates the path is not an address.
   * - Setting the second lsb indicates the path is non-standard.
   */
  *info = 0;

  if (*depth != HNS_BIP44_ADDR_DEPTH)
    *info |= HNS_BIP44_NON_ADDR;

  if (*depth > HNS_BIP44_ADDR_DEPTH)
    *info |= HNS_BIP44_NON_STD;

  uint8_t level;
  uint32_t value;

  for (level = 0; level < *depth; level++) {
    if (!read_u32(buf, len, &value, HNS_BE)) {
      *buf -= 4 + (4 * level);
      *len += 4 + (4 * level);
      return false;
    }

    path[level] = value;

    switch(level) {
      case 0:
        if (value != HNS_BIP44_PURPOSE)
          *info = HNS_BIP44_NON_ADDR | HNS_BIP44_NON_STD;
        break;

      case 1:
        if (value < HNS_BIP44_MAINNET || value > HNS_BIP44_SIMNET)
          *info = HNS_BIP44_NON_ADDR | HNS_BIP44_NON_STD;
        break;

      case 2:
        if (!(value & HNS_HARDENED))
          *info = HNS_BIP44_NON_ADDR | HNS_BIP44_NON_STD;
        break;

      default:
        break;
    }
  }

  return true;
}

static inline size_t
write_u8(volatile uint8_t **buf, uint8_t u8) {
  if (buf == NULL || *buf == NULL)
    return 0;

  (*buf)[0] = u8;
  *buf += 1;

  return 1;
}

static inline size_t
write_u16(volatile uint8_t **buf, uint16_t u16, bool be) {
  if (buf == NULL || *buf == NULL)
    return 0;

  if (be) {
    (*buf)[0] = (uint8_t)(u16 >> 8);
    (*buf)[1] = (uint8_t)u16;
  } else {
    memmove(*buf, &u16, 2);
  }

  *buf += 2;

  return 2;
}

static inline size_t
write_u32(volatile uint8_t **buf, uint32_t u32, bool be) {
  if (buf == NULL || *buf == NULL)
    return 0;

  if (be) {
    (*buf)[0] = (uint8_t)(u32 >> 24);
    (*buf)[1] = (uint8_t)(u32 >> 16);
    (*buf)[2] = (uint8_t)(u32 >> 8);
    (*buf)[3] = (uint8_t)u32;
  } else {
    memmove(*buf, &u32, 4);
  }

  *buf += 4;

  return 4;
}

static inline size_t
write_bytes(
  volatile uint8_t **buf,
  volatile const uint8_t *bytes,
  size_t sz
) {
  if (buf == NULL || *buf == NULL)
    return 0;

  memmove(*buf, bytes, sz);
  *buf += sz;

  return sz;
}

static inline size_t
write_varint(volatile uint8_t **buf, hns_varint_t val) {
  if (buf == NULL || *buf == NULL)
    return 0;

  if (val < 0xfd) {
    write_u8(buf, (uint8_t)val);
    return 1;
  }

  if (val <= 0xffff) {
    write_u8(buf, 0xfd);
    write_u16(buf, (uint16_t)val, HNS_LE);
    return 3;
  }

  if (val <= 0xffffffff) {
    write_u8(buf, 0xfe);
    write_u32(buf, (uint32_t)val, HNS_LE);
    return 5;
  }

  return 0;
}

static inline size_t
write_varsize(volatile uint8_t **buf, size_t val) {
  return write_varint(buf, (uint64_t)val);
}

static inline size_t
write_varbytes(
  volatile uint8_t **buf,
  volatile const uint8_t *bytes,
  size_t sz
) {
  if (buf == NULL || *buf == NULL)
    return 0;

  size_t s = 0;
  s += write_varsize(buf, sz);
  s += write_bytes(buf, bytes, sz);

  return s;
}
#endif
