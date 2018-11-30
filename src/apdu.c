#include <stdbool.h>
#include <string.h>
#include "apdu.h"
#include "blake2b.h"
#include "ledger.h"
#include "segwit-addr.h"
#include "utils.h"

static inline void
addr_create_p2pkh(char *, uint8_t *, uint8_t *);

static inline void
tx_parse(hns_transaction_t *, uint8_t *, uint8_t *);

static inline void
tx_sign(hns_transaction_t *, uint8_t *, uint8_t *);

volatile uint8_t
hns_apdu_get_firmware_version(
  volatile uint8_t * buf,
  volatile uint8_t * flags
) {
  uint8_t p1 = buf[HNS_OFFSET_P1];
  uint8_t p2 = buf[HNS_OFFSET_P2];
  uint8_t lc = buf[HNS_OFFSET_LC];

  if(p1 != 0)
    THROW(HNS_EX_INCORRECT_P1_P2);

  if(p2 != 0)
    THROW(HNS_EX_INCORRECT_P1_P2);

  if(lc != 0)
    THROW(HNS_EX_INCORRECT_LENGTH);

  if (!ledger_pin_validated())
    THROW(HNS_EX_SECURITY_STATUS_NOT_SATISFIED);

  uint8_t len = 0;

  len += write_u8(&buf, HNS_APP_MAJOR_VERSION);
  len += write_u8(&buf, HNS_APP_MINOR_VERSION);
  len += write_u8(&buf, HNS_APP_PATCH_VERSION);

  // TODO(boymanjor): better exception
  if (len != 3)
    THROW(EXCEPTION);

  return len;
}

volatile uint8_t
hns_apdu_get_wallet_public_key(
  volatile uint8_t * buf,
  volatile uint8_t * flags
) {
  uint8_t p1 = buf[HNS_OFFSET_P1];
  uint8_t p2 = buf[HNS_OFFSET_P2];
  uint8_t lc = buf[HNS_OFFSET_LC];
  uint8_t * cdata = buf + HNS_OFFSET_CDATA;

  switch(p1) {
    case 0x00:
    case 0x01:
      // TODO(boymanjor): display addr
      break;
    default:
      THROW(HNS_EX_INCORRECT_P1_P2);
  }

  char hrp[2];

  switch(p2) {
    case 0:
      strcpy(hrp, "hs");
    case 1:
      strcpy(hrp, "ts");
    case 2:
      strcpy(hrp, "ss");
    case 3:
      strcpy(hrp, "rs");
      break;
    default:
      THROW(HNS_EX_INCORRECT_P1_P2);
  }

  if (!ledger_pin_validated())
    THROW(HNS_SW_SECURITY_STATUS_NOT_SATISFIED);

  uint8_t depth;
  uint32_t path[HNS_MAX_PATH];

  // TODO(boymanjor): use descriptive exception
  if (!read_bip32_path(&cdata, &lc, &depth, path))
    THROW(INVALID_PARAMETER);

  uint8_t addr[42];
  ledger_bip32_node_t n;
  ledger_bip32_node_derive(&n, path, depth);
  addr_create_p2pkh(hrp, n.pub, &addr);

  uint8_t len = 0;
  len += write_varbytes(&buf, n.pub, sizeof(n.pub));
  len += write_varbytes(&buf, addr, sizeof(addr));
  len += write_bytes(&buf, n.code, sizeof(n.code));

  // TODO(boymanjor): use descriptive exception
  if (len != 109)
    THROW(EXCEPTION);

  return len;
}

volatile uint8_t
hns_apdu_tx_sign(volatile uint8_t * buf, volatile uint8_t * flags) {
  static hns_transaction_t tx;
  uint8_t p1 = buf[HNS_OFFSET_P1];
  uint8_t p2 = buf[HNS_OFFSET_P2];
  uint8_t lc = buf[HNS_OFFSET_LC];
  uint8_t * cdata = buf + HNS_OFFSET_CDATA;

  switch(p1) {
    case 0x00:
      break;

    case 0x01: {
      if (!ledger_pin_validated())
        THROW(HNS_EX_SECURITY_STATUS_NOT_SATISFIED);

      memset(&tx, 0, sizeof(tx));
      read_u32(&cdata, &lc, &tx.ver, true);
      read_u32(&cdata, &lc, &tx.locktime, true);
      read_varint(&cdata, &lc, &tx.ins_len);
      read_varint(&cdata, &lc, &tx.outs_len);

      if (cdata - lc != buf + HNS_OFFSET_CDATA)
        THROW(HNS_EX_INCORRECT_LENGTH);

      return 0;
    }

    default:
      THROW(HNS_EX_INCORRECT_P1_P2);
      break;
  };

  switch(p2) {
    case 0x00:
      tx_parse(&tx, cdata, &lc);
      break;

    case 0x01:
      tx_sign(&tx, cdata, &lc);
      break;

    default:
      THROW(HNS_EX_INCORRECT_P1_P2);
      break;
  }

  return 0;
}

static inline void
addr_create_p2pkh(char * hrp, uint8_t * pub, uint8_t * addr) {
  uint8_t pkh[20];

  if (blake2b(pkh, 20, NULL, 0, pub, 33))
    THROW(EXCEPTION);

  if (!segwit_addr_encode(addr, hrp, 0, pkh, 20))
    THROW(EXCEPTION);
}

static inline void
tx_parse(
  hns_transaction_t * tx,
  uint8_t * buf,
  uint8_t * len
) {
  static int in_pos = 0;
  static int out_pos = 0;
  static int parse_pos = 0;
  static int store_len = 0;
  static uint8_t store[2 * 336]; // Double the size of G_apdu_io_buffer

  hns_input_t * in = NULL;
  hns_output_t * out = NULL;

  if (parse_pos >= 0 && parse_pos < 4) {
    if (in_pos < tx->ins_len)
      in = &tx->ins[in_pos];
  }

  if (parse_pos >= 4 && parse_pos < 8) {
    if (out_pos < tx->outs_len)
      out = &tx->outs[out_pos];
  }

  // TODO(boymanjor): THROW(INVALID_PARSER_STATE)
  if (in == NULL && out == NULL)
    THROW(INVALID_PARAMETER);

  if (store_len == 0) {
    memmove(store, buf, *len);
  } else {
    memmove(store + store_len, buf, *len);
    *len += store_len;
  }

  buf = store;

  for (;;) {
    bool should_continue = false;

    switch(parse_pos) {
      case 0:
        if (!read_prevout(&buf, len, &in->prevout)) {
          parse_pos = 0;
          break;
        }

      case 1:
        if (!read_u64(&buf, len, &in->val, true)) {
          parse_pos = 1;
          break;
        }

      case 2:
        if (!read_u32(&buf, len, &in->seq, true)) {
          parse_pos = 2;
          break;
        }

      case 3:
        if (!read_varint(&buf, len, &in->script_len)) {
          parse_pos = 3;
          break;
        }

      case 4:
        if (!read_bytes(&buf, len, in->script, in->script_len)) {
          parse_pos = 4;
          break;
        }

        if (++in_pos < tx->ins_len) {
          in = &tx->ins[in_pos];
          parse_pos = 0;
          should_continue = true;
          break;
        }

      case 5:
        if (!read_u64(&buf, len, &out->val, true)) {
          parse_pos = 5;
          break;
        }

      case 6:
        if (!read_addr(&buf, len, &out->addr)) {
          parse_pos = 6;
          break;
        }

      case 7:
        if (!read_covenant(&buf, len, &out->covenant)) {
          parse_pos = 7;
          break;
        }

        if (++out_pos < tx->outs_len) {
          out = &tx->outs[out_pos];
          parse_pos = 5;
          should_continue = true;
          break;
        }

        parse_pos = 8;
        break;
    }

    if (should_continue)
      continue;

    if (*len > 0)
      memmove(store, buf, *len);

    // TODO(boymanjor): THROW(INVALID_PARSER_STATE)
    if (*len < 0)
      THROW(EXCEPTION);

    store_len = *len;
    break;
  }
}

static inline void
tx_sign(
  hns_transaction_t * tx,
  uint8_t * buf,
  uint8_t * len
) {
}
