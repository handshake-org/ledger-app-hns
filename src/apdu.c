#include <stdbool.h>
#include <string.h>
#include "apdu.h"
#include "blake2b.h"
#include "ledger.h"
#include "segwit-addr.h"
#include "utils.h"

volatile uint8_t
hns_apdu_get_firmware_version(
  volatile uint8_t * buf,
  volatile uint8_t * flags
) {
  uint8_t p1 = buf[HNS_OFFSET_P1];
  uint8_t p2 = buf[HNS_OFFSET_P2];
  size_t lc = buf[HNS_OFFSET_LC];

  if(p1 != 0)
    THROW(HNS_EX_INCORRECT_P1_P2);

  if(p2 != 0)
    THROW(HNS_EX_INCORRECT_P1_P2);

  if(lc != 0)
    THROW(HNS_EX_INCORRECT_LENGTH);

  if (!ledger_pin_validated())
    THROW(HNS_EX_SECURITY_STATUS_NOT_SATISFIED);

  buf[0] = HNS_APP_MAJOR_VERSION;
  buf[1] = HNS_APP_MINOR_VERSION;
  buf[2] = HNS_APP_PATCH_VERSION;

  return 3;
}

volatile uint8_t
hns_apdu_get_wallet_public_key(
  volatile uint8_t * buf,
  volatile uint8_t * flags
) {
  uint8_t p1 = buf[HNS_OFFSET_P1];
  uint8_t p2 = buf[HNS_OFFSET_P2];
  size_t lc = buf[HNS_OFFSET_LC];
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

  if (lc < 1 || lc > HNS_MAX_PATH_LEN)
    THROW(HNS_SW_INCORRECT_LENGTH);

  if (!ledger_pin_validated())
    THROW(HNS_SW_SECURITY_STATUS_NOT_SATISFIED);

  uint8_t depth;

  if (!read_u8(cdata, &lc, &depth))
    // TODO(boymanjor): use descriptive exception
    THROW(INVALID_PARAMETER);

  if (depth > HNS_MAX_PATH)
    THROW(INVALID_PARAMETER);

  uint32_t path[depth];
  uint8_t i;

  for (i = 0; i < depth; i++) {
    if (!read_u32(cdata, &lc, &path[i], true))
      THROW(INVALID_PARAMETER);
  }

  ledger_bip32_node_t n;
  ledger_bip32_node_derive(&n, path, depth, hrp);

  uint8_t * out = buf;
  uint8_t len = 0;

  len += write_varbytes(out, n.pub, sizeof(n.pub));
  len += write_varbytes(out, n.addr, sizeof(n.addr));
  len += write_bytes(out, n.code, sizeof(n.code));

  return out - buf;
}

static inline void
tx_parse(
  hns_transaction_ctx_t * ctx,
  uint8_t * buf,
  size_t * len
) {
  static int in_pos = 0;
  static int out_pos = 0;
  static int parse_pos = 0;
  static int parse_buf_len = 0;
  static uint8_t * parse_buf[2 * 336]; // Double the size of G_apdu_io_buffer

  hns_input_t * in = NULL;
  hns_output_t * out = NULL;

  if (parse_pos >= 0 && parse_pos < 4) {
    if (in_pos < ctx->ins_len)
      in = &ctx->ins[in_pos];
  }

  if (parse_pos >= 4 && parse_pos < 8) {
    if (out_pos < ctx->outs_len)
      out = &ctx->outs[out_pos];
  }

  // TODO(boymanjor): THROW(INVALID_PARSER_STATE)
  if (in == NULL && out == NULL)
    THROW(INVALID_PARAMETER);

  if (parse_buf_len == 0) {
    memmove(parse_buf, buf, *len);
  } else {
    memmove(parse_buf + parse_buf_len, buf, *len);
    *len += parse_buf_len;
  }

  for (;;) {
    int rewind = 0;
    bool should_continue = false;

    switch(parse_pos) {
      case 0:
        if (!read_prevout(parse_buf, len, &in->prevout)) {
          parse_pos = 0;
          break;
        }

        rewind += sizeof(in->prevout.hash) + sizeof(in->prevout.index);

      case 1:
        if (!read_u64(parse_buf, len, &in->val, true)) {
          parse_pos = 1;
          break;
        }

        rewind += sizeof(in->val);

      case 2:
        if (!read_u32(parse_buf, len, &in->seq, true)) {
          parse_pos = 2;
          break;
        }

        rewind += sizeof(in->seq);

      case 3:
        if (!read_varint(parse_buf, len, &in->script_len)) {
          parse_pos = 3;
          break;
        }

        rewind += size_varint(in->script_len);

      case 4:
        if (!read_bytes(parse_buf, len, in->script, in->script_len)) {
          parse_pos = 4;
          break;
        }

        rewind += in->script_len;

        if (++in_pos < ctx->ins_len) {
          in = &ctx->ins[in_pos];
          parse_pos = 0;
          should_continue = true;
          break;
        }

      case 5:
        if (!read_u64(parse_buf, len, &out->val, true)) {
          parse_pos = 5;
          break;
        }

        rewind += sizeof(out->val);

      case 6:
        if (!read_addr(parse_buf, len, &out->addr)) {
          parse_pos = 6;
          break;
        }

        rewind += 2 + out->addr.len;

      case 7:
        if (!read_covenant(parse_buf, len, &out->covenant)) {
          parse_pos = 7;
          break;
        }

        rewind += 1 + size_varint(out->covenant.len) + out->covenant.len;

        if (++out_pos < ctx->outs_len) {
          out = &ctx->outs[out_pos];
          parse_pos = 5;
		  should_continue = true;
          break;
        }

        parse_pos = 8;
        break;
    }

    if (should_continue)
      continue;

    if (*len > 0) {
      memmove(parse_buf - rewind, parse_buf, *len);
    }

    // TODO(boymanjor): THROW(INVALID_PARSER_STATE)
    if (*len < 0) {
      THROW(EXCEPTION);
    }

    parse_buf -= rewind;
    parse_buf_len = *len;
    break;
  }
}

static inline void
tx_sign(
  hns_transaction_ctx_t * ctx,
  uint8_t * buf,
  size_t * len
) {
}

volatile uint8_t
hns_apdu_tx_sign(volatile uint8_t * buf, volatile uint8_t * flags) {
  static hns_transaction_ctx_t ctx;
  uint8_t p1 = buf[HNS_OFFSET_P1];
  uint8_t p2 = buf[HNS_OFFSET_P2];
  size_t lc = buf[HNS_OFFSET_LC];
  uint8_t * cdata = buf + HNS_OFFSET_CDATA;

  switch(p1) {
    case 0x00:
      break;

    case 0x01: {
      if (!ledger_pin_validated())
        THROW(HNS_EX_SECURITY_STATUS_NOT_SATISFIED);

      memset(&ctx, 0, sizeof(ctx));
      read_u32(cdata, &lc, &ctx.ver, true);
      read_u32(cdata, &lc, &ctx.locktime, true);
      read_varint(cdata, &lc, &ctx.ins_len);
      read_varint(cdata, &lc, &ctx.outs_len);

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
      tx_parse(&ctx, cdata, &lc);
      break;

    case 0x01:
      tx_sign(&ctx, cdata, &lc);
      break;

    default:
      THROW(HNS_EX_INCORRECT_P1_P2);
      break;
  }

  return 0;
}
