#include <stdbool.h>
#include <string.h>
#include "apdu.h"
#include "blake2b.h"
#include "ledger.h"
#include "utils.h"

#define P1_CONT 0x00
#define P1_INIT 0x01
#define P2_PARSE 0x00
#define P2_SIGN 0x01

#define PREVOUT 0x00
#define VALUE 0x01
#define SEQUENCE 0x02
#define SCRIPT_LEN 0x03
#define SCRIPT 0x04
#define OUTPUTS 0x05

static hns_apdu_sign_ctx_t * ctx = &global.sign;
static blake2b_ctx sighash;
static blake2b_ctx txid;

static const bagl_element_t ledger_ui_approve_txid[] = {
  LEDGER_UI_BACKGROUND(),
  LEDGER_UI_ICON_LEFT(0x00, BAGL_GLYPH_ICON_CROSS),
  LEDGER_UI_ICON_RIGHT(0x00, BAGL_GLYPH_ICON_CHECK),
  LEDGER_UI_TEXT(0x00, 0, 12, 128, "Correct match?")
};

static const bagl_element_t ledger_ui_compare_txid[] = {
  LEDGER_UI_BACKGROUND(),
  LEDGER_UI_ICON_LEFT(0x01, BAGL_GLYPH_ICON_LEFT),
  LEDGER_UI_ICON_RIGHT(0x02, BAGL_GLYPH_ICON_RIGHT),
  LEDGER_UI_TEXT(0x00, 0, 12, 128, "Confirm txid:"),
  LEDGER_UI_TEXT(0x00, 0, 26, 128, global.sign.part_str)
};

static unsigned int
ledger_ui_approve_txid_button(unsigned int mask, unsigned int ctr) {
  switch (mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT: {
      memset(g_ledger_apdu_exchange_buffer, 0, g_ledger_apdu_exchange_buffer_size);
      ledger_apdu_exchange_with_sw(IO_RETURN_AFTER_TX, 0, HNS_SW_USER_REJECTED);
      ledger_ui_idle();
      break;
    }

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT: {
      uint8_t len = ctx->sig[1] + 2;
      memmove(g_ledger_apdu_exchange_buffer, ctx->sig, len);
      ledger_apdu_exchange_with_sw(IO_RETURN_AFTER_TX, len, HNS_SW_OK);
      ledger_ui_idle();
      break;
    }
  }

  return 0;
}

static unsigned int
ledger_ui_compare_txid_button(unsigned int mask, unsigned int ctr) {
  switch (mask) {
    case BUTTON_LEFT:
    case BUTTON_EVT_FAST | BUTTON_LEFT:
      if (ctx->full_str_pos > 0)
        ctx->full_str_pos--;

      memmove(ctx->part_str, ctx->full_str + ctx->full_str_pos, 12);
      UX_REDISPLAY();
      break;

    case BUTTON_RIGHT:
    case BUTTON_EVT_FAST | BUTTON_RIGHT:
      if (ctx->full_str_pos < ctx->full_str_len - 12)
        ctx->full_str_pos++;

      memmove(ctx->part_str, ctx->full_str + ctx->full_str_pos, 12);
      UX_REDISPLAY();
      break;

    case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT:
      UX_DISPLAY(ledger_ui_approve_txid, NULL);
      break;
  }

  return 0;
}

static const bagl_element_t *
ledger_ui_compare_txid_prepro(const bagl_element_t * e) {
  switch (e->component.userid) {
    case 1:
      return (ctx->full_str_pos == 0) ? NULL : e;

    case 2:
      return (ctx->full_str_pos == ctx->full_str_len - 12) ? NULL : e;

    default:
      return e;
  }
}

static inline uint8_t
parse_tx(uint8_t * len, volatile uint8_t * buf, bool init) {
  static uint8_t i;
  static uint8_t next_item;
  static uint8_t outs_size;
  static uint8_t store_len;
  static uint8_t store[35];

  if (init) {
    i = 0;
    next_item = 0;
    outs_size = 0;
    store_len = 0;

    memset(store, 0, sizeof(store));
    memset(ctx, 0, sizeof(hns_apdu_sign_ctx_t));

    if (!read_bytes(&buf, len, ctx->ver, sizeof(ctx->ver)))
      THROW(INVALID_PARAMETER);

    if (!read_bytes(&buf, len, ctx->locktime, sizeof(ctx->locktime)))
      THROW(INVALID_PARAMETER);

    if (!read_u8(&buf, len, &ctx->ins_len))
      THROW(INVALID_PARAMETER);

    if (!read_u8(&buf, len, &ctx->outs_len))
      THROW(INVALID_PARAMETER);

    if (!read_varint(&buf, len, &outs_size))
      THROW(INVALID_PARAMETER);

    blake2b_init(&txid, 32, NULL, 0);
    blake2b_update(&txid, ctx->ver, sizeof(ctx->ver));
    blake2b_update(&txid, &ctx->ins_len, sizeof(ctx->ins_len));
  }

  hns_input_t * in = NULL;

  if (i < ctx->ins_len)
    in = &ctx->ins[i];

  if (in == NULL)
    if (next_item != OUTPUTS)
      THROW(HNS_EX_INVALID_PARSER_STATE);

  if (store_len > 0) {
    memmove(buf + store_len, buf, *len);
    memmove(buf, store, store_len);
    *len += store_len;
  }

  for (;;) {
    bool should_continue = false;

    switch(next_item) {
      case PREVOUT: {
        if (!read_bytes(&buf, len, &in->prev, sizeof(in->prev)))
          break;

        blake2b_update(&txid, in->prev, sizeof(in->prev));
        next_item++;
      }

      case VALUE: {
        if (!read_bytes(&buf, len, &in->val, sizeof(in->val)))
          break;

        next_item++;
      }

      case SEQUENCE: {
        if (!read_bytes(&buf, len, &in->seq, sizeof(in->seq)))
          break;

        blake2b_update(&txid, in->seq, sizeof(in->seq));
        next_item++;
      }

      case SCRIPT_LEN: {
        if (!read_u8(&buf, len, &in->script_len))
          break;

        next_item++;
      }

      case SCRIPT: {
        if (!read_bytes(&buf, len, in->script, in->script_len))
          break;

        next_item++;

        if (++i < ctx->ins_len) {
          in = &ctx->ins[i];
          next_item = PREVOUT;
          should_continue = true;
          break;
        }

        blake2b_init(&sighash, 32, NULL, 0);

        for (i = 0; i < ctx->ins_len; i++)
          blake2b_update(&sighash, ctx->ins[i].prev, sizeof(ctx->ins[i].prev));

        blake2b_final(&sighash, ctx->prevs);
        blake2b_init(&sighash, 32, NULL, 0);

        for (i = 0; i < ctx->ins_len; i++)
          blake2b_update(&sighash, ctx->ins[i].seq, sizeof(ctx->ins[i].seq));

        blake2b_final(&sighash, ctx->seqs);
        blake2b_init(&sighash, 32, NULL, 0);
        blake2b_update(&txid, &ctx->outs_len, sizeof(ctx->outs_len));
      }

      case OUTPUTS: {
        if (*len > 0) {
          blake2b_update(&txid, buf, *len);
          blake2b_update(&sighash, buf, *len);
          outs_size -= *len;
          buf += *len;
          *len = 0;
        }

        if (outs_size < 0)
          THROW(HNS_EX_INVALID_PARSER_STATE);

        if (outs_size > 0)
          break;

        blake2b_update(&txid, ctx->locktime, sizeof(ctx->locktime));
        blake2b_final(&txid, ctx->txid);
        blake2b_final(&sighash, ctx->outs);
        ctx->parsed = true;
        next_item++;
        break;
      }

      default:
        THROW(HNS_EX_INVALID_PARSER_STATE);
        break;
    }

    if (should_continue)
      continue;

    if (*len < 0)
      THROW(HNS_EX_INVALID_PARSER_STATE);

    if (*len > 0)
      memmove(store, buf, *len);

    store_len = *len;

    break;
  }

  return *len;
};

static const uint8_t SIGHASH_ALL[4] = {0x01, 0x00, 0x00, 0x00};

static inline uint8_t
sign_tx(
  uint8_t * len,
  volatile uint8_t * buf,
  volatile uint8_t * sig,
  volatile uint8_t * flags,
  bool confirm
) {
  uint8_t index;
  uint8_t type[4];
  uint8_t depth;
  uint32_t path[HNS_MAX_PATH];

  if (!ctx->parsed)
    THROW(HNS_EX_INVALID_PARSER_STATE);

  if (!read_bip32_path(&buf, len, &depth, path))
    THROW(INVALID_PARAMETER);

  if (!read_u8(&buf, len, &index))
    THROW(INVALID_PARAMETER);

  if (index > ctx->ins_len)
    THROW(INVALID_PARAMETER);

  if (!read_bytes(&buf, len, type, sizeof(type)))
    THROW(INVALID_PARAMETER);

  if (memcmp(type, SIGHASH_ALL, sizeof(type)))
    THROW(INVALID_PARAMETER);

  uint8_t digest[32];
  hns_input_t in = ctx->ins[index];
  blake2b_init(&sighash, 32, NULL, 0);
  blake2b_update(&sighash, ctx->ver, sizeof(ctx->ver));
  blake2b_update(&sighash, ctx->prevs, sizeof(ctx->prevs));
  blake2b_update(&sighash, ctx->seqs, sizeof(ctx->seqs));
  blake2b_update(&sighash, in.prev, sizeof(in.prev));
  blake2b_update(&sighash, &in.script_len, sizeof(in.script_len));
  blake2b_update(&sighash, in.script, in.script_len);
  blake2b_update(&sighash, in.val, sizeof(in.val));
  blake2b_update(&sighash, in.seq, sizeof(in.seq));
  blake2b_update(&sighash, ctx->outs, sizeof(ctx->outs));
  blake2b_update(&sighash, ctx->locktime, sizeof(ctx->locktime));
  blake2b_update(&sighash, type, sizeof(type));
  blake2b_final(&sighash, digest);
  ledger_ecdsa_sign(path, depth, digest, sizeof(digest), sig);

  if (confirm) {
    hns_bin2hex(ctx->full_str, ctx->txid, sizeof(ctx->txid));
    ctx->full_str_pos = 0;
    ctx->full_str_len = 64;
    ctx->full_str[ctx->full_str_len] = '\0';

    memmove(ctx->part_str, ctx->full_str, 12);
    ctx->part_str[12] = '\0';

    memmove(ctx->sig, sig, sig[1] + 2);
    UX_DISPLAY(ledger_ui_compare_txid, ledger_ui_compare_txid_prepro);
    *flags |= IO_ASYNCH_REPLY;
    return 0;
  }

  return sig[1] + 2;
}

volatile uint8_t
hns_apdu_sign_tx(
  uint8_t init,
  uint8_t func,
  uint8_t len,
  volatile uint8_t * in,
  volatile uint8_t * out,
  volatile uint8_t * flags
) {
  switch(init) {
    case P1_INIT:
      if (!ledger_pin_validated())
        THROW(HNS_EX_SECURITY_STATUS_NOT_SATISFIED);

    case P1_CONT:
      break;

    default:
      THROW(HNS_EX_INCORRECT_P1_P2);
      break;
  };

  switch(func) {
    case P2_PARSE:
      len = parse_tx(&len, in, init);
      break;

    case P2_SIGN:
      len = sign_tx(&len, in, out, flags, init);
      break;

    default:
      THROW(HNS_EX_INCORRECT_P1_P2);
      break;
  }

  return len;
}