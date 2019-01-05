#include <stdbool.h>
#include <string.h>
#include "apdu.h"
#include "blake2b.h"
#include "ledger.h"
#include "utils.h"

#define NO 0x00
#define YES 0x01
#define PARSE 0x00
#define SIGN 0x01
#define PREV 0x00
#define VAL 0x01
#define SEQ 0x02
#define SCRIPT_LEN 0x03
#define SCRIPT 0x04
#define OUTS 0x05

static hns_get_public_key_ctx_t * gpub = &global.pub;
static hns_sign_tx_ctx_t * gtx = &global.tx;

static void
bin2hex(uint8_t * hex, uint8_t * bin, uint8_t len) {
  static uint8_t const lookup[] = "0123456789abcdef";
  uint8_t i;

  for (i = 0; i < len; i++) {
    hex[2*i+0] = lookup[(bin[i]>>4) & 0x0f];
    hex[2*i+1] = lookup[(bin[i]>>0) & 0x0f];
  }

  hex[2*len] = '\0';
}

static void
io_exchange_with_code(uint16_t code, uint8_t len) {
  G_io_apdu_buffer[len++] = code >> 8;
  G_io_apdu_buffer[len++] = code & 0xFF;
  io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, len);
}

volatile uint8_t
hns_apdu_get_firmware_version(
  uint8_t p1,
  uint8_t p2,
  uint8_t len,
  volatile uint8_t * buf,
  volatile uint8_t * flags
) {
  if(p1 != 0)
    THROW(HNS_EX_INCORRECT_P1_P2);

  if(p2 != 0)
    THROW(HNS_EX_INCORRECT_P1_P2);

  if(len != 0)
    THROW(HNS_EX_INCORRECT_LENGTH);

  if (!ledger_pin_validated())
    THROW(HNS_EX_SECURITY_STATUS_NOT_SATISFIED);

  buf[0] = HNS_APP_MAJOR_VERSION;
  buf[1] = HNS_APP_MINOR_VERSION;
  buf[2] = HNS_APP_PATCH_VERSION;

  return 3;
}

#define P1_ADDRESS_NO_CONFIRM 0x00
#define P1_PUBKEY_NO_CONFIRM 0x01
#define P1_ADDRESS_CONFIRM 0x02
#define P1_PUBKEY_CONFIRM 0x03
#define P2_MAINNET 0x00
#define P2_TESTNET 0x01
#define P2_SIMNET 0x02
#define P2_REGTEST 0x03

static const bagl_element_t ledger_ui_compare_public_key[] = {
  UI_BACKGROUND(),
  UI_ICON_LEFT(0x01, BAGL_GLYPH_ICON_LEFT),
  UI_ICON_RIGHT(0x02, BAGL_GLYPH_ICON_RIGHT),
  UI_TEXT(0x00, 0, 12, 128, "Compare:"),
  UI_TEXT(0x00, 0, 26, 128, global.pub.part_str),
};

static const bagl_element_t ledger_ui_approve_public_key[] = {
  UI_BACKGROUND(),
  UI_ICON_LEFT(0x00, BAGL_GLYPH_ICON_CROSS),
  UI_ICON_RIGHT(0x00, BAGL_GLYPH_ICON_CHECK),
  UI_TEXT(0x00, 0, 12, 128, global.pub.confirm_str),
};

static unsigned int
ledger_ui_compare_public_key_button(unsigned int mask, unsigned int ctr) {
  switch (mask) {
    case BUTTON_LEFT:
    case BUTTON_EVT_FAST | BUTTON_LEFT: {
      if (gpub->pos > 0)
        gpub->pos--;

      os_memmove(gpub->part_str, gpub->full_str + gpub->pos, 12);
      UX_REDISPLAY();
      break;
    }

    case BUTTON_RIGHT:
    case BUTTON_EVT_FAST | BUTTON_RIGHT: {
      uint8_t size = gpub->gen_addr ? 42 : 66;

      if (gpub->pos < size - 12)
        gpub->pos++;

      os_memmove(gpub->part_str, gpub->full_str + gpub->pos, 12);
      UX_REDISPLAY();
      break;
    }

    case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT: {
      ledger_ui_idle();
      break;
    }
  }

  return 0;
}

static const bagl_element_t *
ledger_ui_compare_public_key_prepro(const bagl_element_t * e) {
  uint8_t size = gpub->gen_addr ? 42 : 66;

  if ((e->component.userid == 1 && gpub->pos == 0) ||
      (e->component.userid == 2 && gpub->pos == size - 12))
    return NULL;

  return e;
}

static unsigned int
ledger_ui_approve_public_key_button(unsigned int mask, unsigned int ctr) {
  switch (mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT: {
      io_exchange_with_code(HNS_SW_USER_REJECTED, 0);
      ledger_ui_idle();
      break;
    }

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT: {
      uint8_t ** out = &G_io_apdu_buffer;
      uint8_t len = 0;

      hns_bip32_node_t * n = &gpub->n;
      ledger_ecdsa_derive(n->path, n->depth, n->chaincode, &n->prv, &n->pub);
      hns_create_p2pkh_addr(gpub->hrp, n->pub.W, gpub->addr);
      len  = write_varbytes(&out, n->pub.W, 33);
      len += write_varbytes(&out, gpub->addr, sizeof(gpub->addr));
      len += write_bytes(&out, n->chaincode, sizeof(n->chaincode));

      if (len != 109)
        THROW(HNS_EX_INCORRECT_WRITE_LEN);

      io_exchange_with_code(HNS_SW_OK, len);

      if (gpub->gen_addr) {
        os_memmove(gpub->full_str, gpub->addr, sizeof(gpub->addr));
        gpub->full_str[sizeof(gpub->addr)] = '\0';
      } else {
        bin2hex(gpub->full_str, n->pub.W, 33);
      }

      os_memmove(gpub->confirm_str, "Compare:", 9);
      os_memmove(gpub->part_str, gpub->full_str, 12);
      gpub->part_str[12] = '\0';
      gpub->pos = 0;

      UX_DISPLAY(ledger_ui_compare_public_key, ledger_ui_compare_public_key_prepro);
      break;
    }
  }

  return 0;
}

volatile uint8_t
hns_apdu_get_public_key(
  uint8_t p1,
  uint8_t p2,
  uint8_t len,
  volatile uint8_t * buf,
  volatile uint8_t * out,
  volatile uint8_t * flags
) {
  switch(p1) {
    case P1_ADDRESS_CONFIRM:
      gpub->confirm = true;
      gpub->gen_addr = true;
      memmove(gpub->confirm_str, "Generate Address?", 18);
      break;

    case P1_ADDRESS_NO_CONFIRM:
      gpub->confirm = false;
      gpub->gen_addr = true;
      break;

    case P1_PUBKEY_CONFIRM:
      gpub->confirm = true;
      memmove(gpub->confirm_str, "Generate Public Key?", 21);
      gpub->gen_addr = false;
      break;

    case P1_PUBKEY_NO_CONFIRM:
      gpub->confirm = false;
      gpub->gen_addr = false;
      break;

    default:
      THROW(HNS_EX_INCORRECT_P1_P2);
      break;
  }

  switch(p2) {
    case P2_MAINNET:
      strcpy(gpub->hrp, "hs");
      break;

    case P2_TESTNET:
      strcpy(gpub->hrp, "ts");
      break;

    case P2_SIMNET:
      strcpy(gpub->hrp, "ss");
      break;

    case P2_REGTEST:
      strcpy(gpub->hrp, "rs");
      break;

    default:
      THROW(HNS_EX_INCORRECT_P1_P2);
      break;
  }

  hns_bip32_node_t * n = &gpub->n;

  if (!ledger_pin_validated())
    THROW(HNS_SW_SECURITY_STATUS_NOT_SATISFIED);

  if (!read_bip32_path(&buf, &len, &n->depth, n->path))
    THROW(HNS_EX_CANNOT_READ_BIP32_PATH);

  if (gpub->confirm) {
    PRINTF("Should confirm on screen\n");
    UX_DISPLAY(ledger_ui_approve_public_key, NULL);
    *flags |= IO_ASYNCH_REPLY;
    return 0;
  }

  ledger_ecdsa_derive(n->path, n->depth, n->chaincode, &n->prv, &n->pub);
  hns_create_p2pkh_addr(gpub->hrp, n->pub.W, gpub->addr);

  len  = write_varbytes(&out, n->pub.W, 33);
  len += write_varbytes(&out, gpub->addr, sizeof(gpub->addr));
  len += write_bytes(&out, n->chaincode, sizeof(n->chaincode));

  if (len != 109)
    THROW(HNS_EX_INCORRECT_WRITE_LEN);

  return len;
}

static inline uint8_t
parse_tx(
  uint8_t * len,
  volatile uint8_t * buf,
  bool init
) {
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

    gtx->parsed = false;

    memset(store, 0, sizeof(store));
    memset(gtx->prevs, 0, sizeof(gtx->prevs));
    memset(gtx->seqs, 0, sizeof(gtx->seqs));
    memset(gtx->outs, 0, sizeof(gtx->outs));
    memset(gtx->hash, 0, sizeof(gtx->hash));

    if (!read_bytes(&buf, len, gtx->ver, sizeof(gtx->ver)))
      THROW(INVALID_PARAMETER);

    if (!read_bytes(&buf, len, gtx->locktime, sizeof(gtx->locktime)))
      THROW(INVALID_PARAMETER);

    if (!read_u8(&buf, len, &gtx->ins_len))
      THROW(INVALID_PARAMETER);

    if (!read_u8(&buf, len, &gtx->outs_len))
      THROW(INVALID_PARAMETER);

    if (!read_varint(&buf, len, &outs_size))
      THROW(INVALID_PARAMETER);
  }

  hns_input_t * in = NULL;

  if (i < gtx->ins_len)
    in = &gtx->ins[i];

  if (in == NULL)
    if (next_item != OUTS)
      THROW(HNS_EX_INVALID_PARSER_STATE);

  if (store_len > 0) {
    memmove(buf + store_len, buf, *len);
    memmove(buf, store, store_len);
    *len += store_len;
  }

  blake2b_ctx * ctx = &gtx->blake;

  for (;;) {
    bool should_continue = false;

    switch(next_item) {
      case PREV: {
        if (!read_bytes(&buf, len, &in->prev, sizeof(in->prev)))
          break;

        next_item++;
      }

      case VAL: {
        if (!read_bytes(&buf, len, &in->val, sizeof(in->val)))
          break;

        next_item++;
      }

      case SEQ: {
        if (!read_bytes(&buf, len, &in->seq, sizeof(in->seq)))
          break;

        next_item++;
      }

      case SCRIPT_LEN: {
        if (!read_varint(&buf, len, &in->script_len))
          break;

        next_item++;
      }

      case SCRIPT: {
        if (!read_bytes(&buf, len, in->script, in->script_len))
          break;

        next_item++;

        if (++i < gtx->ins_len) {
          in = &gtx->ins[i];
          next_item = PREV;
          should_continue = true;
          break;
        }

        blake2b_init(ctx, 32, NULL, 0);

        for (i = 0; i < gtx->ins_len; i++)
          blake2b_update(ctx, gtx->ins[i].prev, sizeof(gtx->ins[i].prev));

        blake2b_final(ctx, gtx->prevs);
        blake2b_init(ctx, 32, NULL, 0);

        for (i = 0; i < gtx->ins_len; i++)
          blake2b_update(ctx, gtx->ins[i].seq, sizeof(gtx->ins[i].seq));

        blake2b_final(ctx, gtx->seqs);
        blake2b_init(ctx, 32, NULL, 0);
      }

      case OUTS: {
        if (*len > 0) {
          blake2b_update(ctx, buf, *len);
          outs_size -= *len;
          buf += *len;
          *len = 0;
        }

        if (outs_size < 0)
          THROW(HNS_EX_INVALID_PARSER_STATE);

        if (outs_size > 0)
          break;

        gtx->parsed = true;
        blake2b_final(ctx, gtx->outs);
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

static inline uint8_t
sign_tx(
  uint8_t * len,
  volatile uint8_t * buf,
  volatile uint8_t * sig
) {
  const uint8_t SIGHASH_ALL[4] = {0x01, 0x00, 0x00, 0x00};
  uint8_t index;
  uint8_t type[4];
  hns_input_t in;
  hns_bip32_node_t n;

  if (!gtx->parsed)
    THROW(HNS_EX_INVALID_PARSER_STATE);

  if (!read_bip32_path(&buf, len, &n.depth, n.path))
    THROW(INVALID_PARAMETER);

  if (!read_u8(&buf, len, &index))
    THROW(INVALID_PARAMETER);

  if (index > gtx->ins_len)
    THROW(INVALID_PARAMETER);

  if (!read_bytes(&buf, len, type, sizeof(type)))
    THROW(INVALID_PARAMETER);

  if (memcmp(type, SIGHASH_ALL, sizeof(type)))
    THROW(INVALID_PARAMETER);

  in = gtx->ins[index];
  blake2b_ctx * ctx = &gtx->blake;
  blake2b_init(ctx, 32, NULL, 0);
  blake2b_update(ctx, gtx->ver, sizeof(gtx->ver));
  blake2b_update(ctx, gtx->prevs, sizeof(gtx->prevs));
  blake2b_update(ctx, gtx->seqs, sizeof(gtx->seqs));
  blake2b_update(ctx, in.prev, sizeof(in.prev));
  blake2b_update(ctx, &in.script_len, size_varint(in.script_len));
  blake2b_update(ctx, in.script, in.script_len);
  blake2b_update(ctx, in.val, sizeof(in.val));
  blake2b_update(ctx, in.seq, sizeof(in.seq));
  blake2b_update(ctx, gtx->outs, sizeof(gtx->outs));
  blake2b_update(ctx, gtx->locktime, sizeof(gtx->locktime));
  blake2b_update(ctx, type, sizeof(type));
  blake2b_final(ctx, gtx->hash);
  ledger_ecdsa_derive(n.path, n.depth, n.chaincode, &n.prv, &n.pub);
  ledger_ecdsa_sign(&n.prv, gtx->hash, sizeof(gtx->hash), sig);

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
    case YES: {
      if (func == SIGN)
        THROW(HNS_EX_INCORRECT_P1_P2);

      if (!ledger_pin_validated())
        THROW(HNS_EX_SECURITY_STATUS_NOT_SATISFIED);

      break;
    }

    case NO:
      break;

    default:
      THROW(HNS_EX_INCORRECT_P1_P2);
      break;
  };

  switch(func) {
    case PARSE:
      len = parse_tx(&len, in, init);
      break;

    case SIGN:
      len = sign_tx(&len, in, out);
      break;

    default:
      THROW(HNS_EX_INCORRECT_P1_P2);
      break;
  }

  return len;
}
