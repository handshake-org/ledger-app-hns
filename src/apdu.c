#include <stdbool.h>
#include <string.h>
#include "apdu.h"
#include "blake2b.h"
#include "ledger.h"
#include "segwit-addr.h"
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

static hns_tx_state_t * gtx = &global.tx_state;

static inline void
addr_create_p2pkh(char *, uint8_t *, uint8_t *);

static inline uint8_t
tx_parse(uint8_t *, volatile uint8_t *, bool);

static inline uint8_t
tx_sign(uint8_t *, volatile uint8_t *, volatile uint8_t *);

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

volatile uint8_t
hns_apdu_get_wallet_public_key(
  uint8_t p1,
  uint8_t p2,
  uint8_t len,
  volatile uint8_t * buf,
  volatile uint8_t * out,
  volatile uint8_t * flags
) {
  char hrp[2];
  uint8_t addr[42];
  uint8_t depth;
  uint32_t path[HNS_MAX_PATH];
  ledger_bip32_node_t n;

  switch(p1) {
    case 0x00:
    case 0x01:
      // TODO: display addr
      break;
    default:
      THROW(HNS_EX_INCORRECT_P1_P2);
  }

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

  if (!read_bip32_path(&buf, &len, &depth, path))
    THROW(HNS_EX_CANNOT_READ_BIP32_PATH);

  ledger_bip32_node_derive(&n, path, depth);
  addr_create_p2pkh(hrp, n.pub.W, addr);

  len  = write_varbytes(&out, n.pub.W, 33);
  len += write_varbytes(&out, addr, sizeof(addr));
  len += write_bytes(&out, n.code, sizeof(n.code));

  if (len != 109)
    THROW(HNS_EX_INCORRECT_WRITE_LEN);

  return len;
}

volatile uint8_t
hns_apdu_tx_sign(
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
      len = tx_parse(&len, in, init);
      break;

    case SIGN:
      len = tx_sign(&len, in, out);
      break;

    default:
      THROW(HNS_EX_INCORRECT_P1_P2);
      break;
  }

  return len;
}

static inline void
addr_create_p2pkh(char * hrp, uint8_t * pub, uint8_t * addr) {
  uint8_t pkh[20];

  if (blake2b(pkh, 20, NULL, 0, pub, 33))
    THROW(EXCEPTION);

  if (!segwit_addr_encode(addr, hrp, 0, pkh, 20))
    THROW(EXCEPTION);
}

static inline uint8_t
tx_parse(
  uint8_t * len,
  volatile uint8_t * buf,
  bool init
) {
  static uint8_t i;
  static uint8_t next_item;
  static uint8_t outs_size;
  static uint8_t store_len;
  static uint8_t store[35];

  gtx->parsed = false;

  if (init) {
    i = 0;
    next_item = 0;
    store_len = 0;

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
tx_sign(
  uint8_t * len,
  volatile uint8_t * buf,
  volatile uint8_t * sig
) {
  const uint8_t SIGHASH_ALL[4] = {0x01, 0x00, 0x00, 0x00};
  uint8_t type[4];
  uint8_t index;
  uint8_t depth;
  uint32_t path[HNS_MAX_PATH];
  ledger_bip32_node_t n;
  hns_input_t in;

  if (!gtx->parsed)
    THROW(HNS_EX_INVALID_PARSER_STATE);

  if (!read_bip32_path(&buf, len, &depth, path))
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
  ledger_bip32_node_derive(&n, path, depth);
  ledger_ecdsa_sign(&n.prv, gtx->hash, sizeof(gtx->hash), sig);

  return sig[1] + 2;
}
