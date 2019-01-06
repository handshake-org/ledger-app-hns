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

static hns_sign_tx_ctx_t * gtx = &global.tx;

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
sign_tx(uint8_t * len, volatile uint8_t * buf, volatile uint8_t * sig) {
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
