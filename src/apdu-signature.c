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
#define OUTPUTS 0x03

typedef struct hns_input_s {
  uint8_t prev[36];
  uint8_t val[8];
  uint8_t seq[4];
} hns_input_t;

typedef struct hns_apdu_signature_ctx_t {
  bool sign_ready;
  bool skip_input;
  hns_input_t ins[HNS_MAX_INPUTS];
  uint8_t ins_len;
  uint8_t outs_len;
  uint8_t ver[4];
  uint8_t prevs[32];
  uint8_t seqs[32];
  uint8_t outs[32];
  uint8_t txid[32];
  uint8_t locktime[4];
} hns_apdu_signature_ctx_t;

static hns_apdu_signature_ctx_t ctx;
static blake2b_ctx hash;
static blake2b_ctx txid;

static inline uint16_t
parse(uint16_t *len, volatile uint8_t *buf, bool init) {
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
    memset(&ctx, 0, sizeof(hns_apdu_signature_ctx_t));

    ledger_apdu_cache_clear();

    if (!read_bytes(&buf, len, ctx.ver, sizeof(ctx.ver)))
      THROW(HNS_CANNOT_READ_TX_VERSION);

    if (!read_bytes(&buf, len, ctx.locktime, sizeof(ctx.locktime)))
      THROW(HNS_CANNOT_READ_TX_LOCKTIME);

    if (!read_u8(&buf, len, &ctx.ins_len))
      THROW(HNS_CANNOT_READ_INPUTS_LEN);

    if (ctx.ins_len > HNS_MAX_INPUTS)
      THROW(HNS_INCORRECT_INPUTS_LEN);

    if (!read_u8(&buf, len, &ctx.outs_len))
      THROW(HNS_CANNOT_READ_OUTPUTS_LEN);

    if (!read_varint(&buf, len, &outs_size))
      THROW(HNS_CANNOT_READ_OUTPUTS_SIZE);

    blake2b_init(&txid, 32, NULL, 0);
    blake2b_update(&txid, ctx.ver, sizeof(ctx.ver));
    blake2b_update(&txid, &ctx.ins_len, sizeof(ctx.ins_len));
  }

  hns_input_t *in = NULL;

  if (i < ctx.ins_len)
    in = &ctx.ins[i];

  if (in == NULL)
    if (next_item != OUTPUTS)
      THROW(HNS_INCORRECT_PARSER_STATE);

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

        if (++i < ctx.ins_len) {
          in = &ctx.ins[i];
          next_item = PREVOUT;
          should_continue = true;
          break;
        }

        blake2b_init(&hash, 32, NULL, 0);

        for (i = 0; i < ctx.ins_len; i++)
          blake2b_update(&hash, ctx.ins[i].prev, sizeof(ctx.ins[i].prev));

        blake2b_final(&hash, ctx.prevs);
        blake2b_init(&hash, 32, NULL, 0);

        for (i = 0; i < ctx.ins_len; i++)
          blake2b_update(&hash, ctx.ins[i].seq, sizeof(ctx.ins[i].seq));

        blake2b_final(&hash, ctx.seqs);
        blake2b_init(&hash, 32, NULL, 0);
        blake2b_update(&txid, &ctx.outs_len, sizeof(ctx.outs_len));
      }

      case OUTPUTS: {
        if (*len > 0) {
          blake2b_update(&txid, buf, *len);
          blake2b_update(&hash, buf, *len);
          outs_size -= *len;
          buf += *len;
          *len = 0;
        }

        if (outs_size < 0)
          THROW(HNS_INCORRECT_PARSER_STATE);

        if (outs_size > 0)
          break;

        blake2b_update(&txid, ctx.locktime, sizeof(ctx.locktime));
        blake2b_final(&txid, ctx.txid);
        blake2b_final(&hash, ctx.outs);
        ctx.sign_ready = true;
        next_item++;
        break;
      }

      default:
        THROW(HNS_INCORRECT_PARSER_STATE);
        break;
    }

    if (should_continue)
      continue;

    if (*len < 0)
      THROW(HNS_INCORRECT_PARSER_STATE);

    if (*len > 0)
      memmove(store, buf, *len);

    store_len = *len;

    break;
  }

  return *len;
};

static const uint8_t SIGHASH_ALL[4] = {0x01, 0x00, 0x00, 0x00};

static inline uint8_t
sign(
  uint16_t *len,
  volatile uint8_t *buf,
  volatile uint8_t *sig,
  volatile uint8_t *flags,
  bool confirm
) {
  static uint8_t i;
  static uint8_t type[4];
  static uint8_t depth;
  static uint32_t path[HNS_MAX_DEPTH];
  static hns_varint_t script_ctr;

  if (!ctx.skip_input) {
    if (!ctx.sign_ready)
      THROW(HNS_INCORRECT_PARSER_STATE);

    uint8_t unsafe = 0;

    if (!read_bip32_path(&buf, len, &depth, path, &unsafe))
      THROW(HNS_CANNOT_READ_BIP32_PATH);

    if (unsafe)
      THROW(HNS_INCORRECT_SIGNATURE_PATH);

    if (!read_u8(&buf, len, &i))
      THROW(HNS_CANNOT_READ_INPUT_INDEX);

    if (i > ctx.ins_len)
      THROW(HNS_INCORRECT_INPUT_INDEX);

    if (!read_bytes(&buf, len, type, sizeof(type)))
      THROW(HNS_CANNOT_READ_SIGHASH_TYPE);

    if (memcmp(type, SIGHASH_ALL, sizeof(type)))
      THROW(HNS_INCORRECT_SIGHASH_TYPE);

    if (!peek_varint(&buf, len, &script_ctr))
      THROW(HNS_CANNOT_PEEK_SCRIPT_LEN);

    uint8_t script_len[5] = {0};
    uint8_t sz = size_varint(script_ctr);

    if (!read_bytes(&buf, len, script_len, sz))
      THROW(HNS_CANNOT_READ_SCRIPT_LEN);

    blake2b_init(&hash, 32, NULL, 0);
    blake2b_update(&hash, ctx.ver, sizeof(ctx.ver));
    blake2b_update(&hash, ctx.prevs, sizeof(ctx.prevs));
    blake2b_update(&hash, ctx.seqs, sizeof(ctx.seqs));
    blake2b_update(&hash, ctx.ins[i].prev, sizeof(ctx.ins[i].prev));
    blake2b_update(&hash, script_len, sz);

    ctx.skip_input = true;
  }

  script_ctr -= *len;

  blake2b_update(&hash, buf, *len);

  if (script_ctr < 0)
    THROW(HNS_INCORRECT_PARSER_STATE);

  if (script_ctr > 0)
    return 0;

  ctx.skip_input = false;

  uint8_t digest[32];

  blake2b_update(&hash, ctx.ins[i].val, sizeof(ctx.ins[i].val));
  blake2b_update(&hash, ctx.ins[i].seq, sizeof(ctx.ins[i].seq));
  blake2b_update(&hash, ctx.outs, sizeof(ctx.outs));
  blake2b_update(&hash, ctx.locktime, sizeof(ctx.locktime));
  blake2b_update(&hash, type, sizeof(type));
  blake2b_final(&hash, digest);

  ledger_ecdsa_sign(path, depth, digest, sizeof(digest), sig);

  *len = sig[1] + 2;

#if defined(TARGET_NANOS)
  if (confirm) {
    char *header = "TXID";
    char *message = g_ledger.ui.message;

    ledger_apdu_cache_write(*len);

    bin2hex(message, ctx.txid, sizeof(ctx.txid));

    if (!ledger_ui_update(header, message, flags))
      THROW(EXCEPTION);

    return 0;
  }
#endif

  return *len;
}

volatile uint16_t
hns_apdu_get_input_signature(
  uint8_t init,
  uint8_t func,
  uint16_t len,
  volatile uint8_t *in,
  volatile uint8_t *out,
  volatile uint8_t *flags
) {
  switch(init) {
    case P1_INIT:
      if (!ledger_unlocked())
        THROW(HNS_SECURITY_CONDITION_NOT_SATISFIED);

    case P1_CONT:
      break;

    default:
      THROW(HNS_INCORRECT_P1);
      break;
  };

  switch(func) {
    case P2_PARSE:
      len = parse(&len, in, init);
      break;

    case P2_SIGN:
      len = sign(&len, in, out, flags, init);
      break;

    default:
      THROW(HNS_INCORRECT_P2);
      break;
  }

  return len;
}
