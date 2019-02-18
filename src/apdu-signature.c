/**
 * apdu-signature.c - transaction parsing & signing for hns
 * Copyright (c) 2018, Boyma Fahnbulleh (MIT License).
 * https://github.com/boymanjor/ledger-app-hns
 */
#include <stdbool.h>
#include <string.h>
#include "apdu.h"
#include "blake2b.h"
#include "ledger.h"
#include "utils.h"

/**
 * These constants are used to determine if P1 indicates
 * the current APDU message is the initial message or
 * a following message.
 */
#define NO 0x00
#define YES 0x01

/**
 * These constants are used to determine which operation
 * mode is indicated by P2.
 */
#define PARSE 0x00
#define SIGN 0x01

/**
 * These constants are used to determine which transaction
 * detail is currently being parsed.
 */
#define PREVOUT 0x00
#define VALUE 0x01
#define SEQUENCE 0x02
#define OUTPUTS 0x03

/* Inputs are limited due to RAM limitations. */
#define MAX_INPUTS 10

/**
 * HNS transaction input representation.
 */
typedef struct hns_input_s {
  uint8_t prev[36];
  uint8_t val[8];
  uint8_t seq[4];
} hns_input_t;

/**
 * Global context used to handle parsing and signing state.
 */
typedef struct hns_apdu_signature_ctx_t {
  bool tx_parsed;
  hns_input_t ins[MAX_INPUTS];
  uint8_t ins_len;
  uint8_t outs_len;
  uint8_t ver[4];
  uint8_t prevs[32];
  uint8_t seqs[32];
  uint8_t outs[32];
  uint8_t txid[32];
  uint8_t locktime[4];
} hns_apdu_signature_ctx_t;

/**
 * Context used to handle the device's UI.
 */
static ledger_ui_ctx_t *ui = NULL;

/**
 * Context used to handle parsing and signing state.
 */
static hns_apdu_signature_ctx_t ctx;

/**
 * Hashing context for signature hash.
 */
static blake2b_ctx hash;

/**
 * Hashing context for txid.
 */
static blake2b_ctx txid;

/**
 * Parses transactions details, generates txid & begins sighash.
 *
 * In:
 * @param buf is the input buffer.
 * @param len is length of input buffer.
 * @param reset indicates if parser state should be reset.
 * @return the length of the APDU response (always 0).
 */
static inline uint16_t
parse(bool initial_msg, uint16_t *len, volatile uint8_t *buf) {
  static uint8_t i;
  static uint8_t next_item;
  static uint8_t outs_size;

  // If this is the initial message for a new transaction,
  // clear all previous transaction details and parser state.
  if (initial_msg) {
    i = 0;
    next_item = 0;
    outs_size = 0;

    memset(&ctx, 0, sizeof(hns_apdu_signature_ctx_t));

    ledger_apdu_cache_clear();

    if (!read_bytes(&buf, len, ctx.ver, sizeof(ctx.ver)))
      THROW(HNS_CANNOT_READ_TX_VERSION);

    if (!read_bytes(&buf, len, ctx.locktime, sizeof(ctx.locktime)))
      THROW(HNS_CANNOT_READ_TX_LOCKTIME);

    if (!read_u8(&buf, len, &ctx.ins_len))
      THROW(HNS_CANNOT_READ_INPUTS_LEN);

    if (ctx.ins_len > MAX_INPUTS)
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

  // If cache is full, flush to apdu buffer.
  uint8_t cache_len = ledger_apdu_cache_check();

  if (cache_len) {
    uint16_t offset = *len;

    *len += ledger_apdu_cache_flush(offset);

    if (cache_len + offset != *len)
      THROW(HNS_CACHE_FLUSH_ERROR);
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
          // Due to sizes reaching up to +500 bytes,
          // the outputs are hashed immediately to save RAM.
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
        ctx.tx_parsed = true;
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
      if(!ledger_apdu_cache_write(buf, *len))
        THROW(HNS_INCORRECT_PARSER_STATE);

    break;
  }

  return 0;
};


/**
 * Parses sighash, path, and input details, then returns a signature
 * for the specified input.
 *
 * In:
 * @param len is length of input buffer.
 * @param buf is the input buffer.
 * @param sig is the output buffer.
 * @return the length of the APDU response.
 */
static inline uint8_t
sign(
  bool initial_msg,
  uint16_t *len,
  volatile uint8_t *buf,
  volatile uint8_t *sig,
  volatile uint8_t *flags
) {
  static uint8_t i;
  static uint8_t type[4];
  static uint8_t depth;
  static uint32_t path[HNS_MAX_DEPTH];
  static hns_varint_t script_ctr;

  // Currently, only SIGHASH_ALL is supported.
  const uint32_t sighash_all = 1;

  // To save on RAM the tx inputs are hashed immediately,
  // instead of being represented in memory. This may result
  // in multiple messages being sent before a signature is
  // returned. The path, index, sighash type, and script len
  // are only sent with the first message.
  if (initial_msg) {
    if (!ctx.tx_parsed)
      THROW(HNS_INCORRECT_PARSER_STATE);

    uint8_t path_info = 0;
    uint8_t non_address = 0;

    if (!read_bip44_path(&buf, len, &depth, path, &path_info))
      THROW(HNS_CANNOT_READ_BIP44_PATH);

    non_address = path_info & HNS_BIP44_NON_ADDR;

    if (non_address)
      THROW(HNS_INCORRECT_SIGNATURE_PATH);

    if (!read_u8(&buf, len, &i))
      THROW(HNS_CANNOT_READ_INPUT_INDEX);

    if (i > ctx.ins_len)
      THROW(HNS_INCORRECT_INPUT_INDEX);

    if (!read_bytes(&buf, len, type, sizeof(type)))
      THROW(HNS_CANNOT_READ_SIGHASH_TYPE);

    if (memcmp(type, &sighash_all, sizeof(type)))
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
  }

  script_ctr -= *len;

  blake2b_update(&hash, buf, *len);

  if (script_ctr < 0)
    THROW(HNS_INCORRECT_PARSER_STATE);

  if (script_ctr > 0)
    return 0;

  uint8_t digest[32];
  uint8_t sig_len = 64;

  blake2b_update(&hash, ctx.ins[i].val, sizeof(ctx.ins[i].val));
  blake2b_update(&hash, ctx.ins[i].seq, sizeof(ctx.ins[i].seq));
  blake2b_update(&hash, ctx.outs, sizeof(ctx.outs));
  blake2b_update(&hash, ctx.locktime, sizeof(ctx.locktime));
  blake2b_update(&hash, type, sizeof(type));
  blake2b_final(&hash, digest);

  if(!ledger_ecdsa_sign(path, depth, digest, sizeof(digest), sig, sig_len))
    THROW(HNS_FAILED_TO_SIGN_INPUT);

  // Add sighash type to the end of the signature (always SIGHASH_ALL for now).
  sig[sig_len++] = sighash_all;

#if defined(TARGET_NANOS)
  if (ui->must_confirm) {
    char *header = "TXID";
    char *message = ui->message;

    if(!ledger_apdu_cache_write(NULL, sig_len))
      THROW(HNS_CACHE_WRITE_ERROR);

    bin_to_hex(message, ctx.txid, sizeof(ctx.txid));

    if (!ledger_ui_update(header, message, flags))
      THROW(HNS_CANNOT_UPDATE_UI);

    return 0;
  }
#endif

  return sig_len;
}

volatile uint16_t
hns_apdu_get_input_signature(
  uint8_t initial_msg,
  uint8_t mode,
  uint16_t len,
  volatile uint8_t *in,
  volatile uint8_t *out,
  volatile uint8_t *flags
) {
  switch(initial_msg) {
    case YES:
      if (!ledger_unlocked())
        THROW(HNS_SECURITY_CONDITION_NOT_SATISFIED);

      if (mode == PARSE)
        ui = ledger_ui_init_session();
        ui->must_confirm = true;
      break;

    case NO:
      break;

    default:
      THROW(HNS_INCORRECT_P1);
      break;
  };

  switch(mode) {
    case PARSE:
      len = parse(initial_msg, &len, in);
      break;

    case SIGN:
      len = sign(initial_msg, &len, in, out, flags);
      break;

    default:
      THROW(HNS_INCORRECT_P2);
      break;
  }

  return len;
}
