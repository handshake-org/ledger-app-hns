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
#define SEQUENCE 0x01
#define OUTPUTS 0x02

/* Context representing the signing details for an input. */
typedef struct hns_input_s {
  uint8_t prev[36];
  uint8_t val[8];
  uint8_t seq[4];
  uint8_t type[4];
  uint8_t depth;
  uint32_t path[HNS_MAX_DEPTH];
  hns_varint_t script_ctr;
} hns_input_t;

/* Global context used to handle parsing and signing state. */
typedef struct hns_apdu_signature_ctx_t {
  bool tx_parsed;
  uint8_t next_item;
  uint8_t ins_len;
  uint8_t ins_ctr;
  uint8_t outs_len;
  hns_varint_t outs_size;
  uint8_t ver[4];
  uint8_t prevs[32];
  uint8_t seqs[32];
  uint8_t outs[32];
  uint8_t txid[32];
  uint8_t locktime[4];
  hns_input_t curr_input;
} hns_apdu_signature_ctx_t;

/* Context used to handle the device's UI. */
static ledger_ui_ctx_t *ui = NULL;

/* Context used to handle parsing and signing state. */
static hns_apdu_signature_ctx_t ctx;

/* General purpose hashing context. */
static blake2b_ctx blake1;

/* General purpose hashing context. */
static blake2b_ctx blake2;

/* General purpose hashing context. */
static blake2b_ctx blake3;

/**
 * Parses transactions details, generates txid & begins sighash.
 * Will require more than one message for serialized transactions
 * longer than 255 bytes.
 *
 * In:
 * @param buf is the input buffer.
 * @param len is length of input buffer.
 * @param reset indicates if parser state should be reset.
 * @return the length of the APDU response (always 0).
 */
static inline uint8_t
parse(bool initial_msg, uint8_t *len, volatile uint8_t *buf) {
  blake2b_ctx *txid = &blake1;
  blake2b_ctx *prevs = &blake2;
  blake2b_ctx *seqs = &blake3;
  blake2b_ctx *outs = &blake3; /* blake3 re-initialized before use */

  /* If initial msg, clear previous tx details and parser state. */
  if (initial_msg) {
    memset(&ctx, 0, sizeof(hns_apdu_signature_ctx_t));

    blake2b_init(txid, 32, NULL, 0);
    blake2b_init(prevs, 32, NULL, 0);
    blake2b_init(seqs, 32, NULL, 0);

    ledger_apdu_cache_clear();

    if (!read_bytes(&buf, len, ctx.ver, sizeof(ctx.ver)))
      THROW(HNS_CANNOT_READ_TX_VERSION);

    if (!read_bytes(&buf, len, ctx.locktime, sizeof(ctx.locktime)))
      THROW(HNS_CANNOT_READ_TX_LOCKTIME);

    if (!read_u8(&buf, len, &ctx.ins_len))
      THROW(HNS_CANNOT_READ_INPUTS_LEN);

    if (!read_u8(&buf, len, &ctx.outs_len))
      THROW(HNS_CANNOT_READ_OUTPUTS_LEN);

    if (!read_varint(&buf, len, &ctx.outs_size))
      THROW(HNS_CANNOT_READ_OUTPUTS_SIZE);

    blake2b_update(txid, ctx.ver, sizeof(ctx.ver));
    blake2b_update(txid, &ctx.ins_len, sizeof(ctx.ins_len));
  }

  hns_input_t in;

  if (ctx.ins_ctr == ctx.ins_len)
    if (ctx.next_item != OUTPUTS)
      THROW(HNS_INCORRECT_PARSER_STATE);

  if (ctx.ins_ctr > ctx.ins_len)
    THROW(HNS_INCORRECT_PARSER_STATE);

  /* If cache is full, flush to apdu buffer. */
  uint8_t cache_len = ledger_apdu_cache_check();

  if (cache_len) {
    uint8_t offset = *len;

    *len += ledger_apdu_cache_flush(offset);

    if (cache_len + offset != *len)
      THROW(HNS_CACHE_FLUSH_ERROR);
  }

  for (;;) {
    bool should_continue = false;

    switch(ctx.next_item) {
      case PREVOUT: {
        if (!read_bytes(&buf, len, in.prev, sizeof(in.prev)))
          break;

        blake2b_update(prevs, in.prev, sizeof(in.prev));
        blake2b_update(txid, in.prev, sizeof(in.prev));
        ctx.next_item++;
      }

      case SEQUENCE: {
        if (!read_bytes(&buf, len, in.seq, sizeof(in.seq)))
          break;

        blake2b_update(seqs, in.seq, sizeof(in.seq));
        blake2b_update(txid, in.seq, sizeof(in.seq));
        ctx.next_item++;

        if (++ctx.ins_ctr < ctx.ins_len) {
          memset(&in, 0, sizeof(hns_input_t));
          ctx.next_item = PREVOUT;
          should_continue = true;
          break;
        }

        blake2b_final(prevs, ctx.prevs);
        blake2b_final(seqs, ctx.seqs);

        /* Commit to output vector length */
        blake2b_update(txid, &ctx.outs_len, sizeof(ctx.outs_len));

        /* Re-initialze the sighash context for outputs commitment. */
        blake2b_init(outs, 32, NULL, 0);
      }

      case OUTPUTS: {
        if (*len > 0) {
          /* Outputs are hashed immediately to save RAM. */
          blake2b_update(txid, buf, *len);
          blake2b_update(outs, buf, *len);
          ctx.outs_size -= *len;
          buf += *len;
          *len = 0;
        }

        if (ctx.outs_size < 0)
          THROW(HNS_INCORRECT_PARSER_STATE);

        if (ctx.outs_size > 0)
          break;

        blake2b_update(txid, ctx.locktime, sizeof(ctx.locktime));
        blake2b_final(txid, ctx.txid);
        blake2b_final(outs, ctx.outs);
        ctx.tx_parsed = true;
        ctx.next_item++;
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
 * for the specified input. Will require more than one message for
 * scripts longer than 182 bytes (including varint length prefix).
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
  uint8_t *len,
  volatile uint8_t *buf,
  volatile uint8_t *sig,
  volatile uint8_t *flags
) {
  if (!ctx.tx_parsed)
    THROW(HNS_INCORRECT_PARSER_STATE);

  const uint32_t sighash_all = 1;
  hns_input_t *in = &ctx.curr_input;
  blake2b_ctx *hash = &blake1;

  if (initial_msg) {
    uint8_t path_info = 0;
    uint8_t non_address = 0;

    if (!read_bip44_path(&buf, len, &in->depth, in->path, &path_info))
      THROW(HNS_CANNOT_READ_BIP44_PATH);

    non_address = path_info & HNS_BIP44_NON_ADDR;

    if (non_address)
      THROW(HNS_INCORRECT_SIGNATURE_PATH);

    if (!read_bytes(&buf, len, in->type, sizeof(in->type)))
      THROW(HNS_CANNOT_READ_SIGHASH_TYPE);

    if (memcmp(in->type, &sighash_all, sizeof(in->type)))
      THROW(HNS_INCORRECT_SIGHASH_TYPE);

    if (!read_bytes(&buf, len, in->prev, sizeof(in->prev)))
      THROW(HNS_CANNOT_READ_PREVOUT);

    if (!read_bytes(&buf, len, in->val, sizeof(in->val)))
      THROW(HNS_CANNOT_READ_INPUT_VALUE);

    if (!read_bytes(&buf, len, in->seq, sizeof(in->seq)))
      THROW(HNS_CANNOT_READ_SEQUENCE);

    if (!peek_varint(&buf, len, &in->script_ctr))
      THROW(HNS_CANNOT_PEEK_SCRIPT_LEN);

    uint8_t script_len[5] = {0};
    uint8_t sz = size_varint(in->script_ctr);

    if (!read_bytes(&buf, len, script_len, sz))
      THROW(HNS_CANNOT_READ_SCRIPT_LEN);

    blake2b_init(hash, 32, NULL, 0);
    blake2b_update(hash, ctx.ver, sizeof(ctx.ver));
    blake2b_update(hash, ctx.prevs, sizeof(ctx.prevs));
    blake2b_update(hash, ctx.seqs, sizeof(ctx.seqs));
    blake2b_update(hash, in->prev, sizeof(in->prev));
    blake2b_update(hash, script_len, sz);
  }

  in->script_ctr -= *len;

  blake2b_update(hash, buf, *len);

  if (in->script_ctr < 0)
    THROW(HNS_INCORRECT_PARSER_STATE);

  if (in->script_ctr > 0)
    return 0;

  uint8_t digest[32];
  uint8_t sig_len = 64;

  blake2b_update(hash, in->val, sizeof(in->val));
  blake2b_update(hash, in->seq, sizeof(in->seq));
  blake2b_update(hash, ctx.outs, sizeof(ctx.outs));
  blake2b_update(hash, ctx.locktime, sizeof(ctx.locktime));
  blake2b_update(hash, in->type, sizeof(in->type));
  blake2b_final(hash, digest);

  if(!ledger_ecdsa_sign(in->path, in->depth, digest, sizeof(digest), sig, sig_len))
    THROW(HNS_FAILED_TO_SIGN_INPUT);

  /* Append signature with sighash type (always SIGHASH_ALL for now) */
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

volatile uint8_t
hns_apdu_get_input_signature(
  uint8_t initial_msg,
  uint8_t mode,
  uint8_t len,
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
