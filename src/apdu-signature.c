/**
 * apdu-signature.c - transaction parsing & signing for hns
 * Copyright (c) 2018, Boyma Fahnbulleh (MIT License).
 * https://github.com/boymanjor/ledger-app-hns
 */
#include <stdbool.h>
#include <string.h>
#include "apdu.h"
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

/**
 * These constants are used to determine sighash types for
 * the input signatures.
 */
#define SIGHASH_ALL 0x01
#define SIGHASH_NONE 0x02
#define SIGHASH_SINGLE 0x03
#define SIGHASH_SINGLEREVERSE 0x04
#define SIGHASH_NOINPUT 0x40
#define SIGHASH_ANYONECANPAY 0x80

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
  hns_varint_t outs_ctr;
  uint8_t ver[4];
  uint8_t prevs[32];
  uint8_t seqs[32];
  uint8_t outs[32];
  uint8_t txid[32];
  uint8_t locktime[4];
  hns_input_t curr_input;
  hns_varint_t curr_output_ctr;
} hns_apdu_signature_ctx_t;

/* Context used to handle the device's UI. */
static ledger_ui_ctx_t *ui = NULL;

/* Context used to handle parsing and signing state. */
static hns_apdu_signature_ctx_t ctx;

/* General purpose hashing context. */
static ledger_blake2b_ctx blake1;

/* General purpose hashing context. */
static ledger_blake2b_ctx blake2;

/* General purpose hashing context. */
static ledger_blake2b_ctx blake3;

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
  hns_input_t in;
  ledger_blake2b_ctx *txid = &blake1;
  ledger_blake2b_ctx *prevs = &blake2;
  ledger_blake2b_ctx *seqs = &blake3;
  ledger_blake2b_ctx *outs = &blake3; /* Re-initialized before use. */

  /**
   * If this is an initial APDU message, clear
   * the apdu cache and reset the parser's state.
   */

  if (initial_msg) {
    ledger_apdu_cache_clear();

    memset(&ctx, 0, sizeof(hns_apdu_signature_ctx_t));

    if (!read_bytes(&buf, len, ctx.ver, sizeof(ctx.ver)))
      THROW(HNS_CANNOT_READ_TX_VERSION);

    if (!read_bytes(&buf, len, ctx.locktime, sizeof(ctx.locktime)))
      THROW(HNS_CANNOT_READ_TX_LOCKTIME);

    if (!read_u8(&buf, len, &ctx.ins_len))
      THROW(HNS_CANNOT_READ_INPUTS_LEN);

    if (!read_u8(&buf, len, &ctx.outs_len))
      THROW(HNS_CANNOT_READ_OUTPUTS_LEN);

    if (!read_varint(&buf, len, &ctx.outs_ctr))
      THROW(HNS_CANNOT_READ_OUTPUTS_SIZE);

    ledger_blake2b_init(txid, 32);
    ledger_blake2b_init(prevs, 32);
    ledger_blake2b_init(seqs, 32);
    ledger_blake2b_update(txid, ctx.ver, sizeof(ctx.ver));
    ledger_blake2b_update(txid, &ctx.ins_len, sizeof(ctx.ins_len));
  }

  /**
   * Assert the parser is in a valid state and update
   * the apdu buffer with any data left in the cache.
   */

  if (ctx.ins_ctr == ctx.ins_len)
    if (ctx.next_item != OUTPUTS)
      THROW(HNS_INCORRECT_PARSER_STATE);

  if (ctx.ins_ctr > ctx.ins_len)
    THROW(HNS_INCORRECT_PARSER_STATE);

  ledger_apdu_cache_flush(len);

  /**
   * Parse the transaction details.
   */

  for (;;) {
    bool should_continue = false;

    switch(ctx.next_item) {
      case PREVOUT: {
        if (!read_bytes(&buf, len, in.prev, sizeof(in.prev)))
          break;

        ledger_blake2b_update(prevs, in.prev, sizeof(in.prev));
        ledger_blake2b_update(txid, in.prev, sizeof(in.prev));
        ctx.next_item++;
      }

      case SEQUENCE: {
        if (!read_bytes(&buf, len, in.seq, sizeof(in.seq)))
          break;

        ledger_blake2b_update(seqs, in.seq, sizeof(in.seq));
        ledger_blake2b_update(txid, in.seq, sizeof(in.seq));
        ctx.next_item++;

        if (++ctx.ins_ctr < ctx.ins_len) {
          memset(&in, 0, sizeof(hns_input_t));
          ctx.next_item = PREVOUT;
          should_continue = true;
          break;
        }

        ledger_blake2b_final(prevs, ctx.prevs);
        ledger_blake2b_final(seqs, ctx.seqs);
        ledger_blake2b_update(txid, &ctx.outs_len, sizeof(ctx.outs_len));
        ledger_blake2b_init(outs, 32);
      }

      /**
       * Outputs are variable length and can exceed 512 bytes.
       * We hash them immediately to save RAM.
       */

      case OUTPUTS: {
        if (*len > 0) {
          ledger_blake2b_update(txid, buf, *len);
          ledger_blake2b_update(outs, buf, *len);
          ctx.outs_ctr -= *len;
          buf += *len;
          *len = 0;
        }

        if (ctx.outs_ctr < 0)
          THROW(HNS_INCORRECT_PARSER_STATE);

        if (ctx.outs_ctr > 0)
          break;

        ledger_blake2b_update(txid, ctx.locktime, sizeof(ctx.locktime));
        ledger_blake2b_final(txid, ctx.txid);
        ledger_blake2b_final(outs, ctx.outs);
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
 * Parses the signing key's HD path, the sighash type, and the input details.
 * Also parses output data for single output sighash types, then returns a
 * signature for the specified input. Will require more than one message for
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

  const uint8_t zero_hash[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };

  ledger_blake2b_ctx *hash = &blake1;
  ledger_blake2b_ctx *output = &blake2;
  uint8_t hash_digest[32];
  uint8_t output_digest[32];

  /**
   * Parse input details and include initial input
   * commitments for the signature hash.
   */

  hns_input_t *in = &ctx.curr_input;

  if (initial_msg) {
    ledger_apdu_cache_clear();

    uint8_t path_info = 0;

    if (!read_bip44_path(&buf, len, &in->depth, in->path, &path_info))
      THROW(HNS_CANNOT_READ_BIP44_PATH);

    uint8_t non_address = path_info & HNS_BIP44_NON_ADDR;

    if (non_address)
      THROW(HNS_INCORRECT_SIGNATURE_PATH);

    if (!read_bytes(&buf, len, in->type, sizeof(in->type)))
      THROW(HNS_CANNOT_READ_SIGHASH_TYPE);

    if (!read_bytes(&buf, len, in->prev, sizeof(in->prev)))
      THROW(HNS_CANNOT_READ_PREVOUT);

    if (!read_bytes(&buf, len, in->val, sizeof(in->val)))
      THROW(HNS_CANNOT_READ_INPUT_VALUE);

    if (!read_bytes(&buf, len, in->seq, sizeof(in->seq)))
      THROW(HNS_CANNOT_READ_SEQUENCE);

    if (!peek_varint(&buf, len, &in->script_ctr))
      THROW(HNS_CANNOT_PEEK_SCRIPT_LEN);

    uint8_t script_len[5] = {0};
    uint8_t script_len_size = size_varint(in->script_ctr);

    if (!read_bytes(&buf, len, script_len, script_len_size))
      THROW(HNS_CANNOT_READ_SCRIPT_LEN);

    uint8_t *prevs = ctx.prevs;
    uint8_t *seqs = ctx.seqs;

    if (in->type[0] & SIGHASH_ANYONECANPAY) {
      prevs = zero_hash;
    }

    if (in->type[0] & SIGHASH_ANYONECANPAY
        || (in->type[0] & 0x1f) == SIGHASH_SINGLEREVERSE
        || (in->type[0] & 0x1f) == SIGHASH_SINGLE
        || (in->type[0] & 0x1f) == SIGHASH_NONE) {
      seqs = zero_hash;
    }

    if (in->type[0] & SIGHASH_NOINPUT) {
      memset(in->prev, 0x00, 32);
      memset(in->prev + 32, 0xff, 4);
      memset(in->seq, 0xff, sizeof(in->seq));
    }

    ledger_blake2b_init(hash, 32);
    ledger_blake2b_update(hash, ctx.ver, sizeof(ctx.ver));
    ledger_blake2b_update(hash, prevs, 32);
    ledger_blake2b_update(hash, seqs, 32);
    ledger_blake2b_update(hash, in->prev, sizeof(in->prev));
    ledger_blake2b_update(hash, script_len, script_len_size);
  }

  /**
   * Include redeem script, input value, and input sequence commitments
   * for the signature hash. Script data has a variable size, so it is
   * hashed immediately to save RAM.
   */

  if (in->script_ctr > 0) {
    if (*len == 0)
      return 0;

    if (in->script_ctr >= *len) {
      ledger_blake2b_update(hash, buf, *len);
      in->script_ctr -= *len;
      return 0;
    }

    ledger_blake2b_update(hash, buf, in->script_ctr);
    ledger_blake2b_update(hash, in->val, sizeof(in->val));
    ledger_blake2b_update(hash, in->seq, sizeof(in->seq));
    buf += in->script_ctr;
    *len -= in->script_ctr;
    in->script_ctr = 0;
  }

  /**
   * Include output, locktime, and sighash type commitments for the
   * signature hash. For single output commitments, the client must
   * provide the output data. It is hashed immediately to save RAM.
   *
   * Afterwards, the signature hash is finalized and signed.
   */

  uint8_t *outs = ctx.outs;
  uint8_t type = in->type[0] & 0x1f;

  if (type == SIGHASH_NONE) {
    outs = zero_hash;
  } else if (type == SIGHASH_SINGLE || type == SIGHASH_SINGLEREVERSE) {
    hns_varint_t *output_ctr = &ctx.curr_output_ctr;

    ledger_apdu_cache_flush(len);

    if (*output_ctr == 0) {
      if (*len == 0)
        return 0;

      if (!read_varint(&buf, len, output_ctr)) {
        if(!ledger_apdu_cache_write(buf, *len))
          THROW(HNS_CACHE_WRITE_ERROR);
        return 0;
      }

      if (*output_ctr == 0)
        THROW(HNS_INCORRECT_PARSER_STATE);

      ledger_blake2b_init(output, 32);
    }

    if (*output_ctr < *len)
      THROW(HNS_INCORRECT_PARSER_STATE);

    if (*output_ctr > *len) {
      if (*len == 0)
        return 0;

      ledger_blake2b_update(output, buf, *len);
      *output_ctr -= *len;

      return 0;
    }

    ledger_blake2b_update(output, buf, *len);
    ledger_blake2b_final(output, output_digest);
    outs = output_digest;
    *output_ctr = 0;
  }

  ledger_blake2b_update(hash, outs, 32);
  ledger_blake2b_update(hash, ctx.locktime, sizeof(ctx.locktime));
  ledger_blake2b_update(hash, in->type, sizeof(in->type));
  ledger_blake2b_final(hash, hash_digest);

  if(!ledger_ecdsa_sign(in->path, in->depth, hash_digest, 32, sig, 64))
    THROW(HNS_FAILED_TO_SIGN_INPUT);

  sig[64] = in->type[0];

#if defined(TARGET_NANOS)
  if (ui->must_confirm) {
    char *header = "TXID";
    char *message = ui->message;

    if(!ledger_apdu_cache_write(NULL, 65))
      THROW(HNS_CACHE_WRITE_ERROR);

    bin_to_hex(message, ctx.txid, sizeof(ctx.txid));

    if (!ledger_ui_update(header, message, flags))
      THROW(HNS_CANNOT_UPDATE_UI);

    return 0;
  }
#endif

  return 65;
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

      if (mode == PARSE) {
        ui = ledger_ui_init_session();
        ui->must_confirm = true;
      }
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
