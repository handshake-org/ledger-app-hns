/**
 * apdu-signature.c - transaction parsing & signing for hns
 * Copyright (c) 2018, Boyma Fahnbulleh (MIT License).
 * https://github.com/handshake-org/ledger-app-hns
 */
#include <stdbool.h>
#include <string.h>
#include "apdu.h"
#include "ledger.h"
#include "utils.h"

/**
 * These constants are used to determine the contents of P1.
 */
#define P1_INIT_MASK 0x01    /* xx1 */
#define P1_NETWORK_MASK 0x06 /* 11x */
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
#define INPUT_VALUE 0x02
#define OUTPUT_VALUE 0x03
#define ADDR_VERSION 0x04
#define ADDR_HASH_LEN 0x05
#define ADDR_HASH 0x06
#define COVENANT_TYPE 0x07
#define COVENANT_ITEMS_LEN 0x08
#define COVENANT_ITEMS 0x09

/**
 * These constants are used to determine sighash types for
 * the input signatures.
 */
#define ZERO 0x00
#define SIGHASH_ALL 0x01
#define SIGHASH_NONE 0x02
#define SIGHASH_SINGLE 0x03
#define SIGHASH_SINGLEREVERSE 0x04
#define SIGHASH_NOINPUT 0x40
#define SIGHASH_ANYONECANPAY 0x80

/**
 * These constants are used to determine the change address flag.
 */
#define NO_CHANGE_ADDR 0x00
#define P2PKH_CHANGE_ADDR 0x01
#define P2SH_CHANGE_ADDR 0x02

/**
 * These constants are used across all covenants.
 */
#define NAME_HASH 0x00
#define HEIGHT 0x01

/**
 * These constants are used to determine the OPEN covenant items.
 */
#define OPEN_NAME 0x02

/**
 * These constants are used to determine the BID covenant items.
 */
#define BID_NAME 0x02
#define BID_HASH 0x03

/**
 * These constants are used to determine the REVEAL covenant items.
 */
#define REVEAL_NONCE 0x02
#define REVEAL_NAME 0x03

/**
 * These constants are used to determine the REDEEM covenant items.
 */
#define REDEEM_NAME 0x02

/**
 * These constants are used to determine the REGISTER covenant items.
 */
#define REGISTER_RESOURCE_LEN 0x02
#define REGISTER_RESOURCE 0x03
#define REGISTER_HASH 0x04
#define REGISTER_NAME 0x05

/**
 * These constants are used to determine the UPDATE covenant items.
 */
#define UPDATE_RESOURCE_LEN 0x02
#define UPDATE_RESOURCE 0x03
#define UPDATE_NAME 0x04

/**
 * These constants are used to determine the RENEW covenant items.
 */
#define RENEW_HASH 0x02
#define RENEW_NAME 0x03

/**
 * These constants are used to determine the TRANSFER covenant items.
 */
#define ADDRESS_VER 0x02
#define ADDRESS_HASH 0x03
#define TRANSFER_NAME 0x04

/**
 * These constants are used to determine the FINALIZE covenant items.
 */
#define FINALIZE_NAME 0x02
#define FLAGS 0x03
#define CLAIM_HEIGHT 0x04
#define RENEWAL_COUNT 0x05
#define FINALIZE_HASH 0x06

/**
 * These constants are used to determine the REVOKE covenant items.
 */
#define REVOKE_NAME 0x02

/* Context used to handle the device's UI. */
static ledger_ui_ctx_t *ui = NULL;

/* Context used to handle parsing and signing state. */
static hns_tx_t ctx;

/* General purpose hashing context. */
static ledger_blake2b_ctx blake1;

/* General purpose hashing context. */
static ledger_blake2b_ctx blake2;

/**
 * Parses an item from the covenant items list
 * and adds it to the provided hash context.
 * Upon completion, the item counter is increased.
 *
 * In:
 * @param item_sz is the expected size of the item (bytes).
 *
 * Out:
 * @param buf is the input buffer.
 * @param len is the length of the input buffer.
 * @param item is the parsed item.
 * @param hash is the blake2b hash context.
 * @returns a boolean indicating success or failure.
 */
static inline bool
parse_item(
  volatile uint8_t **buf,
  uint16_t *len,
  uint8_t *item,
  size_t item_sz,
  ledger_blake2b_ctx *hash
) {
  uint8_t item_len;

  if (!read_varbytes(buf, len, item, item_sz, (size_t *)&item_len))
    return false;

  if (item_len != item_sz)
    THROW(HNS_INCORRECT_PARSER_STATE);

  ledger_blake2b_update(hash, &item_len, 1);
  ledger_blake2b_update(hash, item, item_len);
  ctx.next_item++;
  return true;
}

/**
 * Parses an address from the covenant items list
 * and adds it to the provided hash context. Upon
 * completion, the item counter is increased.
 *
 * Out:
 * @param buf is the input buffer.
 * @param len is the length of the input buffer.
 * @param addr_hash is the parsed address hash.
 * @param addr_len is the parsed address length.
 * @param hash is the blake2b hash context.
 * @returns a boolean indicating success or failure.
 */
static inline bool
parse_addr(
  volatile uint8_t **buf,
  uint16_t *len,
  uint8_t *addr_hash,
  uint8_t *addr_len,
  ledger_blake2b_ctx *hash
){
  uint8_t a[32];
  uint8_t alen;

  if (!read_varbytes(buf, len, a, 32, (size_t *)&alen))
    return false;

  ledger_blake2b_update(hash, &alen, 1);
  ledger_blake2b_update(hash, a, alen);
  memmove(addr_hash, a, alen);
  *addr_len = alen;
  ctx.next_item++;
  return true;
}

/**
 * Parses a name from the covenant items list
 * and adds it to the provided hash context. Upon
 * completion, the item counter is increased.
 *
 * Out:
 * @param buf is the input buffer.
 * @param len is the length of the input buffer.
 * @param name is the parsed name.
 * @param name_len is the parsed name length.
 * @param hash is the blake2b hash context.
 * @returns a boolean indicating success or failure.
 */
static inline bool
parse_name(
  volatile uint8_t **buf,
  uint16_t *len,
  char *name,
  uint8_t *name_len,
  ledger_blake2b_ctx *hash
) {
  uint8_t n[64];
  uint8_t nlen;

  if (!read_varbytes(buf, len, n, 63, (size_t *)&nlen))
    return false;

  if (nlen < 1 || nlen > 63)
    THROW(HNS_INCORRECT_NAME_LEN);

  n[nlen] = '\0';
  ledger_blake2b_update(hash, &nlen, 1);
  ledger_blake2b_update(hash, n, nlen);
  strcpy(name, (char *)n);
  *name_len = nlen;
  ctx.next_item++;
  return true;
}

/**
 * Parses a name from the serialized tx and
 * compares it against the name hash in the
 * covenant items list.
 *
 * In:
 * @param name_hash is the sha3 hash of the name.
 *
 * Out:
 * @param buf is the input buffer.
 * @param len is the length of the input buffer.
 * @param name is the parsed name.
 * @param name_len is the parsed name length.
 * @returns a boolean indicating success or failure.
 */
static inline bool
cmp_name(
  volatile uint8_t **buf,
  uint16_t *len,
  uint8_t *name_hash,
  char *name,
  uint8_t *name_len
) {
  uint8_t n[64];
  size_t nlen;
  uint8_t digest[32];

  if (!read_varbytes(buf, len, n, 63, &nlen))
    return false;

  if (nlen < 1 || nlen > 63)
    THROW(HNS_INCORRECT_NAME_LEN);

  if (!ledger_sha3(n, nlen, digest))
    THROW(HNS_CANNOT_CREATE_COVENANT_NAME_HASH);

  if (memcmp(name_hash, digest, 32) != 0)
    THROW(HNS_COVENANT_NAME_HASH_MISMATCH);

  n[nlen] = '\0';
  strcpy(name, (char *)n);
  *name_len = nlen;
  ctx.next_item++;
  return true;
}

/**
 * Parses the length of the resource bytes from
 * the covenant items list and adds it to the
 * hash context. Upon completion, the item counter
 * is increased.
 *
 * Out:
 * @param buf is the input buffer.
 * @param len is the length of the input buffer.
 * @param ctr is the length of the resource.
 * @param hash is the blake2b hash context.
 * @returns a boolean indicating success or failure.
 */
static inline bool
parse_resource_len(
  volatile uint8_t **buf,
  uint16_t *len,
  hns_varint_t *ctr,
  ledger_blake2b_ctx *hash
) {
  if (!peek_varint(buf, len, ctr))
    return false;

  uint8_t res_len[5] = {0};
  uint8_t res_len_size = size_varint(*ctr);

  if (!read_bytes(buf, len, res_len, res_len_size))
    THROW(HNS_CANNOT_READ_RESOURCE_LEN);

  ledger_blake2b_update(hash, res_len, res_len_size);
  ctx.next_item++;
  return true;
}

/**
 * Parses resource bytes from the covenant
 * items list and adds them to the hash context.
 * Upon completion, the item counter is increased.
 *
 * Out:
 * @param buf is the input buffer.
 * @param len is the length of the input buffer.
 * @param ctr is the length of the resource.
 * @param hash is the blake2b hash context.
 * @returns a boolean indicating success or failure.
 */
static inline bool
parse_resource(
  volatile uint8_t **buf,
  uint16_t *len,
  hns_varint_t *ctr,
  ledger_blake2b_ctx *hash
) {
  hns_varint_t length = *ctr;

  if (*ctr > 0) {
    if (*ctr > *len)
      length = *len;

    ledger_blake2b_update(hash, *buf, length);

    *buf += length;
    *len -= length;
    *ctr -= length;

    if (*ctr > 0) {
      if (*len != 0)
        THROW(HNS_INCORRECT_PARSER_STATE);

      return false;
    }
  }

  ctx.next_item++;
  return true;
}

/**
 * Parses transactions details & begins sighash. Will require
 * more than one message for serialized transactions longer
 * than 255 bytes.
 *
 * In:
 * @param p1 is the first apdu command parameter.
 * @param buf is the input buffer.
 * @param len is length of input buffer.
 *
 * Out:
 * @param res is the APDU response.
 * @param flags holds the apdu exchange buffer flags.
 * @return the length of the APDU response.
 */
static inline uint8_t
parse(
  uint8_t p1,
  uint16_t *len,
  volatile uint8_t *buf,
  volatile uint8_t *res,
  volatile uint8_t *flags
) {
  hns_input_t in;
  hns_output_t *out = &ctx.curr_output;
  ledger_blake2b_ctx *prevs = &blake1;
  ledger_blake2b_ctx *seqs = &blake2;
  ledger_blake2b_ctx *outs = &blake2; /* Re-initialized before use. */

  /**
   * If this is an initial APDU message, clear
   * the apdu cache and reset the parser's state.
   */

  if (p1 & P1_INIT_MASK) {
    ledger_apdu_cache_clear();

    memset(&ctx, 0, sizeof(hns_tx_t));

    if (!read_bytes(&buf, len, ctx.ver, sizeof(ctx.ver)))
      THROW(HNS_CANNOT_READ_TX_VERSION);

    if (!read_bytes(&buf, len, ctx.locktime, sizeof(ctx.locktime)))
      THROW(HNS_CANNOT_READ_TX_LOCKTIME);

    if (!read_u8(&buf, len, &ctx.ins_len))
      THROW(HNS_CANNOT_READ_INPUTS_LEN);

    if (!read_u8(&buf, len, &ctx.outs_len))
      THROW(HNS_CANNOT_READ_OUTPUTS_LEN);

    /**
     * Read change address info. If the change flag is 0x01, we must parse the
     * change output's index, and the corresponding address's version and
     * derivation path. Otherwise, we move on to the input data.
     *
     * Due to a max derivation depth of 5, all change address information
     * should fit within the first parsing message. Unknown flag values will
     * throw an error.
     */

    if (!read_u8(&buf, len, &ctx.change_flag))
      THROW(HNS_CANNOT_READ_CHANGE_ADDR_FLAG);

    switch(ctx.change_flag) {
      case P2PKH_CHANGE_ADDR: {
        ledger_ecdsa_xpub_t xpub;
        uint8_t path_info = 0;

        if (!read_u8(&buf, len, &ctx.change_index))
          THROW(HNS_CANNOT_READ_CHANGE_OUTPUT_INDEX);

        if (!read_u8(&buf, len, &ctx.change.ver))
          THROW(HNS_CANNOT_READ_ADDR_VERSION);

        if (!read_bip44_path(&buf, len, &xpub.depth, xpub.path, &path_info))
          THROW(HNS_CANNOT_READ_BIP44_PATH);

        if (path_info & HNS_BIP44_NON_ADDR)
          THROW(HNS_INCORRECT_ADDR_PATH);

        ledger_ecdsa_derive_xpub(&xpub);

        if (ledger_blake2b(xpub.key, 33, ctx.change.hash, 20))
          THROW(HNS_CANNOT_INIT_BLAKE2B_CTX);

        ctx.change.hash_len = 20;

        break;
      }

      case NO_CHANGE_ADDR:
      case P2SH_CHANGE_ADDR:
        break;

      default:
        THROW(HNS_INCORRECT_CHANGE_ADDR_FLAG);
    }

    ledger_blake2b_init(prevs, 32);
    ledger_blake2b_init(seqs, 32);
  }

  /**
   * Assert the parser is in a valid state and update
   * the apdu buffer with any data left in the cache.
   */

  if (ctx.ins_ctr == ctx.ins_len)
    if (ctx.next_field < OUTPUT_VALUE)
      THROW(HNS_INCORRECT_PARSER_STATE);

  if (ctx.ins_ctr > ctx.ins_len)
    THROW(HNS_INCORRECT_PARSER_STATE);

  if (ctx.outs_ctr == ctx.outs_len)
    if (ctx.next_field <= COVENANT_ITEMS)
      THROW(HNS_INCORRECT_PARSER_STATE);

  if (ctx.outs_ctr > ctx.outs_len)
    THROW(HNS_INCORRECT_PARSER_STATE);

  ledger_apdu_cache_flush(len);

  /**
   * Parse the transaction details.
   */

  for (;;) {
    bool should_continue = false;

    switch(ctx.next_field) {
      case PREVOUT: {
        if (!read_bytes(&buf, len, in.prev, sizeof(in.prev)))
          break;

        ledger_blake2b_update(prevs, in.prev, sizeof(in.prev));
        ctx.next_field++;
      }

      case SEQUENCE: {
        if (!read_bytes(&buf, len, in.seq, sizeof(in.seq)))
          break;

        ledger_blake2b_update(seqs, in.seq, sizeof(in.seq));
        ctx.next_field++;
      }

      case INPUT_VALUE: {
        uint8_t val[8];

        if (!read_bytes(&buf, len, val, 8))
          break;

        add_u64(ctx.fees, ctx.fees, val);
        ctx.next_field++;

        if (++ctx.ins_ctr < ctx.ins_len) {
          memset(&in, 0, sizeof(hns_input_t));
          ctx.next_field = PREVOUT;
          should_continue = true;
          break;
        }

        ledger_blake2b_final(prevs, ctx.prevs);
        ledger_blake2b_final(seqs, ctx.seqs);
        ledger_blake2b_init(outs, 32);
      }

      /**
       * Outputs are variable length and can exceed 512 bytes.
       * We hash them immediately to save RAM.
       */

      case OUTPUT_VALUE: {
        uint8_t *val = out->val;

        if (!read_bytes(&buf, len, val, 8))
          break;

        sub_u64(ctx.fees, ctx.fees, val);
        ledger_blake2b_update(outs, val, 8);
        ctx.next_field++;
      }

      case ADDR_VERSION: {
        uint8_t *ver = &out->addr.ver;

        if (!read_u8(&buf, len, ver))
          break;

        ledger_blake2b_update(outs, ver, 1);
        ctx.next_field++;
      }

      case ADDR_HASH_LEN: {
        uint8_t *hash_len = &out->addr.hash_len;

        if (!read_u8(&buf, len, hash_len))
          break;

        ledger_blake2b_update(outs, hash_len, 1);
        ctx.next_field++;
      }

      case ADDR_HASH: {
        hns_addr_t *addr = &out->addr;

        if (!read_bytes(&buf, len, addr->hash, addr->hash_len))
          break;

        ledger_blake2b_update(outs, addr->hash, addr->hash_len);
        ctx.next_field++;
      }

      case COVENANT_TYPE: {
        uint8_t *type = &out->cov.type;

        if (!read_u8(&buf, len, type))
          break;

        ledger_blake2b_update(outs, type, 1);
        ctx.next_field++;
      }

      case COVENANT_ITEMS_LEN: {
        hns_varint_t *items_len = &out->cov.items_len;

        if (!peek_varint(&buf, len, items_len))
          break;

        uint8_t items_len_buf[5] = {0};
        uint8_t items_len_size = size_varint(*items_len);

        if (!read_bytes(&buf, len, items_len_buf, items_len_size))
          THROW(HNS_CANNOT_READ_COVENANT_ITEMS_LEN);

        ledger_blake2b_update(outs, items_len_buf, items_len_size);
        ctx.next_field++;
      }

     /**
      * If the output has a covenant type that includes the name in its items
      * field, we do not need to verify the name hash. Otherwise, we need to
      * verify the name hash before confirming the name on-screen. In this
      * case, the client is required to send the name with the other
      * covenant details.
      *
      * Note: the name is not included in the output commitment unless it is
      * a part of the covenant's items list.
      */

      case COVENANT_ITEMS: {
        switch(out->cov.type) {
          case HNS_NONE:
            break;

          /**
           * For each subsequent case, the internal
           * switch fall-throughs are intentional.
           */
          case HNS_OPEN: {
            hns_cov_t *c = &out->cov;
            hns_open_t *o = &c->items.open;
            switch (ctx.next_item) {
              case NAME_HASH:
                if (!parse_item(&buf, len, o->name_hash, 32, outs))
                  goto inner_break;

              case HEIGHT:
                if (!parse_item(&buf, len, o->height, 4, outs))
                  goto inner_break;

              case OPEN_NAME:
                if (!parse_name(&buf, len, c->name, &c->name_len, outs))
                  goto inner_break;
            }
            break;
          }

          case HNS_BID: {
            hns_cov_t *c = &out->cov;
            hns_bid_t *b = &c->items.bid;
            switch (ctx.next_item) {
              case NAME_HASH:
                if (!parse_item(&buf, len, b->name_hash, 32, outs))
                  goto inner_break;

              case HEIGHT:
                if (!parse_item(&buf, len, b->height, 4, outs))
                  goto inner_break;

              case BID_NAME:
                if (!parse_name(&buf, len, c->name, &c->name_len, outs))
                  goto inner_break;

              case BID_HASH:
                if (!parse_item(&buf, len, b->hash, 32, outs))
                  goto inner_break;
            }
            break;
          }

          case HNS_REVEAL: {
            hns_cov_t *c = &out->cov;
            hns_reveal_t *r = &c->items.reveal;
            switch (ctx.next_item) {
              case NAME_HASH:
                if (!parse_item(&buf, len, r->name_hash, 32, outs))
                  goto inner_break;

              case HEIGHT:
                if (!parse_item(&buf, len, r->height, 4, outs))
                  goto inner_break;

              case REVEAL_NONCE:
                if (!parse_item(&buf, len, r->nonce, 32, outs))
                  goto inner_break;

              case REVEAL_NAME:
                if (!cmp_name(&buf, len, r->name_hash, c->name, &c->name_len))
                  goto inner_break;
            }
            break;
          }

          case HNS_REDEEM: {
            hns_cov_t *c = &out->cov;
            hns_redeem_t *r = &c->items.redeem;
            switch (ctx.next_item) {
              case NAME_HASH:
                if (!parse_item(&buf, len, r->name_hash, 32, outs))
                  goto inner_break;

              case HEIGHT:
                if (!parse_item(&buf, len, r->height, 4, outs))
                  goto inner_break;

              case REDEEM_NAME:
                if (!cmp_name(&buf, len, r->name_hash, c->name, &c->name_len))
                  goto inner_break;
            }
            break;
          }

          case HNS_REGISTER: {
            hns_cov_t *c = &out->cov;
            hns_register_t *r = &c->items.register_cov;
            switch (ctx.next_item) {
              case NAME_HASH:
                if (!parse_item(&buf, len, r->name_hash, 32, outs))
                  goto inner_break;

              case HEIGHT:
                if (!parse_item(&buf, len, r->height, 4, outs))
                  goto inner_break;

              case REGISTER_RESOURCE_LEN:
                if (!parse_resource_len(&buf, len, &r->resource_ctr, outs))
                  goto inner_break;

              case REGISTER_RESOURCE:
                if (!parse_resource(&buf, len, &r->resource_ctr, outs))
                  goto inner_break;

              case REGISTER_HASH:
                if (!parse_item(&buf, len, r->hash, 32, outs))
                  goto inner_break;

              case REGISTER_NAME:
                if (!cmp_name(&buf, len, r->name_hash, c->name, &c->name_len))
                  goto inner_break;
            }
            break;
          }

          case HNS_UPDATE: {
            hns_cov_t *c = &out->cov;
            hns_update_t *u = &c->items.update;
            switch(ctx.next_item) {
              case NAME_HASH:
                if (!parse_item(&buf, len, u->name_hash, 32, outs))
                  goto inner_break;

              case HEIGHT:
                if (!parse_item(&buf, len, u->height, 4, outs))
                  goto inner_break;

              case UPDATE_RESOURCE_LEN:
                if (!parse_resource_len(&buf, len, &u->resource_ctr, outs))
                  goto inner_break;

              case UPDATE_RESOURCE:
                if (!parse_resource(&buf, len, &u->resource_ctr, outs))
                  goto inner_break;

              case UPDATE_NAME:
                if (!cmp_name(&buf, len, u->name_hash, c->name, &c->name_len))
                  goto inner_break;
            }
            break;
          }

          case HNS_RENEW: {
            hns_cov_t *c = &out->cov;
            hns_renew_t *r = &c->items.renew;
            switch(ctx.next_item) {
              case NAME_HASH:
                if (!parse_item(&buf, len, r->name_hash, 32, outs))
                  goto inner_break;

              case HEIGHT:
                if (!parse_item(&buf, len, r->height, 4, outs))
                  goto inner_break;

              case RENEW_HASH:
                if (!parse_item(&buf, len, r->hash, 32, outs))
                  goto inner_break;

              case RENEW_NAME:
                if (!cmp_name(&buf, len, r->name_hash, c->name, &c->name_len))
                  goto inner_break;
            }
            break;
          }

          case HNS_TRANSFER: {
            hns_cov_t *c = &out->cov;
            hns_transfer_t *t = &c->items.transfer;
            switch (ctx.next_item) {
              case NAME_HASH:
                if (!parse_item(&buf, len, t->name_hash, 32, outs))
                  goto inner_break;

              case HEIGHT:
                if (!parse_item(&buf, len, t->height, 4, outs))
                  goto inner_break;

              case ADDRESS_VER:
                if (!parse_item(&buf, len, &t->addr_ver, 1, outs))
                  goto inner_break;

              case ADDRESS_HASH:
                if (!parse_addr(&buf, len, t->addr_hash, &t->addr_len, outs))
                  goto inner_break;

              case TRANSFER_NAME:
                if (!cmp_name(&buf, len, t->name_hash, c->name, &c->name_len))
                  goto inner_break;
            }
            break;
          }

          case HNS_FINALIZE: {
            hns_cov_t *c = &out->cov;
            hns_finalize_t *f = &c->items.finalize;
            switch(ctx.next_item) {
              case NAME_HASH:
                if (!parse_item(&buf, len, f->name_hash, 32, outs))
                  goto inner_break;

              case HEIGHT:
                if (!parse_item(&buf, len, f->height, 4, outs))
                  goto inner_break;

              case FINALIZE_NAME:
                if (!parse_name(&buf, len, c->name, &c->name_len, outs))
                  goto inner_break;

              case FLAGS:
                if (!parse_item(&buf, len, &f->flags, 1, outs))
                  goto inner_break;

              case CLAIM_HEIGHT:
                if (!parse_item(&buf, len, f->claim_height, 4, outs))
                  goto inner_break;

              case RENEWAL_COUNT:
                if (!parse_item(&buf, len, f->renewal_count, 4, outs))
                  goto inner_break;

              case FINALIZE_HASH:
                if (!parse_item(&buf, len, f->hash, 32, outs))
                  goto inner_break;
            }
            break;
          }

          case HNS_REVOKE: {
            hns_cov_t *c = &out->cov;
            hns_revoke_t *r = &c->items.revoke;
            switch (ctx.next_item) {
              case NAME_HASH:
                if (!parse_item(&buf, len, r->name_hash, 32, outs))
                  goto inner_break;

              case HEIGHT:
                if (!parse_item(&buf, len, r->height, 4, outs))
                  goto inner_break;

              case REVOKE_NAME:
                if (!cmp_name(&buf, len, r->name_hash, c->name, &c->name_len))
                  goto inner_break;
            }
            break;
          }

          default:
            THROW(HNS_UNSUPPORTED_COVENANT_TYPE);
        }

        if (ctx.change_flag == P2PKH_CHANGE_ADDR &&
            ctx.change_index == ctx.outs_ctr) {
          /**
           * We need to verify that the change address details,
           * sent by the client, match a key on this device.
           */

          if (out->addr.ver != ctx.change.ver)
            THROW(HNS_CHANGE_ADDRESS_MISMATCH);

          if (out->addr.hash_len != ctx.change.hash_len)
            THROW(HNS_CHANGE_ADDRESS_MISMATCH);

          if (memcmp(out->addr.hash, ctx.change.hash, out->addr.hash_len) != 0)
            THROW(HNS_CHANGE_ADDRESS_MISMATCH);

          if (++ctx.outs_ctr < ctx.outs_len) {
            ctx.next_field = OUTPUT_VALUE;
            ctx.next_item = NAME_HASH;
            should_continue = true;
            break;
          }
        } else {
          /**
           * We need to handle the case in which there is still data left in
           * the apdu buffer. Any remaining bytes are sent back to the client.
           * We also store the signature ctx on the ui ctx so we can iterate
           * through the output items during on-screen confirmation.
           */

          ui->ctx = (void *)&ctx;
          ui->flags = flags;
          ui->buflen = *len;
          ui->network = p1 & P1_NETWORK_MASK;

          if (ui->buflen != 0) {
            ui->buflen = write_u8(&res, *len);
            ui->buflen += write_bytes(&res, buf, *len);
          }

          char *hdr = "Verify";
          char *msg = ui->message;
          snprintf(msg, 11, "Output #%d", ++(ui->ctr));

          if (!ledger_ui_update(LEDGER_UI_OUTPUT, hdr, msg, flags))
            THROW(HNS_CANNOT_UPDATE_UI);

          if (++ctx.outs_ctr < ctx.outs_len) {
            ctx.next_field = OUTPUT_VALUE;
            ctx.next_item = NAME_HASH;
            return ui->buflen;
          }
        }

        ledger_blake2b_final(outs, ctx.outs);
        ctx.tx_parsed = true;
        ctx.next_field++;
        break;
      }

      default:
        THROW(HNS_INCORRECT_PARSER_STATE);
        break;
    }

inner_break:

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
 * @param p1 is the first apdu command parameter.
 * @param len is length of input buffer.
 * @param buf is the input buffer.
 *
 * Out:
 * @param sig is the output buffer.
 * @param flags holds the apdu exchange buffer flags.
 * @return the length of the APDU response.
 */
static inline uint8_t
sign(
  uint8_t p1,
  uint16_t *len,
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
  uint8_t digest[32];

  /**
   * Parse input details and include initial input
   * commitments for the signature hash.
   */

  hns_input_t *in = &ctx.curr_input;
  uint8_t *type = &in->type[0];

  if (p1 & P1_INIT_MASK) {
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

    if (*type & SIGHASH_ANYONECANPAY) {
      prevs = (uint8_t *)zero_hash;
    }

    if (*type & SIGHASH_ANYONECANPAY
        || (*type & 0x1f) == SIGHASH_SINGLEREVERSE
        || (*type & 0x1f) == SIGHASH_SINGLE
        || (*type & 0x1f) == SIGHASH_NONE) {
      seqs = (uint8_t *)zero_hash;
    }

    if (*type & SIGHASH_NOINPUT) {
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

  switch(*type & 0x1f) {
    case SIGHASH_NONE:
      outs = (uint8_t *)zero_hash;
      break;

    case SIGHASH_SINGLE:
    case SIGHASH_SINGLEREVERSE: {
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
      ledger_blake2b_final(output, digest);
      outs = digest;
      *output_ctr = 0;
      break;
    }

    default:
      break;
  }

  ledger_blake2b_update(hash, outs, 32);
  ledger_blake2b_update(hash, ctx.locktime, sizeof(ctx.locktime));
  ledger_blake2b_update(hash, in->type, sizeof(in->type));
  ledger_blake2b_final(hash, digest);

  if(!ledger_ecdsa_sign(in->path, in->depth, digest, 32, sig, 64))
    THROW(HNS_FAILED_TO_SIGN_INPUT);

  sig[64] = *type;


  /**
   * Confirm the fees iff this is the first SIGHASH_ALL signed input.
   * If we have more SIGHASH_ALL signed inputs, the committed inputs
   * and outputs will be the same.
   */

  if (*type == SIGHASH_ALL && ui->must_confirm) {
    char *hdr = "Fees";
    char *msg = ui->message;

    hex_to_dec(msg, ctx.fees);

    if(!ledger_apdu_cache_write(NULL, 65))
      THROW(HNS_CACHE_WRITE_ERROR);

    if (!ledger_ui_update(LEDGER_UI_FEES, hdr, msg, flags))
      THROW(HNS_CANNOT_UPDATE_UI);

    return 0;
  }

  /**
   * If the client sends anything besides SIGHASH_ALL we need to confirm
   * that the user knows what is going on. We do not confirm the fees in
   * this case, because not all inputs and outputs are included in the
   * signature hash.
   */

  if (*type != SIGHASH_ALL) {
    static const char types[5][14] = {"", "ALL", "NONE", "SINGLE", "SINGLEREVERSE"};
    char *hdr = "Sighash Type";
    char *msg = ui->message;
    uint8_t low = *type & 0x1f;
    uint8_t high = *type & 0xf0;

    if (low < SIGHASH_ALL || low > SIGHASH_SINGLEREVERSE)
      THROW(HNS_UNSUPPORTED_SIGHASH_TYPE);

    strcpy(msg, types[low]);

    switch(high) {
      case ZERO:
        break;

      case SIGHASH_NOINPUT:
        strcat(msg, " | NOINPUT");
        break;

      case SIGHASH_ANYONECANPAY:
        strcat(msg, " | ANYONECANPAY");
        break;

      default:
        THROW(HNS_UNSUPPORTED_SIGHASH_TYPE);
    }

    if(!ledger_apdu_cache_write(NULL, 65))
      THROW(HNS_CACHE_WRITE_ERROR);

    if (!ledger_ui_update(LEDGER_UI_SIGHASH_TYPE, hdr, msg, flags))
      THROW(HNS_CANNOT_UPDATE_UI);

    return 0;
  }

  return 65;
}

uint16_t
hns_apdu_get_input_signature(
  uint8_t p1,
  uint8_t p2,
  uint16_t len,
  volatile uint8_t *in,
  volatile uint8_t *out,
  volatile uint8_t *flags
) {
  switch(p1 & P1_INIT_MASK) {
    case YES:
      if (!ledger_unlocked())
        THROW(HNS_SECURITY_CONDITION_NOT_SATISFIED);

      if (p2 == PARSE) {
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

  switch(p2) {
    case PARSE:
      len = parse(p1, &len, in, out, flags);
      break;

    case SIGN:
      len = sign(p1, &len, in, out, flags);
      break;

    default:
      THROW(HNS_INCORRECT_P2);
      break;
  }

  return len;
}
