/**
 * apdu.h - header file for apdu commands
 * Copyright (c) 2018, Boyma Fahnbulleh (MIT License).
 * https://github.com/handshake-org/ledger-app-hns
 */
#ifndef _HNS_APDU_H
#define _HNS_APDU_H

#include <stdint.h>
#include "utils.h"

/**
 * Offsets used to parse APDU header.
 */

#define HNS_OFFSET_CLA 0x00
#define HNS_OFFSET_INS 0x01
#define HNS_OFFSET_P1 0x02
#define HNS_OFFSET_P2 0x03
#define HNS_OFFSET_LC 0x04
#define HNS_OFFSET_CDATA 0x05

/**
 * Standard APDU status words.
 */

#define HNS_OK 0x9000
#define HNS_INCORRECT_P1 0x6Af1
#define HNS_INCORRECT_P2 0x6Af2
#define HNS_INCORRECT_LC 0x6700
#define HNS_INCORRECT_CDATA 0x6a80
#define HNS_INS_NOT_SUPPORTED 0x6d00
#define HNS_CLA_NOT_SUPPORTED 0x6e00
#define HNS_SECURITY_CONDITION_NOT_SATISFIED 0x6982
#define HNS_CONDITIONS_OF_USE_NOT_SATISFIED 0x6985

/**
 * App specific APDU status words.
 */

#define HNS_CANNOT_INIT_BLAKE2B_CTX 0x13
#define HNS_CANNOT_ENCODE_ADDRESS 0x14
#define HNS_CANNOT_READ_BIP44_PATH 0x15
#define HNS_CANNOT_READ_TX_VERSION 0x16
#define HNS_CANNOT_READ_TX_LOCKTIME 0x17
#define HNS_CANNOT_READ_INPUTS_LEN 0x18
#define HNS_CANNOT_READ_OUTPUTS_LEN 0x19
#define HNS_CANNOT_READ_OUTPUTS_SIZE 0x1a
#define HNS_CANNOT_READ_INPUT_INDEX 0x1b
#define HNS_CANNOT_READ_SIGHASH_TYPE 0x1c
#define HNS_CANNOT_READ_SCRIPT_LEN 0x1d
#define HNS_CANNOT_PEEK_SCRIPT_LEN 0x1e
#define HNS_INCORRECT_INPUT_INDEX 0x1f
#define HNS_INCORRECT_SIGHASH_TYPE 0x20
#define HNS_INCORRECT_PARSER_STATE 0x21
#define HNS_INCORRECT_SIGNATURE_PATH 0x22
#define HNS_CANNOT_ENCODE_XPUB 0x23
#define HNS_INCORRECT_INPUTS_LEN 0x24
#define HNS_INCORRECT_ADDR_PATH 0x25
#define HNS_CACHE_WRITE_ERROR 0x26
#define HNS_CACHE_FLUSH_ERROR 0x27
#define HNS_CANNOT_UPDATE_UI 0x28
#define HNS_FAILED_TO_SIGN_INPUT 0x29
#define HNS_CANNOT_READ_PREVOUT 0x2a
#define HNS_CANNOT_READ_INPUT_VALUE 0x2b
#define HNS_CANNOT_READ_SEQUENCE 0x2c
#define HNS_CANNOT_READ_CHANGE_ADDR_FLAG 0x2d
#define HNS_INCORRECT_CHANGE_ADDR_FLAG 0x2e
#define HNS_CANNOT_READ_CHANGE_OUTPUT_INDEX 0x2f
#define HNS_CANNOT_READ_ADDR_VERSION 0x30
#define HNS_UNSUPPORTED_COVENANT_TYPE 0x31
#define HNS_CANNOT_READ_COVENANT_ITEMS_LEN 0x32
#define HNS_INCORRECT_NAME_LEN 0x33
#define HNS_UNSUPPORTED_SIGHASH_TYPE 0x34
#define HNS_CANNOT_READ_RESOURCE_LEN 0x35
#define HNS_CANNOT_CREATE_COVENANT_NAME_HASH 0x36
#define HNS_COVENANT_NAME_HASH_MISMATCH 0x37
#define HNS_CHANGE_ADDRESS_MISMATCH 0x38

/**
 * These constants are used to determine the covenant type.
 */
#define HNS_NONE 0x00
#define HNS_CLAIM 0x01
#define HNS_OPEN 0x02
#define HNS_BID 0x03
#define HNS_REVEAL 0x04
#define HNS_REDEEM 0x05
#define HNS_REGISTER 0x06
#define HNS_UPDATE 0x07
#define HNS_RENEW 0x08
#define HNS_TRANSFER 0x09
#define HNS_FINALIZE 0x0a
#define HNS_REVOKE 0x0b

/**
 * Covenant items for respective covenant types.
 */

typedef struct hns_open_s {
  uint8_t name_hash[32];
  uint8_t height[4];
} hns_open_t;

typedef struct hns_bid_s {
  uint8_t name_hash[32];
  uint8_t height[4];
  uint8_t hash[32];
} hns_bid_t;

typedef struct hns_reveal_s {
  uint8_t name_hash[32];
  uint8_t height[4];
  uint8_t nonce[32];
} hns_reveal_t;

typedef struct hns_redeem_s {
  uint8_t name_hash[32];
  uint8_t height[4];
} hns_redeem_t;

/**
 * TODO(boymanjor): optimize memory
 * usage to handle 512-byte resources
 * in register and update covenants.
 */
typedef struct hns_register_s {
  uint8_t name_hash[32];
  uint8_t height[4];
  hns_varint_t resource_ctr;
  uint8_t hash[32];
} hns_register_t;

typedef struct hns_update_s {
  uint8_t name_hash[32];
  uint8_t height[4];
  hns_varint_t resource_ctr;
} hns_update_t;

typedef struct hns_renew_s {
  uint8_t name_hash[32];
  uint8_t height[4];
  uint8_t hash[32];
} hns_renew_t;

typedef struct hns_transfer_s {
  uint8_t name_hash[32];
  uint8_t height[4];
  uint8_t addr_ver;
  uint8_t addr_len;
  uint8_t addr_hash[32];
} hns_transfer_t;

typedef struct hns_finalize_s {
  uint8_t name_hash[32];
  uint8_t height[4];
  uint8_t flags;
  uint8_t claim_height[4];
  uint8_t renewal_count[4];
  uint8_t hash[32];
} hns_finalize_t;

typedef struct hns_revoke_s {
  uint8_t name_hash[32];
  uint8_t height[4];
} hns_revoke_t;

typedef union {
  hns_open_t open;
  hns_bid_t bid;
  hns_reveal_t reveal;
  hns_redeem_t redeem;
  hns_register_t register_cov;
  hns_update_t update;
  hns_renew_t renew;
  hns_transfer_t transfer;
  hns_finalize_t finalize;
  hns_revoke_t revoke;
} hns_cov_items_t;

/**
 * Covenant struct.
 */

typedef struct hns_cov_s {
  uint8_t type;
  hns_varint_t items_len;
  hns_cov_items_t items;

  /* Name is stored on covenant to allow
   * simple verification of the name hash. */
  uint8_t name_len;
  char name[64];
} hns_cov_t;

/**
 * Address struct.
 */

typedef struct hns_addr_s {
  uint8_t ver;
  uint8_t hash_len;
  uint8_t hash[32];
} hns_addr_t;

/**
 * Input struct.
 */

typedef struct hns_input_s {
  uint8_t prev[36];
  uint8_t val[8];
  uint8_t seq[4];
  uint8_t type[4];
  uint8_t depth;
  uint32_t path[HNS_MAX_DEPTH];
  hns_varint_t script_ctr;
} hns_input_t;

/**
 * Output struct.
 */

typedef struct hns_output_s {
  uint8_t val[8];
  hns_addr_t addr;
  hns_cov_t cov;
} hns_output_t;

/**
 * Struct used to handle tx
 * parsing and signing state.
 */

typedef struct hns_tx_s {
  bool tx_parsed;
  uint8_t next_field;
  uint8_t next_item;
  uint8_t ins_len;
  uint8_t ins_ctr;
  uint8_t outs_len;
  uint8_t outs_ctr;
  uint8_t ver[4];
  uint8_t prevs[32];
  uint8_t seqs[32];
  uint8_t outs[32];
  uint8_t txid[32];
  uint8_t locktime[4];
  uint8_t change_flag;
  uint8_t change_index;
  uint8_t fees[8];
  hns_addr_t change;
  hns_input_t curr_input;
  hns_output_t curr_output;
  hns_varint_t curr_output_ctr; /* for single output commitments */
} hns_tx_t;

/**
 * Returns the application's version number.
 *
 * In:
 * @param p1 is first instruction param
 * @param p2 is second instruction param
 * @param len is length of the command data buffer
 *
 * Out:
 * @param in is the command data buffer
 * @param out is the output buffer
 * @param flags is bit array for apdu exchange flags
 * @return the status word
 */

uint8_t
hns_apdu_get_app_version(
  uint8_t p1,
  uint8_t p2,
  uint8_t len,
  volatile uint8_t *in,
  volatile uint8_t *out,
  volatile uint8_t *flags
);

/**
 * Derives a public key, extended public key, and/or bech32 address.
 *
 * In:
 * @param p1 is first instruction param
 * @param p2 is second instruction param
 * @param len is length of the command data buffer
 *
 * Out:
 * @param in is the command data buffer
 * @param out is the output buffer
 * @param flags is bit array for apdu exchange flags
 * @return the status word
 */

uint16_t
hns_apdu_get_public_key(
  uint8_t p1,
  uint8_t p2,
  uint16_t len,
  volatile uint8_t *in,
  volatile uint8_t *out,
  volatile uint8_t *flags
);

/**
 * Parses transaction details and signs transaction inputs.
 *
 * In:
 * @param p1 is first instruction param
 * @param p2 is second instruction param
 * @param len is length of the command data buffer
 *
 * Out:
 * @param in is the command data buffer
 * @param out is the output buffer
 * @param flags is bit array for apdu exchange flags
 * @return the status word
 */

uint16_t
hns_apdu_get_input_signature(
  uint8_t p1,
  uint8_t p2,
  uint16_t len,
  volatile uint8_t *in,
  volatile uint8_t *out,
  volatile uint8_t *flags
);
#endif
