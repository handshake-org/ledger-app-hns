#ifndef _HNS_APDU_H
#define _HNS_APDU_H

#include <stdbool.h>
#include <stdint.h>
#include "utils.h"

#define HNS_OFFSET_CLA 0x00
#define HNS_OFFSET_INS 0x01
#define HNS_OFFSET_P1 0x02
#define HNS_OFFSET_P2 0x03
#define HNS_OFFSET_LC 0x04
#define HNS_OFFSET_CDATA 0x05

#define HNS_OK 0x9000
#define HNS_INCORRECT_P1 0x6Af1
#define HNS_INCORRECT_P2 0x6Af2
#define HNS_INCORRECT_LC 0x6700
#define HNS_INCORRECT_CDATA 0x6a80
#define HNS_INS_NOT_SUPPORTED 0x6d00
#define HNS_CLA_NOT_SUPPORTED 0x6e00
#define HNS_SECURITY_CONDITION_NOT_SATISFIED 0x6982
#define HNS_USER_REJECTED 0x6985

#define HNS_CANNOT_INIT_BLAKE2B_CTX 0x13
#define HNS_CANNOT_ENCODE_ADDRESS 0x14
#define HNS_CANNOT_READ_BIP32_PATH 0x15
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

typedef struct hns_input_s {
  uint8_t prev[36];
  uint8_t val[8];
  uint8_t seq[4];
} hns_input_t;

typedef struct hns_apdu_pubkey_ctx_s {
  uint8_t store[114];
  uint8_t store_len;
  uint8_t confirm_str[20];
  uint8_t part_str[13];
  uint8_t full_str[67];
  uint8_t full_str_len;
  uint8_t full_str_pos;
} hns_apdu_pubkey_ctx_t;

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
  uint8_t sig[73];
  uint8_t part_str[13];
  uint8_t full_str[65];
  uint8_t full_str_len;
  uint8_t full_str_pos;
} hns_apdu_signature_ctx_t;

typedef union {
  hns_apdu_pubkey_ctx_t pubkey;
  hns_apdu_signature_ctx_t signature;
} global_apdu_ctx_t;

extern global_apdu_ctx_t global;

volatile uint16_t
hns_apdu_get_app_version(
  uint8_t p1,
  uint8_t p2,
  uint16_t len,
  volatile uint8_t *in,
  volatile uint8_t *out,
  volatile uint8_t *flags
);

volatile uint16_t
hns_apdu_get_public_key(
  uint8_t p1,
  uint8_t p2,
  uint16_t len,
  volatile uint8_t *in,
  volatile uint8_t *out,
  volatile uint8_t *flags
);

volatile uint16_t
hns_apdu_get_input_signature(
  uint8_t p1,
  uint8_t p2,
  uint16_t len,
  volatile uint8_t *in,
  volatile uint8_t *out,
  volatile uint8_t *flags
);
#endif
