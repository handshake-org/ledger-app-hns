#include <stdbool.h>
#include <string.h>
#include "apdu.h"
#include "blake2b.h"
#include "ledger.h"
#include "segwit-addr.h"
#include "utils.h"

static hns_transaction_t * gtx = &global.tx;

static inline void
addr_create_p2pkh(char *, uint8_t *, uint8_t *);

static inline uint8_t
tx_parse(uint8_t *, volatile uint8_t *);

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
  uint8_t p1,
  uint8_t p2,
  uint8_t len,
  volatile uint8_t * in,
  volatile uint8_t * out,
  volatile uint8_t * flags
) {
  switch(p1) {
    case 0x00:
      break;

    case 0x01: {
      if (!ledger_pin_validated())
        THROW(HNS_EX_SECURITY_STATUS_NOT_SATISFIED);

      // TODO: handle init member
      if (gtx->init)
        THROW(HNS_EX_INVALID_PARSER_STATE);

      gtx->ins_pos = 0;
      gtx->parse_pos = 0;
      gtx->store_len = 0;
      memset(gtx->p_hash, 0, 32);
      memset(gtx->s_hash, 0, 32);
      memset(gtx->o_hash, 0, 32);
      memset(gtx->tx_hash, 0, 32);

      read_bytes(&in, &len, gtx->ver, sizeof(gtx->ver));
      read_bytes(&in, &len, gtx->locktime, sizeof(gtx->locktime));
      read_u8(&in, &len, &gtx->ins_len);
      read_u8(&in, &len, &gtx->outs_len);
      read_varint(&in, &len, &gtx->outs_sz);
      break;
    }

    default:
      THROW(HNS_EX_INCORRECT_P1_P2);
      break;
  };

  switch(p2) {
    case 0x00:
      len = tx_parse(&len, in);
      break;

    case 0x01:
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
  volatile uint8_t * buf
) {
  hns_input_t * in = NULL;

  if (gtx->parse_pos < 0 || gtx->parse_pos > 5)
    THROW(HNS_EX_INVALID_PARSER_STATE);

  if (gtx->parse_pos < 5) {
    if (gtx->ins_pos >= gtx->ins_len)
      THROW(HNS_EX_INVALID_PARSER_STATE);
    in = &gtx->ins[gtx->ins_pos];
  }

  if (gtx->store_len > 0) {
    memmove(gtx->store + gtx->store_len, buf, *len);
    *len += gtx->store_len;
    memmove(buf, gtx->store, *len);
  }

  for (;;) {
    bool should_continue = false;

    switch(gtx->parse_pos) {
      case 0: {
        if (!read_bytes(&buf, len, &in->prevout, sizeof(in->prevout))) {
          gtx->parse_pos = 0;
          break;
        }
      }

      case 1: {
        if (!read_bytes(&buf, len, &in->val, sizeof(in->val))) {
          gtx->parse_pos = 1;
          break;
        }
      }

      case 2: {
        if (!read_bytes(&buf, len, &in->seq, sizeof(in->seq))) {
          gtx->parse_pos = 2;
          break;
        }
      }

      case 3: {
        if (!read_varint(&buf, len, &in->script_len)) {
          gtx->parse_pos = 3;
          break;
        }
      }

      case 4: {
        if (!read_bytes(&buf, len, in->script, in->script_len)) {
          gtx->parse_pos = 4;
          break;
        }

        if (++gtx->ins_pos < gtx->ins_len) {
          should_continue = true;
          in = &gtx->ins[gtx->ins_pos];
          gtx->parse_pos = 0;
          break;
        }

        int i = 0;
        blake2b_init(&gtx->blake, 32, NULL, 0);

        for (i = 0; i < gtx->ins_len; i++)
          blake2b_update(&gtx->blake,
            gtx->ins[i].prevout, sizeof(gtx->ins[i].prevout));

        blake2b_final(&gtx->blake, gtx->p_hash);
        blake2b_init(&gtx->blake, 32, NULL, 0);

        for (i = 0; i < gtx->ins_len; i++)
          blake2b_update(&gtx->blake,
            gtx->ins[i].seq, sizeof(gtx->ins[i].seq));

        blake2b_final(&gtx->blake, gtx->s_hash);
        blake2b_init(&gtx->blake, 32, NULL, 0);
      }

      case 5: {
        if (*len > 0) {
          blake2b_update(&gtx->blake, buf, *len);
          gtx->outs_sz -= *len;
          buf += *len;
          *len = 0;
        }

        if (gtx->outs_sz < 0)
          THROW(HNS_EX_INVALID_PARSER_STATE);

        if (gtx->outs_sz > 0) {
          gtx->parse_pos = 5;
          break;
        }

        blake2b_final(&gtx->blake, gtx->o_hash);
        gtx->parse_pos = 6;
        break;
      }
    }

    if (should_continue)
      continue;

    if (*len < 0)
      THROW(HNS_EX_INVALID_PARSER_STATE);

    if (*len > 0)
      memmove(gtx->store, buf, *len);

    gtx->store_len = *len;

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
  uint8_t type[4];
  uint8_t index;
  uint8_t depth;
  uint32_t path[HNS_MAX_PATH];
  ledger_bip32_node_t n;
  hns_input_t in;

  if (!read_bip32_path(&buf, len, &depth, path))
    THROW(INVALID_PARAMETER);

  if (!read_u8(&buf, len, &index))
    THROW(INVALID_PARAMETER);

  if (!read_bytes(&buf, len, type, sizeof(type)))
    THROW(INVALID_PARAMETER);

  in = gtx->ins[index];
  blake2b_init(&gtx->blake, 32, NULL, 0);
  blake2b_update(&gtx->blake, gtx->ver, sizeof(gtx->ver));
  blake2b_update(&gtx->blake, gtx->p_hash, sizeof(gtx->p_hash));
  blake2b_update(&gtx->blake, gtx->s_hash, sizeof(gtx->s_hash));
  blake2b_update(&gtx->blake, in.prevout, sizeof(in.prevout));
  blake2b_update(&gtx->blake, &in.script_len, 1);
  blake2b_update(&gtx->blake, in.script, in.script_len);
  blake2b_update(&gtx->blake, in.val, sizeof(in.val));
  blake2b_update(&gtx->blake, in.seq, sizeof(in.seq));
  blake2b_update(&gtx->blake, gtx->o_hash, sizeof(gtx->o_hash));
  blake2b_update(&gtx->blake, gtx->locktime, sizeof(gtx->locktime));
  blake2b_update(&gtx->blake, type, sizeof(type));
  blake2b_final(&gtx->blake, gtx->tx_hash);
  ledger_bip32_node_derive(&n, path, depth);
  ledger_ecdsa_sign(&n.prv, gtx->tx_hash, sizeof(gtx->tx_hash), sig);

  return sig[1] + 2;
}
