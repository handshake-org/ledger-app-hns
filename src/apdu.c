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

      gtx->in_pos = 0;
      gtx->out_pos = 0;
      gtx->parse_pos = 0;
      gtx->store_len = 0;

      read_bytes(&in, &len, gtx->ver, sizeof(gtx->ver));
      read_bytes(&in, &len, gtx->locktime, sizeof(gtx->locktime));
      read_u8(&in, &len, &gtx->ins_len);
      read_u8(&in, &len, &gtx->outs_len);
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
  hns_output_t * out = NULL;

  if (gtx->parse_pos < 0 || gtx->parse_pos > 7)
    THROW(HNS_EX_INVALID_PARSER_STATE);

  if (gtx->in_pos < gtx->ins_len)
    in = &gtx->ins[gtx->in_pos];

  if (gtx->out_pos < gtx->outs_len)
    out = &gtx->outs[gtx->out_pos];

  if (in == NULL && out == NULL)
    THROW(HNS_EX_INVALID_PARSER_STATE);

  if (gtx->store_len == 0) {
    memcpy(gtx->store, buf, *len);
  } else {
    memcpy(gtx->store + gtx->store_len, buf, *len);
    *len += gtx->store_len;
  }

  buf = gtx->store;

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

        if (++gtx->in_pos < gtx->ins_len) {
          in = &gtx->ins[gtx->in_pos];
          gtx->parse_pos = 0;
          should_continue = true;
          break;
        }
      }

      case 5: {
        if (!read_bytes(&buf, len, &out->val, sizeof(out->val))) {
          gtx->parse_pos = 5;
          break;
        }
      }

      case 6: {
        uint8_t * data = out->addr_data;
        uint8_t * data_len = &out->addr_len;
        uint8_t data_sz = sizeof(out->addr_data);

        if (!read_varbytes(&buf, len, data, data_sz, data_len)) {
          gtx->parse_pos = 6;
          break;
        }
      }

      case 7: {
        uint8_t * data = out->covenant_data;
        uint8_t * data_len = &out->covenant_len;
        uint8_t data_sz = sizeof(out->covenant_data);

        if (!read_varbytes(&buf, len, data, data_sz, data_len)) {
          gtx->parse_pos = 7;
          break;
        }

        if (++gtx->out_pos < gtx->outs_len) {
          out = &gtx->outs[gtx->out_pos];
          gtx->parse_pos = 5;
          should_continue = true;
          break;
        }

        gtx->parse_pos = 8;
        break;
      }
    }

    if (should_continue)
      continue;

    if (*len > 0)
      memcpy(gtx->store, buf, *len);

    if (*len < 0)
      THROW(HNS_EX_INVALID_PARSER_STATE);

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
  blake2b_ctx ctx;
  ledger_bip32_node_t n;

  if (!read_bip32_path(&buf, len, &depth, path))
    THROW(INVALID_PARAMETER);

  if (!read_u8(&buf, len, &index))
    THROW(INVALID_PARAMETER);

  if (!read_bytes(&buf, len, type, sizeof(type)))
    THROW(INVALID_PARAMETER);

  hns_input_t in = gtx->ins[index];
  blake2b_init(&ctx, 32, NULL, 0);
  int i = 0;

  for (i = 0; i < gtx->ins_len; i++)
    blake2b_update(&ctx, gtx->ins[i].prevout, sizeof(gtx->ins[i].prevout));

  blake2b_final(&ctx, gtx->p_hash);
  blake2b_init(&ctx, 32, NULL, 0);

  for (i = 0; i < gtx->ins_len; i++)
    blake2b_update(&ctx, gtx->ins[i].seq, sizeof(gtx->ins[i].seq));

  blake2b_final(&ctx, gtx->s_hash);
  blake2b_init(&ctx, 32, NULL, 0);

  for (i = 0; i < gtx->outs_len; i++) {
    hns_output_t o = gtx->outs[i];
    blake2b_update(&ctx, o.val, sizeof(o.val));
    blake2b_update(&ctx, o.addr_data, o.addr_len);
    blake2b_update(&ctx, o.covenant_data, o.covenant_len);
  }

  blake2b_final(&ctx, gtx->o_hash);

  blake2b_init(&ctx, 32, NULL, 0);
  blake2b_update(&ctx, gtx->ver, sizeof(gtx->ver));
  blake2b_update(&ctx, gtx->p_hash, sizeof(gtx->p_hash));
  blake2b_update(&ctx, gtx->s_hash, sizeof(gtx->s_hash));
  blake2b_update(&ctx, in.prevout, sizeof(in.prevout));
  blake2b_update(&ctx, &in.script_len, 1);
  blake2b_update(&ctx, in.script, in.script_len);
  blake2b_update(&ctx, in.val, sizeof(in.val));
  blake2b_update(&ctx, in.seq, sizeof(in.seq));
  blake2b_update(&ctx, gtx->o_hash, sizeof(gtx->o_hash));
  blake2b_update(&ctx, gtx->locktime, sizeof(gtx->locktime));
  blake2b_update(&ctx, type, sizeof(type));
  blake2b_final(&ctx, gtx->tx_hash);

  ledger_bip32_node_derive(&n, path, depth);
  ledger_ecdsa_sign(&n.prv, gtx->tx_hash, sizeof(gtx->tx_hash), sig);

  return sig[1] + 2;
}
