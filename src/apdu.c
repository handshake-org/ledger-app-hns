#include <stdbool.h>
#include <string.h>
#include "apdu.h"
#include "blake2b.h"
#include "ledger.h"
#include "segwit-addr.h"
#include "utils.h"

static hns_transaction_t * tx = &global.tx;

static inline void
addr_create_p2pkh(char *, uint8_t *, uint8_t *);

static uint8_t
tx_parse(uint8_t *, volatile uint8_t *);

static uint8_t
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

  // TODO: use descriptive exception
  if (!read_bip32_path(&buf, &len, &depth, path))
    THROW(INVALID_PARAMETER);

  ledger_bip32_node_derive(&n, path, depth);
  addr_create_p2pkh(hrp, n.pub.W, addr);

  len  = write_varbytes(&out, n.pub.W, 33);
  len += write_varbytes(&out, addr, sizeof(addr));
  len += write_bytes(&out, n.code, sizeof(n.code));

  // TODO: better io exception
  if (len != 109)
    THROW(EXCEPTION);

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

      // TODO: throw better exception
      if (tx->init)
        THROW(EXCEPTION);

      tx->in_pos = 0;
      tx->out_pos = 0;
      tx->parse_pos = 0;
      tx->store_len = 0;

      read_bytes(&in, &len, tx->ver, sizeof(tx->ver));
      read_bytes(&in, &len, tx->locktime, sizeof(tx->locktime));
      read_u8(&in, &len, &tx->ins_len);
      read_u8(&in, &len, &tx->outs_len);
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

static uint8_t
tx_parse(
  uint8_t * len,
  volatile uint8_t * buf
) {
  hns_input_t * in = NULL;
  hns_output_t * out = NULL;

  if (tx->parse_pos < 0 || tx->parse_pos > 7)
    THROW(INVALID_PARAMETER);

  if (tx->in_pos < tx->ins_len)
    in = &tx->ins[tx->in_pos];

  if (tx->out_pos < tx->outs_len)
    out = &tx->outs[tx->out_pos];

  // TODO(boymanjor): THROW(INVALID_PARSER_STATE)
  if (in == NULL && out == NULL)
    THROW(INVALID_PARAMETER);

  if (tx->store_len == 0) {
    memcpy(tx->store, buf, *len);
  } else {
    memcpy(tx->store + tx->store_len, buf, *len);
    *len += tx->store_len;
  }

  buf = tx->store;

  for (;;) {
    bool should_continue = false;

    switch(tx->parse_pos) {
      case 0: {
        if (!read_bytes(&buf, len, &in->prevout, sizeof(in->prevout))) {
          tx->parse_pos = 0;
          break;
        }
      }

      case 1: {
        if (!read_bytes(&buf, len, &in->val, sizeof(in->val))) {
          tx->parse_pos = 1;
          break;
        }
      }

      case 2: {
        if (!read_bytes(&buf, len, &in->seq, sizeof(in->seq))) {
          tx->parse_pos = 2;
          break;
        }
      }

      case 3: {
        if (!read_varint(&buf, len, &in->script_len)) {
          tx->parse_pos = 3;
          break;
        }
      }

      case 4: {
        if (!read_bytes(&buf, len, in->script, in->script_len)) {
          tx->parse_pos = 4;
          break;
        }

        if (++tx->in_pos < tx->ins_len) {
          in = &tx->ins[tx->in_pos];
          tx->parse_pos = 0;
          should_continue = true;
          break;
        }
      }

      case 5: {
        if (!read_bytes(&buf, len, &out->val, sizeof(out->val))) {
          tx->parse_pos = 5;
          break;
        }
      }

      case 6: {
        uint8_t * data = out->addr_data;
        uint8_t * data_len = &out->addr_len;
        uint8_t data_sz = sizeof(out->addr_data);

        if (!read_varbytes(&buf, len, data, data_sz, data_len)) {
          tx->parse_pos = 6;
          break;
        }
      }

      case 7: {
        uint8_t * data = out->covenant_data;
        uint8_t * data_len = &out->covenant_len;
        uint8_t data_sz = sizeof(out->covenant_data);

        if (!read_varbytes(&buf, len, data, data_sz, data_len)) {
          tx->parse_pos = 7;
          break;
        }

        if (++tx->out_pos < tx->outs_len) {
          out = &tx->outs[tx->out_pos];
          tx->parse_pos = 5;
          should_continue = true;
          break;
        }

        tx->parse_pos = 8;
        break;
      }
    }

    if (should_continue)
      continue;

    if (*len > 0)
      memcpy(tx->store, buf, *len);

    // TODO: THROW(INVALID_PARSER_STATE)
    if (*len < 0)
      THROW(EXCEPTION);

    tx->store_len = *len;
    break;
  }

  return *len;
};

static uint8_t
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

  hns_input_t in = tx->ins[index];
  blake2b_init(&ctx, 32, NULL, 0);
  int i = 0;

  for (i = 0; i < tx->ins_len; i++)
    blake2b_update(&ctx, tx->ins[i].prevout, sizeof(tx->ins[i].prevout));

  blake2b_final(&ctx, tx->p_hash);
  blake2b_init(&ctx, 32, NULL, 0);

  for (i = 0; i < tx->ins_len; i++)
    blake2b_update(&ctx, tx->ins[i].seq, sizeof(tx->ins[i].seq));

  blake2b_final(&ctx, tx->s_hash);
  blake2b_init(&ctx, 32, NULL, 0);

  for (i = 0; i < tx->outs_len; i++) {
    hns_output_t o = tx->outs[i];
    blake2b_update(&ctx, o.val, sizeof(o.val));
    blake2b_update(&ctx, o.addr_data, o.addr_len);
    blake2b_update(&ctx, o.covenant_data, o.covenant_len);
  }

  blake2b_final(&ctx, tx->o_hash);

  blake2b_init(&ctx, 32, NULL, 0);
  blake2b_update(&ctx, tx->ver, sizeof(tx->ver));
  blake2b_update(&ctx, tx->p_hash, sizeof(tx->p_hash));
  blake2b_update(&ctx, tx->s_hash, sizeof(tx->s_hash));
  blake2b_update(&ctx, in.prevout, sizeof(in.prevout));
  blake2b_update(&ctx, &in.script_len, 1);
  blake2b_update(&ctx, in.script, in.script_len);
  blake2b_update(&ctx, in.val, sizeof(in.val));
  blake2b_update(&ctx, in.seq, sizeof(in.seq));
  blake2b_update(&ctx, tx->o_hash, sizeof(tx->o_hash));
  blake2b_update(&ctx, tx->locktime, sizeof(tx->locktime));
  blake2b_update(&ctx, type, sizeof(type));
  blake2b_final(&ctx, tx->tx_hash);

  ledger_bip32_node_derive(&n, path, depth);
  ledger_ecdsa_sign(&n.prv, tx->tx_hash, sizeof(tx->tx_hash), sig);

  return sig[1] + 2;
}
