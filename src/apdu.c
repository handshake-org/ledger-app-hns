#include <stdbool.h>
#include <string.h>
#include "apdu.h"
#include "blake2b.h"
#include "ledger.h"
#include "segwit-addr.h"
#include "utils.h"

volatile uint8_t
hns_apdu_get_firmware_version(
  volatile uint8_t * buf,
  volatile uint8_t * flags
) {
  uint8_t p1 = buf[HNS_OFFSET_P1];
  uint8_t p2 = buf[HNS_OFFSET_P2];
  uint8_t lc = buf[HNS_OFFSET_LC];

  if(p1 != 0x00)
    THROW(HNS_EX_INCORRECT_P1_P2);

  if(p2 != 0x00)
    THROW(HNS_EX_INCORRECT_P1_P2);

  if(lc != 0x00)
    THROW(HNS_EX_INCORRECT_LENGTH);

  if (!ledger_pin_validated())
    THROW(HNS_EX_SECURITY_STATUS_NOT_SATISFIED);

  buf[0] = HNS_APP_MAJOR_VERSION;
  buf[1] = HNS_APP_MINOR_VERSION;
  buf[2] = HNS_APP_PATCH_VERSION;

  return 0x03;
}

volatile uint8_t
hns_apdu_get_wallet_public_key(
  volatile uint8_t * buf,
  volatile uint8_t * flags
) {
  uint8_t p1 = buf[HNS_OFFSET_P1];
  uint8_t p2 = buf[HNS_OFFSET_P2];
  uint8_t lc = buf[HNS_OFFSET_LC];
  uint8_t * cdata = buf + HNS_OFFSET_CDATA;
  char hrp[2];

  switch(p1) {
    case 0x00:
    case 0x01:
      // TODO(boymanjor): display addr
      break;
    default:
      THROW(HNS_EX_INCORRECT_P1_P2);
  }

  switch(p2) {
    case 0x00:
      strcpy(hrp, "hs");
    case 0x01:
      strcpy(hrp, "ts");
    case 0x02:
      strcpy(hrp, "ss");
    case 0x03:
      strcpy(hrp, "rs");
      break;
    default:
      THROW(HNS_EX_INCORRECT_P1_P2);
  }

  if (lc < 1 || lc > HNS_MAX_PATH_LEN)
    THROW(HNS_SW_INCORRECT_LENGTH);

  if (!ledger_pin_validated())
    THROW(HNS_SW_SECURITY_STATUS_NOT_SATISFIED);

  uint8_t depth = *(cdata++);

  if (depth > HNS_MAX_PATH)
    THROW(INVALID_PARAMETER);

  uint32_t path[depth];
  uint8_t i;

  for (i = 0; i < depth; i++) {
    hns_read_u32(&path[i], cdata, true);
    cdata += 4;
  }

  ledger_bip32_node_t n;
  ledger_bip32_node_derive(&n, path, depth, hrp);

  uint8_t * out = buf;

  *(out++) = sizeof(n.pub);
  memmove(out, n.pub, sizeof(n.pub));
  out += sizeof(n.pub);
  *(out++) = sizeof(n.addr);
  memmove(out, n.addr, sizeof(n.addr));
  out += sizeof(n.addr);
  memmove(out, n.code, sizeof(n.code));
  out += sizeof(n.code);

  return 1 + sizeof(n.pub) + 1 + sizeof(n.addr) + sizeof(n.code);
}

typedef struct
hns_transaction_ctx_s {
  uint32_t version;
  uint32_t no_inputs;
  uint8_t inputs[no_inputs][32 + 4]; // txhash + index
  uint8_t sequences[no_inputs];
} hns_transaction_ctx_t;

static void
prepare_inputs(
  hns_transaction_ctx_t ctx,
  volatile uint8_t * buf,
  uint8_t len
) {

}

static void
prepare_outputs(
  hns_transaction_ctx_t ctx,
  volatile uint8_t * buf,
  uint8_t len
) {

}

static void
sign_input(
  hns_transaction_ctx_t ctx,
  volatile uint8_t * buf,
  uint8_t len
) {

}

volatile uint8_t
hns_apdu_tx_sign(volatile uint8_t * buf, volatile uint8_t * flags) {
  uint8_t p1 = buf[HNS_OFFSET_P1];
  uint8_t p2 = buf[HNS_OFFSET_P2];
  uint8_t lc = buf[HNS_OFFSET_LC];
  uint8_t * cdata = buf + HNS_OFFSET_CDATA;
  static hns_transaction_ctx_t ctx;

  switch(p1) {
    case 0x00:
      break;

    case 0x01:
      if (!ledger_pin_validated())
        THROW(HNS_EX_SECURITY_STATUS_NOT_SATISFIED);

      memset(&ctx, 0, sizeof(ctx));
      hns_read_u32(&ctx.version, cdata, true);
      hns_read_varint(&ctx.version, cdata + 4);
      return 0;
      break;

    default:
      THROW(HNS_EX_INCORRECT_P1_P2);
      break;
  };

  switch(p2) {
    case 0x01:
      prepare_inputs(ctx, cdata, lc);
      break;

    case 0x02:
      prepare_outputs(ctx, cdata, lc);
      break;

    case 0x04:
      sign_input(ctx, cdata, lc);
      break;

    default:
      THROW(HNS_EX_INCORRECT_P1_P2);
      break;
  }

  return 0;
}
