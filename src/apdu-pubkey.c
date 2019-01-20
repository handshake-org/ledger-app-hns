#include <string.h>
#include "apdu.h"
#include "blake2b.h"
#include "ledger.h"
#include "segwit-addr.h"
#include "utils.h"

#define P1_NO_CONFIRM 0x00
#define P1_CONFIRM_PUBKEY 0x01
#define P1_CONFIRM_ADDRESS 0x03

#define CONFIRM_FLAG 0x01
#define ADDRESS_FLAG 0x02

#define P2_MAINNET 0x00
#define P2_TESTNET 0x01
#define P2_SIMNET 0x02
#define P2_REGTEST 0x03

static hns_apdu_pubkey_ctx_t *ctx = &global.pubkey;

static const bagl_element_t approve_public_key[] = {
  LEDGER_UI_BACKGROUND(),
  LEDGER_UI_ICON_LEFT(0x00, BAGL_GLYPH_ICON_CROSS),
  LEDGER_UI_ICON_RIGHT(0x00, BAGL_GLYPH_ICON_CHECK),
  LEDGER_UI_TEXT(0x00, 0, 12, 128, "Correct match?")
};

static const bagl_element_t compare_public_key[] = {
  LEDGER_UI_BACKGROUND(),
  LEDGER_UI_ICON_LEFT(0x01, BAGL_GLYPH_ICON_LEFT),
  LEDGER_UI_ICON_RIGHT(0x02, BAGL_GLYPH_ICON_RIGHT),
  LEDGER_UI_TEXT(0x00, 0, 12, 128, global.pubkey.confirm_str),
  LEDGER_UI_TEXT(0x00, 0, 26, 128, global.pubkey.part_str)
};

static unsigned int
approve_public_key_button(unsigned int mask, unsigned int ctr) {
  switch (mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT: {
      memset(g_ledger_apdu_buffer, 0, g_ledger_apdu_buffer_size);
      ledger_apdu_exchange(LEDGER_RETURN_AFTER_TX, 0, HNS_USER_REJECTED);
      ledger_ui_idle();
      break;
    }

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT: {
      memmove(g_ledger_apdu_buffer, ctx->store, ctx->store_len);
      ledger_apdu_exchange(LEDGER_RETURN_AFTER_TX, ctx->store_len, HNS_OK);
      ledger_ui_idle();
      break;
    }
  }

  return 0;
}

static unsigned int
compare_public_key_button(unsigned int mask, unsigned int ctr) {
  switch (mask) {
    case BUTTON_LEFT:
    case BUTTON_EVT_FAST | BUTTON_LEFT: {
      if (ctx->full_str_pos > 0)
        ctx->full_str_pos--;

      memmove(ctx->part_str, ctx->full_str + ctx->full_str_pos, 12);
      UX_REDISPLAY();
      break;
    }

    case BUTTON_RIGHT:
    case BUTTON_EVT_FAST | BUTTON_RIGHT: {
      if (ctx->full_str_pos < ctx->full_str_len - 12)
        ctx->full_str_pos++;

      memmove(ctx->part_str, ctx->full_str + ctx->full_str_pos, 12);
      UX_REDISPLAY();
      break;
    }

    case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT: {
      UX_DISPLAY(approve_public_key, NULL);
      break;
    }
  }

  return 0;
}

static const bagl_element_t *
compare_public_key_prepro(const bagl_element_t *e) {
  switch (e->component.userid) {
    case 1:
      return (ctx->full_str_pos == 0) ? NULL : e;

    case 2:
      return (ctx->full_str_pos == ctx->full_str_len - 12) ? NULL : e;

    default:
      return e;
  }
}


static inline void
create_p2pkh_addr(char *hrp, uint8_t *pub, uint8_t *out) {
  uint8_t pkh[20];
  uint8_t addr[42];

  if (blake2b(pkh, 20, NULL, 0, pub, 33))
    THROW(HNS_CANNOT_INIT_BLAKE2B_CTX);

  if (!segwit_addr_encode(addr, hrp, 0, pkh, 20))
    THROW(HNS_CANNOT_ENCODE_ADDRESS);

  memmove(out, addr, sizeof(addr));
}

volatile uint16_t
hns_apdu_get_public_key(
  uint8_t p1,
  uint8_t p2,
  uint16_t len,
  volatile uint8_t *buf,
  volatile uint8_t *out,
  volatile uint8_t *flags
) {
  switch(p1) {
    case P1_NO_CONFIRM:
    case P1_CONFIRM_PUBKEY:
    case P1_CONFIRM_ADDRESS:
      break;

    default:
      THROW(HNS_INCORRECT_P1);
      break;
  }

  char hrp[2];

  switch(p2) {
    case P2_MAINNET:
      strcpy(hrp, "hs");
      break;

    case P2_TESTNET:
      strcpy(hrp, "ts");
      break;

    case P2_SIMNET:
      strcpy(hrp, "ss");
      break;

    case P2_REGTEST:
      strcpy(hrp, "rs");
      break;

    default:
      THROW(HNS_INCORRECT_P2);
      break;
  }

  uint8_t depth;
  uint32_t path[HNS_MAX_PATH];

  if (!ledger_pin_validated())
    THROW(HNS_SECURITY_CONDITION_NOT_SATISFIED);

  if (!read_bip32_path(&buf, &len, &depth, path))
    THROW(HNS_CANNOT_READ_BIP32_PATH);

  ledger_xpub_t xpub;
  ledger_ecdsa_derive_xpub(path, depth, &xpub);

  uint8_t addr[42];
  create_p2pkh_addr(hrp, xpub.key, addr);

  len  = write_varbytes(&out, xpub.key, 33);
  len += write_varbytes(&out, addr, 42);
  len += write_bytes(&out, xpub.code, 32);

  if (len != 109)
    THROW(HNS_INCORRECT_WRITE_LEN);

  if (p1 & CONFIRM_FLAG) {
    memmove(ctx->store, g_ledger_apdu_buffer, len);
    ctx->store_len = len;

    if (p1 & ADDRESS_FLAG) {
      memmove(ctx->confirm_str, "Confirm address:", 17);
      memmove(ctx->full_str, addr, 42);
      ctx->full_str[42] = '\0';
      ctx->full_str_len = 42;
    } else {
      memmove(ctx->confirm_str, "Confirm public key:", 20);
      bin2hex(ctx->full_str, xpub.key, sizeof(xpub.key));
      ctx->full_str[66] = '\0';
      ctx->full_str_len = 66;
    }

    memmove(ctx->part_str, ctx->full_str, 12);
    ctx->part_str[12] = '\0';
    ctx->full_str_pos = 0;

    UX_DISPLAY(compare_public_key, compare_public_key_prepro);
    *flags |= LEDGER_ASYNCH_REPLY;
    return 0;
  }

  return len;
}
