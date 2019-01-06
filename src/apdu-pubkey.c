#include <string.h>
#include "apdu.h"
#include "blake2b.h"
#include "ledger.h"
#include "utils.h"

#define P1_ADDRESS_NO_CONFIRM 0x00
#define P1_PUBKEY_NO_CONFIRM 0x01
#define P1_ADDRESS_CONFIRM 0x02
#define P1_PUBKEY_CONFIRM 0x03

#define P2_MAINNET 0x00
#define P2_TESTNET 0x01
#define P2_SIMNET 0x02
#define P2_REGTEST 0x03

static const bagl_element_t ledger_ui_compare_public_key[] = {
  LEDGER_UI_BACKGROUND(),
  LEDGER_UI_ICON_LEFT(0x01, BAGL_GLYPH_ICON_LEFT),
  LEDGER_UI_ICON_RIGHT(0x02, BAGL_GLYPH_ICON_RIGHT),
  LEDGER_UI_TEXT(0x00, 0, 12, 128, "Compare:"),
  LEDGER_UI_TEXT(0x00, 0, 26, 128, global.pub.part_str),
};

static const bagl_element_t ledger_ui_approve_public_key[] = {
  LEDGER_UI_BACKGROUND(),
  LEDGER_UI_ICON_LEFT(0x00, BAGL_GLYPH_ICON_CROSS),
  LEDGER_UI_ICON_RIGHT(0x00, BAGL_GLYPH_ICON_CHECK),
  LEDGER_UI_TEXT(0x00, 0, 12, 128, global.pub.confirm_str),
};

static hns_get_public_key_ctx_t * gpub = &global.pub;

static unsigned int
ledger_ui_compare_public_key_button(unsigned int mask, unsigned int ctr) {
  switch (mask) {
    case BUTTON_LEFT:
    case BUTTON_EVT_FAST | BUTTON_LEFT: {
      if (gpub->pos > 0)
        gpub->pos--;

      os_memmove(gpub->part_str, gpub->full_str + gpub->pos, 12);
      UX_REDISPLAY();
      break;
    }

    case BUTTON_RIGHT:
    case BUTTON_EVT_FAST | BUTTON_RIGHT: {
      uint8_t size = gpub->gen_addr ? 42 : 66;

      if (gpub->pos < size - 12)
        gpub->pos++;

      os_memmove(gpub->part_str, gpub->full_str + gpub->pos, 12);
      UX_REDISPLAY();
      break;
    }

    case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT: {
      ledger_ui_idle();
      break;
    }
  }

  return 0;
}

static const bagl_element_t *
ledger_ui_compare_public_key_prepro(const bagl_element_t * e) {
  uint8_t size = gpub->gen_addr ? 42 : 66;

  if ((e->component.userid == 1 && gpub->pos == 0) ||
      (e->component.userid == 2 && gpub->pos == size - 12))
    return NULL;

  return e;
}

static unsigned int
ledger_ui_approve_public_key_button(unsigned int mask, unsigned int ctr) {
  switch (mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT: {
      ledger_apdu_exchange_with_sw(IO_RETURN_AFTER_TX, HNS_SW_USER_REJECTED, 0);
      ledger_ui_idle();
      break;
    }

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT: {
      uint8_t ** out = &G_io_apdu_buffer;
      uint8_t len = 0;

      hns_bip32_node_t * n = &gpub->n;
      ledger_ecdsa_derive(n->path, n->depth, n->chaincode, &n->prv, &n->pub);
      hns_create_p2pkh_addr(gpub->hrp, n->pub.W, gpub->addr);
      len  = write_varbytes(&out, n->pub.W, 33);
      len += write_varbytes(&out, gpub->addr, sizeof(gpub->addr));
      len += write_bytes(&out, n->chaincode, sizeof(n->chaincode));

      if (len != 109)
        THROW(HNS_EX_INCORRECT_WRITE_LEN);

      io_exchange_with_code(HNS_SW_OK, len);

      if (gpub->gen_addr) {
        os_memmove(gpub->full_str, gpub->addr, sizeof(gpub->addr));
        gpub->full_str[sizeof(gpub->addr)] = '\0';
      } else {
        hns_bin2hex(gpub->full_str, n->pub.W, 33);
      }

      os_memmove(gpub->confirm_str, "Compare:", 9);
      os_memmove(gpub->part_str, gpub->full_str, 12);
      gpub->part_str[12] = '\0';
      gpub->pos = 0;

      UX_DISPLAY(ledger_ui_compare_public_key, ledger_ui_compare_public_key_prepro);
      break;
    }
  }

  return 0;
}

volatile uint8_t
hns_apdu_get_public_key(
  uint8_t p1,
  uint8_t p2,
  uint8_t len,
  volatile uint8_t * buf,
  volatile uint8_t * out,
  volatile uint8_t * flags
) {
  switch(p1) {
    case P1_ADDRESS_CONFIRM:
      gpub->confirm = true;
      gpub->gen_addr = true;
      memmove(gpub->confirm_str, "Generate Address?", 18);
      break;

    case P1_ADDRESS_NO_CONFIRM:
      gpub->confirm = false;
      gpub->gen_addr = true;
      break;

    case P1_PUBKEY_CONFIRM:
      gpub->confirm = true;
      memmove(gpub->confirm_str, "Generate Public Key?", 21);
      gpub->gen_addr = false;
      break;

    case P1_PUBKEY_NO_CONFIRM:
      gpub->confirm = false;
      gpub->gen_addr = false;
      break;

    default:
      THROW(HNS_EX_INCORRECT_P1_P2);
      break;
  }

  switch(p2) {
    case P2_MAINNET:
      strcpy(gpub->hrp, "hs");
      break;

    case P2_TESTNET:
      strcpy(gpub->hrp, "ts");
      break;

    case P2_SIMNET:
      strcpy(gpub->hrp, "ss");
      break;

    case P2_REGTEST:
      strcpy(gpub->hrp, "rs");
      break;

    default:
      THROW(HNS_EX_INCORRECT_P1_P2);
      break;
  }

  hns_bip32_node_t * n = &gpub->n;

  if (!ledger_pin_validated())
    THROW(HNS_SW_SECURITY_STATUS_NOT_SATISFIED);

  if (!read_bip32_path(&buf, &len, &n->depth, n->path))
    THROW(HNS_EX_CANNOT_READ_BIP32_PATH);

  if (gpub->confirm) {
    PRINTF("Should confirm on screen\n");
    UX_DISPLAY(ledger_ui_approve_public_key, NULL);
    *flags |= IO_ASYNCH_REPLY;
    return 0;
  }

  ledger_ecdsa_derive(n->path, n->depth, n->chaincode, &n->prv, &n->pub);
  hns_create_p2pkh_addr(gpub->hrp, n->pub.W, gpub->addr);

  len  = write_varbytes(&out, n->pub.W, 33);
  len += write_varbytes(&out, gpub->addr, sizeof(gpub->addr));
  len += write_bytes(&out, n->chaincode, sizeof(n->chaincode));

  if (len != 109)
    THROW(HNS_EX_INCORRECT_WRITE_LEN);

  return len;
}
