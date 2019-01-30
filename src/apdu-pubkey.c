#include <string.h>
#include "apdu.h"
#include "blake2b.h"
#include "ledger.h"
#include "libbase58.h"
#include "segwit-addr.h"
#include "utils.h"

// p1 constants
#define DEFAULT 0x00 // xx0
#define CONFIRM 0x01 // xx1

#define NETWORK_MASK 0x06 // 110
#define MAINNET 0x00      // 00x
#define TESTNET 0x02      // 01x
#define REGTEST 0x04      // 10x
#define SIMNET  0x06      // 11x

// p2 constants
#define PUBKEY 0x00
#define XPUB 0x01
#define ADDR 0x02

#define XPUB_MAINNET 0x0488b21e
#define XPUB_TESTNET 0x043587cf
#define XPUB_REGTEST 0xeab4fa05
#define XPUB_SIMNET 0x0420bd3a

static hns_apdu_pubkey_ctx_t *ctx = &global.pubkey;

#if defined(TARGET_NANOS)
static const bagl_element_t approve[] = {
  LEDGER_UI_BACKGROUND(),
  LEDGER_UI_ICON_LEFT(0x00, BAGL_GLYPH_ICON_CROSS),
  LEDGER_UI_ICON_RIGHT(0x00, BAGL_GLYPH_ICON_CHECK),
  LEDGER_UI_TEXT(0x00, 0, 12, 128, "OK?")
};

static const bagl_element_t compare[] = {
  LEDGER_UI_BACKGROUND(),
  LEDGER_UI_ICON_LEFT(0x01, BAGL_GLYPH_ICON_LEFT),
  LEDGER_UI_ICON_RIGHT(0x02, BAGL_GLYPH_ICON_RIGHT),
  LEDGER_UI_TEXT(0x00, 0, 12, 128, global.pubkey.confirm_str),
  LEDGER_UI_TEXT(0x00, 0, 26, 128, global.pubkey.part_str)
};

static unsigned int
approve_button(unsigned int mask, unsigned int ctr) {
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
compare_button(unsigned int mask, unsigned int ctr) {
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
      UX_DISPLAY(approve, NULL);
      break;
    }
  }

  return 0;
}

static const bagl_element_t *
compare_prepro(const bagl_element_t *e) {
  switch (e->component.userid) {
    case 1:
      return (ctx->full_str_pos == 0) ? NULL : e;

    case 2:
      return (ctx->full_str_pos == ctx->full_str_len - 12) ? NULL : e;

    default:
      return e;
  }
}
#endif

static inline void
create_p2pkh_addr(char *hrp, uint8_t *pubkey, uint8_t *addr) {
  uint8_t hash[20];

  if (blake2b(hash, 20, NULL, 0, pubkey, 33))
    THROW(HNS_CANNOT_INIT_BLAKE2B_CTX);

  if (!segwit_addr_encode(addr, hrp, 0, hash, 20))
    THROW(HNS_CANNOT_ENCODE_ADDRESS);
}

static inline bool
encode_xpub(ledger_xpub_t *xpub, uint8_t network, char *b58, size_t *b58_sz) {
  uint8_t data[82];
  uint8_t checksum[32];
  uint8_t *buf = data;

  switch(network) {
    case MAINNET:
      write_u32(&buf, XPUB_MAINNET, HNS_BE);
      break;

    case TESTNET:
      write_u32(&buf, XPUB_TESTNET, HNS_BE);
      break;

    case REGTEST:
      write_u32(&buf, XPUB_REGTEST, HNS_BE);
      break;

    case SIMNET:
      write_u32(&buf, XPUB_SIMNET, HNS_BE);
      break;

    default:
      THROW(HNS_CANNOT_ENCODE_XPUB);
      break;
  }

  write_u8(&buf, xpub->depth);
  write_bytes(&buf, xpub->fp, sizeof(xpub->fp));
  write_u32(&buf, xpub->path[xpub->depth - 1], HNS_BE);
  write_bytes(&buf, xpub->code, sizeof(xpub->code));
  write_bytes(&buf, xpub->key, sizeof(xpub->key));
  ledger_sha256(checksum, data, 78);
  ledger_sha256(checksum, checksum, 32);
  write_bytes(&buf, checksum, 4);

  PRINTF("we in here\n");
  return b58enc(b58, b58_sz, data, sizeof(data));
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
    case DEFAULT:
    case CONFIRM:
    case DEFAULT | TESTNET:
    case DEFAULT | REGTEST:
    case DEFAULT | SIMNET:
    case CONFIRM | TESTNET:
    case CONFIRM | REGTEST:
    case CONFIRM | SIMNET:
      break;
    default:
      THROW(HNS_INCORRECT_P1);
  }

  switch(p2) {
    case PUBKEY:
    case PUBKEY | XPUB:
    case PUBKEY | ADDR:
    case PUBKEY | XPUB | ADDR:
      break;
    default:
      THROW(HNS_INCORRECT_P2);
  }

  ledger_xpub_t xpub;
  uint8_t unsafe_path = 0;
  uint8_t long_path = 0;

  memset(ctx, 0, sizeof(hns_apdu_pubkey_ctx_t));

  if (!ledger_pin_validated())
    THROW(HNS_SECURITY_CONDITION_NOT_SATISFIED);

  if (!read_bip32_path(&buf, &len, &xpub.depth, xpub.path, &unsafe_path))
    THROW(HNS_CANNOT_READ_BIP32_PATH);

  if (xpub.depth > HNS_ADDR_DEPTH)
    long_path = 1;

  // TODO: throw better exceptions
  if (p2 & ADDR) {
    if (xpub.depth != HNS_ADDR_DEPTH)
      THROW(HNS_INCORRECT_P2);

    if (unsafe_path)
      THROW(HNS_INCORRECT_P2);

    if (long_path)
      THROW(HNS_INCORRECT_P2);
  }

  // Write pubkey to output buffer.
  ledger_ecdsa_derive_xpub(&xpub);
  len = write_bytes(&out, xpub.key, sizeof(xpub.key));

  // Write xpub details to output buffer, or write 0x0000.
  if (p2 & XPUB) {
    len += write_varbytes(&out, xpub.code, sizeof(xpub.code));
    len += write_varbytes(&out, xpub.fp, sizeof(xpub.fp));
  } else {
    len += write_u16(&out, 0, HNS_LE);
  }

  // Write addr to output
  // buffer, or write 0x00.
  uint8_t addr[42];

  if (p2 & ADDR) {
    char hrp[2];

    switch(xpub.path[1]) {
      case HNS_MAINNET:
        strcpy(hrp, "hs");
        break;

      case HNS_TESTNET:
        strcpy(hrp, "ts");
        break;

      case HNS_REGTEST:
        strcpy(hrp, "rs");
        break;

      case HNS_SIMNET:
        strcpy(hrp, "ss");
        break;

      default:
        THROW(HNS_CANNOT_ENCODE_ADDRESS);
        break;
    }

    create_p2pkh_addr(hrp, xpub.key, addr);
    len += write_varbytes(&out, addr, sizeof(addr));
  } else {
    len += write_u8(&out, 0);
  }

#if defined(TARGET_NANOS)
  if ((p1 & CONFIRM) || unsafe_path || long_path) {
    memmove(ctx->store, g_ledger_apdu_buffer, len);
    ctx->store_len = len;

    if (unsafe_path) {
      memmove(ctx->confirm_str, "WARNING", 8);
      memmove(ctx->full_str,
        "Unhardened derivation above BIP44 change level is unsafe.", 57);
      ctx->full_str[57] = '\0';
      ctx->full_str_len = 57;
    } else if(long_path) {
      memmove(ctx->confirm_str, "WARNING", 8);
      memmove(ctx->full_str,
        "Derivation passes BIP44 address level.", 38);
      ctx->full_str[38] = '\0';
      ctx->full_str_len = 38;
    } else if (p2 & ADDR) {
      memmove(ctx->confirm_str, "Address", 8);
      memmove(ctx->full_str, addr, 42);
      ctx->full_str[42] = '\0';
      ctx->full_str_len = 42;
    } else if (p2 & XPUB) {
      uint8_t network = p1 & NETWORK_MASK;
      size_t sz;

      if (!encode_xpub(&xpub, network, ctx->full_str, &sz))
        THROW(HNS_CANNOT_ENCODE_XPUB);

      memmove(ctx->confirm_str, "Xpub", 5);
      ctx->full_str[sz] = '\0';
      ctx->full_str_len = sz;
    } else {
      memmove(ctx->confirm_str, "Public Key", 11);
      bin2hex(ctx->full_str, xpub.key, sizeof(xpub.key));
      ctx->full_str[66] = '\0';
      ctx->full_str_len = 66;
    }

    memmove(ctx->part_str, ctx->full_str, 12);
    ctx->part_str[12] = '\0';
    ctx->full_str_pos = 0;

    UX_DISPLAY(compare, compare_prepro);
    *flags |= LEDGER_ASYNCH_REPLY;
    return 0;
  }
#endif

  return len;
}
