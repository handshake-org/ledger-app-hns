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

static ledger_ui_ctx_t *ctx = &g_ledger.ui;

static inline void
encode_addr(char *hrp, uint8_t *pubkey, char *addr) {
  uint8_t hash[20];

  if (blake2b(hash, 20, NULL, 0, pubkey, 33))
    THROW(HNS_CANNOT_INIT_BLAKE2B_CTX);

  if (!segwit_addr_encode(addr, hrp, 0, hash, 20))
    THROW(HNS_CANNOT_ENCODE_ADDRESS);
}

static inline bool
encode_xpub(
  ledger_ecdsa_xpub_t *xpub,
  uint8_t network,
  char *b58,
  size_t *b58_sz
) {
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

  ledger_ecdsa_xpub_t xpub;
  uint8_t unsafe_path = 0;
  uint8_t long_path = 0;

  memset(ctx, 0, sizeof(ledger_ui_ctx_t));

  if (!ledger_unlocked())
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

  // Write addr to output buffer, or write 0x00.
  char addr[75];

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

    encode_addr(hrp, xpub.key, addr);
    len += write_varbytes(&out, addr, sizeof(addr));
  } else {
    len += write_u8(&out, 0);
  }

#if defined(TARGET_NANOS)
  if ((p1 & CONFIRM) || unsafe_path || long_path) {
    char *header = NULL;
    char *message = NULL;

    ledger_apdu_cache_write(len);

    if (unsafe_path) {
      header = "WARNING";
      message = "Unhardened derivation above BIP44 change level is unsafe.";
    } else if(long_path) {
      header = "WARNING";
      message = "Derivation passes BIP44 address level.";
    } else if (p2 & ADDR) {
      header = "Address";
      message = addr;
    } else if (p2 & XPUB) {
      uint8_t message_sz = sizeof(ctx->message);
      header = "XPUB";
      message = ctx->message;

      if (!encode_xpub(&xpub, p1 & NETWORK_MASK, message, &message_sz))
        THROW(HNS_CANNOT_ENCODE_XPUB);

    } else {
      header = "Public Key";
      message = ctx->message;
      bin2hex(message, xpub.key, sizeof(xpub.key));
    }

    if(!ledger_ui_update(header, message, flags))
      THROW(EXCEPTION);

    return 0;
  }
#endif

  return len;
}
