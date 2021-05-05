/**
 * apdu-pubkey.c - xpub, pubkey and address derivation for hns
 * Copyright (c) 2018, Boyma Fahnbulleh (MIT License).
 * https://github.com/handshake-org/ledger-app-hns
 */
#include <string.h>
#include "apdu.h"
#include "ledger.h"
#include "libbase58.h"
#include "segwit-addr.h"
#include "utils.h"

/**
 * These constants are used to inspect P1's least significant bit.
 * This bit specifies whether on-device confirmation is required.
 */
#define DEFAULT 0x00 // xx0
#define CONFIRM 0x01 // xx1

/**
 * These constants are used to inspect P1's 2nd & 3rd least significant bits.
 * These bits specify the network to use for formatting info shown on-device.
 */
#define NETWORK_MASK 0x06 // 110
#define MAINNET 0x00      // 00x
#define TESTNET 0x02      // 01x
#define REGTEST 0x04      // 10x
#define SIMNET  0x06      // 11x

/**
 * These constants are used to inspect P2.
 * P2 is used to indicated what information to derive.
 */
#define PUBKEY 0x00
#define XPUB 0x01
#define ADDR 0x02

/**
 * Network prefixes for base58 xpub encoding.
 */
#define XPUB_MAINNET 0x0488b21e
#define XPUB_TESTNET 0x043587cf
#define XPUB_REGTEST 0xeab4fa05
#define XPUB_SIMNET 0x0420bd3a

/**
 * Encodes a pubkey hash in bech32 format.
 *
 * In:
 * @param hrp is the human readable part of bech32 encoding.
 * @param pubkey is the pubkey to encode.
 *
 * Out:
 * @param addr is the encoded address.
 */
static inline void
encode_addr(char *hrp, uint8_t *pubkey, char *addr) {
  uint8_t hash[20];

  if (ledger_blake2b(pubkey, 33, hash, 20))
    THROW(HNS_CANNOT_INIT_BLAKE2B_CTX);

  if (!segwit_addr_encode(addr, hrp, 0, hash, 20))
    THROW(HNS_CANNOT_ENCODE_ADDRESS);
}

/**
 * Encodes an xpub in base58check format.
 *
 * In:
 * @param xpub is the xpub to encode.
 * @param network is 2 bit flag parsed from P1.
 *
 * Out:
 * @param b58 is the encoded xpub string.
 * @param b58_sz is the size of the encoded xpub string.
 * @return a boolean indicating success or failure.
 */
static inline bool
encode_xpub(
  ledger_ecdsa_xpub_t *xpub,
  uint8_t network,
  char *b58,
  size_t *b58_sz
) {
  uint8_t data[82];
  uint8_t checksum[32];
  volatile uint8_t *buf = data;

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
  ledger_sha256(data, 78, checksum);
  ledger_sha256(checksum, 32, checksum);
  write_bytes(&buf, checksum, 4);

  return b58enc(b58, b58_sz, data, sizeof(data));
}

uint16_t
hns_apdu_get_public_key(
  uint8_t p1,
  uint8_t p2,
  uint16_t len,
  volatile uint8_t *buf,
  volatile uint8_t *out,
  volatile uint8_t *flags
) {
  if (!ledger_unlocked())
    THROW(HNS_SECURITY_CONDITION_NOT_SATISFIED);

  ledger_ui_ctx_t *ui = ledger_ui_init_session();

  switch(p1) {
    case DEFAULT | MAINNET:
    case DEFAULT | TESTNET:
    case DEFAULT | REGTEST:
    case DEFAULT | SIMNET:
      break;

    case CONFIRM | MAINNET:
    case CONFIRM | TESTNET:
    case CONFIRM | REGTEST:
    case CONFIRM | SIMNET:
      ui->must_confirm = true;
      break;

    default:
      THROW(HNS_INCORRECT_P1);
      break;
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
  uint8_t path_info = 0;
  uint8_t non_address = 0;
  uint8_t non_standard = 0;

  ledger_apdu_cache_clear();

  if (!read_bip44_path(&buf, &len, &xpub.depth, xpub.path, &path_info))
    THROW(HNS_CANNOT_READ_BIP44_PATH);

  non_address = path_info & HNS_BIP44_NON_ADDR;
  non_standard = path_info & HNS_BIP44_NON_STD;

  if ((p2 & ADDR) && non_address)
    THROW(HNS_INCORRECT_ADDR_PATH);

  ledger_ecdsa_derive_xpub(&xpub);

  len = write_bytes(&out, xpub.key, sizeof(xpub.key));

  if (p2 & XPUB) {
    len += write_varbytes(&out, xpub.code, sizeof(xpub.code));
    len += write_varbytes(&out, xpub.fp, sizeof(xpub.fp));
  } else {
    len += write_u16(&out, 0, HNS_LE);
  }

  char addr[75];

  if (p2 & ADDR) {
    char hrp[3];

    switch(xpub.path[1]) {
      case HNS_BIP44_MAINNET:
        strcpy(hrp, "hs");
        break;

      case HNS_BIP44_TESTNET:
        strcpy(hrp, "ts");
        break;

      case HNS_BIP44_REGTEST:
        strcpy(hrp, "rs");
        break;

      case HNS_BIP44_SIMNET:
        strcpy(hrp, "ss");
        break;

      default:
        THROW(HNS_CANNOT_ENCODE_ADDRESS);
        break;
    }

    encode_addr(hrp, xpub.key, addr);

    len += write_varbytes(&out, (const uint8_t *)addr, 42);
  } else {
    len += write_u8(&out, 0);
  }

  if (ui->must_confirm || non_standard) {
    char *hdr = NULL;
    char *msg = NULL;

    if (!ledger_apdu_cache_write(NULL, len))
      THROW(HNS_CACHE_WRITE_ERROR);

    if (non_standard) {
      hdr = "WARNING";
      msg = "Non-standard BIP44 derivation path.";
    } else if (p2 & ADDR) {
      hdr = "Address";
      msg = addr;
    } else if (p2 & XPUB) {
      size_t msg_sz = sizeof(ui->message);

      hdr = "XPUB";
      msg = ui->message;

      if (!encode_xpub(&xpub, p1 & NETWORK_MASK, msg, &msg_sz))
        THROW(HNS_CANNOT_ENCODE_XPUB);
    } else {
      hdr = "Public Key";
      msg = ui->message;
      bin_to_hex(msg, xpub.key, sizeof(xpub.key));
    }

    if(!ledger_ui_update(LEDGER_UI_KEY, hdr, msg, flags))
      THROW(HNS_CANNOT_UPDATE_UI);

    return 0;
  }

  return len;
}
