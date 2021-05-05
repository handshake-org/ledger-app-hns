/**
 * ledger.h - header file for Ledger related source.
 * Copyright (c) 2018, Boyma Fahnbulleh (MIT License).
 * https://github.com/handshake-org/ledger-app-hns
 */
#ifndef _HNS_LEDGER_H
#define _HNS_LEDGER_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "os.h"
#include "os_io_seproxyhal.h"
#include "cx.h"
#include "ux.h"

/**
 * Size of the apdu cache buffer.
 */
#define LEDGER_APDU_CACHE_SIZE 114

/**
 * Maximum BIP32 derivation depth.
 */
#define LEDGER_MAX_DEPTH 10

/**
 * Exception used to initiate an application reset.
 */
#define LEDGER_RESET EXCEPTION_IO_RESET

/**
 * These constants are used to determine the current
 * state of the device's screen.
 */
enum ledger_ui_state {
  LEDGER_UI_KEY,
  LEDGER_UI_OUTPUT,
  LEDGER_UI_VALUE,
  LEDGER_UI_ADDRESS,
  LEDGER_UI_NEW_OWNER,
  LEDGER_UI_COVENANT_TYPE,
  LEDGER_UI_NAME,
  LEDGER_UI_FEES,
  LEDGER_UI_SIGHASH_TYPE
};

/**
 * Blake2b context.
 */
typedef cx_blake2b_t ledger_blake2b_ctx;

/**
 * BIP32 ECDSA Extended Public Key.
 */
typedef struct ledger_ecdsa_xpub_s {
  uint8_t code[32];
  uint8_t key[33];
  uint8_t fp[4];
  uint8_t depth;
  uint32_t path[LEDGER_MAX_DEPTH];
} ledger_ecdsa_xpub_t;

/**
 * UI context used to manage on-screen text.
 */
typedef struct ledger_ui_ctx_s {
  bool must_confirm;
  char header[14];
  char message[113];
#if defined(HAVE_UX_FLOW)
  char type[9];
  char name[64];
  char owner[75];
  char value[22];
  char address[75];
#else
  uint8_t message_len;
  uint8_t message_pos;
  char viewport[13];
  enum ledger_ui_state state;
#endif
  void *ctx;
  uint8_t buflen;
  volatile uint8_t *flags;
  uint8_t network;
  uint8_t ctr;
} ledger_ui_ctx_t;

/**
 * Union storing any global contexts used in the application.
 */
typedef union {
  ledger_ui_ctx_t ui;
} ledger_ctx_t;

/**
 * Global context accessed across application.
 */
extern ledger_ctx_t g_ledger;

/**
 * Initializes the Ledger device.
 */
uint8_t *
ledger_init(void);

/**
 * Boots the Ledger device.
 */
void
ledger_boot(void);

/**
 * Resets the Ledger device.
 */
void
ledger_reset(void);

/**
 * Exits the Ledger BOLOS environment.
 *
 * In:
 * @param code is the exit code.
 */
void
ledger_exit(uint32_t code);

/**
 * Checks that device pin code has been entered.
 */
bool
ledger_unlocked(void);

/**
 * Zeros any bytes in the apdu exchange buffer.
 */
void
ledger_apdu_buffer_clear(void);

/**
 * Copies data from the src buffer to the cache. If src is NULL, copy
 * src_len amount of bytes from the APDU exchange buffer to the cache.
 *
 * In:
 * @param src is the data buffer to copy to cache.
 * @param src_len is the amount of data to copy to cache.
 *
 * Out:
 * @return boolean indicating success or failure.
 */
bool
ledger_apdu_cache_write(volatile uint8_t *src, uint8_t src_len);

/**
 * Copies all data in the cache to the APDU exchange buffer. The len
 * parameter indicates the amount of bytes already in the APDU buffer
 * that the caller wishes to save. These bytes will be appended to the
 * end of the cache before updating the exchange buffer. If the len
 * parameter is used, the APDU header bytes will be saved, otherwise
 * the cache is copied to the beginning of the exchange buffer. If the
 * cache is empty, the exchange buffer will be left unchanged.
 *
 * In:
 * @param len is the amount of bytes in the exchange buffer.
 *
 * Out:
 * @return the amount of data added to the exchange buffer from the cache.
 */
uint8_t
ledger_apdu_cache_flush(uint16_t *len);

/**
 * Checks the apdu cache buffer for stored data.
 *
 * Out:
 * @return the amount of bytes stored in the cache.
 */
uint8_t
ledger_apdu_cache_check(void);

/**
 * Zeros any bytes in the apdu cache buffer.
 */
void
ledger_apdu_cache_clear(void);

/**
 * Exchanges messages over the APDU protocol.
 *
 * In:
 * @param flags is bit array for apdu exchange flags.
 * @param len is the length of the data in the apdu buffer.
 * @param sw is the status word to send.
 *
 * Out:
 * @return the length of the message returned from the apdu buffer.
 */
uint16_t
ledger_apdu_exchange(uint8_t flags, uint16_t len, uint16_t sw);

/**
 * Helper function that generates a blake2b digest.
 *
 * In:
 * @param data is the data to hash.
 * @param data_sz is the length of the data, in bytes.
 * @param digest_sz is the length of the hash digest, in bytes.
 *
 * Out:
 * @param digest is the hash digest.
 */
int
ledger_blake2b(
  void const *data,
  size_t data_sz,
  void const *digest,
  size_t digest_sz
);

/**
 * Initializes the blake2b hash context.
 *
 * In:
 * @param ctx is the blake2b context.
 * @param digest_sz is the length of the hash digest, in bytes.
 */
void
ledger_blake2b_init(ledger_blake2b_ctx *ctx, size_t digest_sz);

/**
 * Updates the blake2b hash context.
 *
 * In:
 * @param ctx is the blake2b context.
 * @param data is the data to hash.
 * @param data_sz is the length of the data, in bytes.
 */
void
ledger_blake2b_update(
  ledger_blake2b_ctx *ctx,
  volatile void const *data,
  size_t data_sz
);

/**
 * Returns blake2b hash digest.
 *
 * In:
 * @param ctx is the blake2b context.
 *
 * Out:
 * @param digest is the hash digest.
 */
void
ledger_blake2b_final(ledger_blake2b_ctx *ctx, void *digest);

/**
 * Derives an ECDSA extended public key.
 *
 * Out:
 * @param xpub is the extended public key.
 */
void
ledger_ecdsa_derive_xpub(ledger_ecdsa_xpub_t *xpub);

/**
 * Returns an ECDSA signature.
 *
 * In:
 * @param path is an array of indices used to derive the signing key.
 * @param depth is the number of levels to derive in the HD tree.
 * @param hash is the hash to be signed.
 * @param hash_len is the length of the hash.
 *
 * Out:
 * @param sig is the resultant signature.
 */
bool
ledger_ecdsa_sign(
  uint32_t *path,
  uint8_t depth,
  uint8_t *hash,
  size_t hash_len,
  volatile uint8_t *sig,
  uint8_t sig_len
);

/**
 * Returns sha256 hash digest.
 *
 * In:
 * @param data is the data to hash.
 * @param data_sz is the length of the data.
 *
 * Out:
 * @param digest is the hash digest.
 * @return boolean indicating success or failure.
 */
bool
ledger_sha256(const void *data, size_t data_sz, void *digest);

/**
 * Returns sha3 hash digest.
 *
 * In:
 * @param data is the data to hash.
 * @param data_sz is the length of the data.
 *
 * Out:
 * @param digest is the hash digest.
 * @return boolean indicating success or failure.
 */
bool
ledger_sha3(const void *data, size_t data_sz, void *digest);

/**
 * Renders the main menu on screen.
 */
void
ledger_ui_idle(void);

/**
 * Initializes the device UI.
 */
void
ledger_ui_init(void);

/**
 * Initialize UI session for handling apdu commmand.
 *
 * Out:
 * @return the global UI context.
 */
ledger_ui_ctx_t *
ledger_ui_init_session(void);

/**
 * Updates the device's on-screen text.
 *
 * In:
 * @param state indicates the current item displayed on-screen.
 * @param header is the header text.
 * @param message is the message text.
 *
 * Out:
 * @param flags is bit array for apdu exchange flags
 * @return a boolean indicating success or failure
 */
bool
ledger_ui_update(
  enum ledger_ui_state state,
  char *header,
  char *message,
  volatile uint8_t *flags
);
#endif
