#ifndef _HNS_LEDGER_H
#define _HNS_LEDGER_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "os.h"
#include "os_io_seproxyhal.h"

#define LEDGER_MAX_DEPTH 10
#define LEDGER_RESET EXCEPTION_IO_RESET

typedef struct ledger_ecdsa_xpub_s {
  uint8_t code[32];
  uint8_t key[33];
  uint8_t fp[4];
  uint8_t depth;
  uint32_t path[LEDGER_MAX_DEPTH];
} ledger_ecdsa_xpub_t;

typedef struct ledger_ui_ctx_s {
  uint8_t header[11];
  uint8_t viewport[13];
  uint8_t message[113];
  uint8_t message_len;
  uint8_t message_pos;
} ledger_ui_ctx_t;

typedef union {
  ledger_ui_ctx_t ui;
} ledger_ctx_t;

extern ledger_ctx_t g_ledger;

uint8_t *
ledger_init(void);

void
ledger_boot();

void
ledger_reset();

void
ledger_exit(uint32_t code);

uint32_t
ledger_unlocked();

void
ledger_apdu_buffer_clear();

bool
ledger_apdu_cache_write(uint8_t len);

uint8_t
ledger_apdu_cache_flush(uint8_t len);

uint8_t
ledger_apdu_cache_check();

void
ledger_apdu_cache_clear();

uint16_t
ledger_apdu_exchange(uint8_t flags, uint16_t len, uint16_t sw);

void
ledger_ecdsa_derive_xpub(ledger_ecdsa_xpub_t *xpub);

void
ledger_ecdsa_sign(
  uint32_t *path,
  uint8_t depth,
  uint8_t *hash,
  size_t hash_len,
  uint8_t *sig
);

bool
ledger_sha256(void *digest, const void *data, size_t data_sz);

void
ledger_ui_idle();

void
ledger_ui_init();

bool
ledger_ui_update(char *header, char *message, uint8_t *flags);
#endif
