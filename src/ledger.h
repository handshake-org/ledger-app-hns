#ifndef _HNS_LEDGER_H
#define _HNS_LEDGER_H

#include <stdbool.h>
#include <stdint.h>
#include "os.h"
#include "os_io_seproxyhal.h"

typedef struct
ledger_bip32_node_s {
  uint32_t * path;
  uint8_t depth;
  uint8_t prv[32];
  uint8_t pub[33];
  uint8_t code[32];
  cx_ecfp_private_key_t private;
  cx_ecfp_public_key_t public;
} ledger_bip32_node_t;

extern uint16_t g_ledger_ui_step;
extern uint16_t g_ledger_ui_step_count;

uint8_t *
ledger_init(void);

void
ledger_ui_init(void);

void
ledger_ui_idle(void);

void
ledger_bip32_node_derive(ledger_bip32_node_t *, uint32_t *, uint8_t);

void
ledger_ecdsa_sign(cx_ecfp_private_key_t, uint8_t *, size_t, uint8_t *, size_t);

static inline void
ledger_boot(void) {
  os_boot();
}

static inline void
ledger_reset(void) {
  reset();
}

static inline void
ledger_exit(unsigned int exit_code) {
  BEGIN_TRY_L(exit) {
    TRY_L(exit) {
      os_sched_exit(exit_code);
    }
    FINALLY_L(exit);
  }
  END_TRY_L(exit);
}

static inline uint16_t
ledger_apdu_exchange(uint8_t flags, uint16_t len) {
  return io_exchange(CHANNEL_APDU | flags, len);
}

static inline unsigned int
ledger_pin_validated(void) {
  return os_global_pin_is_validated();
}
#endif
