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
  uint8_t addr[42];
} ledger_bip32_node_t;

extern uint16_t g_ledger_ui_step;
extern uint16_t g_ledger_ui_step_count;

void
ledger_boot(void);

void
ledger_reset(void);

void
ledger_exit(unsigned int);

uint16_t
ledger_apdu_exchange(uint8_t, uint16_t);

unsigned int
ledger_pin_validated(void);

uint8_t *
ledger_init(void);

void
ledger_ui_init(void);

void
ledger_ui_idle(void);

void
ledger_bip32_node_derive(
  ledger_bip32_node_t *,
  uint32_t *,
  uint8_t,
  char *
);
#endif
