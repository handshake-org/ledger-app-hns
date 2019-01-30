#ifndef _HNS_LEDGER_H
#define _HNS_LEDGER_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "os.h"
#include "os_io_seproxyhal.h"

#define LEDGER_ASYNCH_REPLY IO_ASYNCH_REPLY
#define LEDGER_MAX_DEPTH 10
#define LEDGER_RESET EXCEPTION_IO_RESET
#define LEDGER_RETURN_AFTER_TX IO_RETURN_AFTER_TX

#if defined(TARGET_NANOS)

/**
 * For more details on UI elements see:
 * https://github.com/ledgerhq/nanos-secure-sdk
 */

#define LEDGER_UI_BACKGROUND() \
  {{BAGL_RECTANGLE,0,0,0,128,32,0,0,BAGL_FILL,0,0xFFFFFF,0,0}, \
   NULL,0,0,0,NULL,NULL,NULL}

#define LEDGER_UI_ICON_LEFT(userid, glyph) \
  {{BAGL_ICON,userid,3,12,7,7,0,0,0,0xFFFFFF,0,0,glyph}, \
   NULL,0,0,0,NULL,NULL,NULL}

#define LEDGER_UI_ICON_RIGHT(userid, glyph) \
  {{BAGL_ICON,userid,117,13,8,6,0,0,0,0xFFFFFF,0,0,glyph}, \
   NULL,0,0,0,NULL,NULL,NULL}

#define LEDGER_UI_TEXT(userid, x, y, w, text) \
  {{BAGL_LABELINE,userid,x,y,w,12,0,0,0,0xFFFFFF,0, \
    BAGL_FONT_OPEN_SANS_REGULAR_11px|BAGL_FONT_ALIGNMENT_CENTER,0}, \
   (char *)text,0,0,0,NULL,NULL,NULL}
#endif

typedef struct ledger_xpub_s {
  uint8_t code[32];
  uint8_t key[33];
  uint8_t fp[4];
  uint8_t depth;
  uint32_t path[LEDGER_MAX_DEPTH];
} ledger_xpub_t;

extern uint8_t *g_ledger_apdu_buffer;
extern uint16_t g_ledger_apdu_buffer_size;
extern uint16_t g_ledger_ui_step;
extern uint16_t g_ledger_ui_step_count;

static inline void
ledger_boot(void) {
  os_boot();
}

static inline void
ledger_reset(void) {
  reset();
}

static inline void
ledger_exit(unsigned int code) {
  BEGIN_TRY_L(exit) {
    TRY_L(exit) {
      os_sched_exit(code);
    }
    FINALLY_L(exit);
  }
  END_TRY_L(exit);
}

static inline uint16_t
ledger_apdu_exchange(
  uint8_t flags,
  uint16_t len,
  uint16_t sw
) {
  if (sw) {
    g_ledger_apdu_buffer[len++] = sw >> 8;
    g_ledger_apdu_buffer[len++] = sw & 0xff;
  }

  return io_exchange(CHANNEL_APDU | flags, len);
}

static inline unsigned int
ledger_pin_validated(void) {
  return os_global_pin_is_validated();
}

uint8_t *
ledger_init(void);

void
ledger_ui_init(void);

void
ledger_ui_idle(void);

bool
ledger_sha256(void *digest, const void *data, size_t data_sz);

void
ledger_ecdsa_derive_xpub(ledger_xpub_t *xpub);

void
ledger_ecdsa_sign(
  uint32_t *path,
  uint8_t depth,
  uint8_t *hash,
  size_t hash_len,
  uint8_t *sig
);
#endif
