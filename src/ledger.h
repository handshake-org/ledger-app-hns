#ifndef _HNS_LEDGER_H
#define _HNS_LEDGER_H

#include <stdbool.h>
#include <stdint.h>
#include "os.h"
#include "os_io_seproxyhal.h"

typedef cx_ecfp_private_key_t ledger_private_key_t;
typedef cx_ecfp_public_key_t ledger_public_key_t;

#if defined(TARGET_NANOS)

#define UI_BACKGROUND() \
  {{BAGL_RECTANGLE,0,0,0,128,32,0,0,BAGL_FILL,0,0xFFFFFF,0,0}, \
   NULL,0,0,0,NULL,NULL,NULL}

#define UI_ICON_LEFT(userid, glyph) \
  {{BAGL_ICON,userid,3,12,7,7,0,0,0,0xFFFFFF,0,0,glyph}, \
   NULL,0,0,0,NULL,NULL,NULL}

#define UI_ICON_RIGHT(userid, glyph) \
  {{BAGL_ICON,userid,117,13,8,6,0,0,0,0xFFFFFF,0,0,glyph}, \
   NULL,0,0,0,NULL,NULL,NULL}

#define UI_TEXT(userid, x, y, w, text) \
  {{BAGL_LABELINE,userid,x,y,w,12,0,0,0,0xFFFFFF,0, \
    BAGL_FONT_OPEN_SANS_REGULAR_11px|BAGL_FONT_ALIGNMENT_CENTER,0}, \
   (char *)text,0,0,0,NULL,NULL,NULL}
#endif

extern uint16_t g_ledger_ui_step;
extern uint16_t g_ledger_ui_step_count;

uint8_t *
ledger_init(void);

void
ledger_ui_init(void);

void
ledger_ui_idle(void);

void
ledger_ecdsa_derive(
  uint32_t *,
  uint8_t,
  uint8_t *,
  ledger_private_key_t *,
  ledger_public_key_t *
);

void
ledger_ecdsa_sign(ledger_private_key_t *, uint8_t *, size_t, uint8_t *);

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
