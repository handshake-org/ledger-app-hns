/**
 * ledger-ui.c - ui functionality for Ledger Nano S
 * Copyright (c) 2018, Boyma Fahnbulleh (MIT License).
 * https://github.com/boymanjor/ledger-app-hns
 */
#include "apdu.h"
#include "glyphs.h"
#include "ledger.h"
#include "utils.h"

#if defined(TARGET_NANOS)

/**
 * For more details on UI elements see:
 * - https://github.com/ledgerhq/nanos-secure-sdk
 * - https://ledger.readthedocs.io/en/latest/userspace/display_management.html
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

static ux_menu_entry_t const main_menu[];

/**
 * About menu screen for Ledger Nano S.
 */
static ux_menu_entry_t const about_menu[] = {
  {NULL, NULL, 0, NULL, "Version", APPVERSION, 0, 0},
  {main_menu, NULL, 1, &C_nanos_icon_back, "Back", NULL, 61, 40},
  UX_MENU_END
};

/**
 * Main menu screen for Ledger Nano S.
 * Declared above so it can be used in about_menu.
 */
static ux_menu_entry_t const main_menu[] = {
  {NULL, NULL, 0, NULL, "Use wallet to", "view accounts", 0, 0},
  {about_menu, NULL, 0, NULL, "About", NULL, 0, 0},
  {NULL, ledger_exit, 0, &C_nanos_icon_dashboard, "Quit app", NULL, 50, 29},
  UX_MENU_END
};

/**
 * Approval screen for on-device confirmations.
 *
 * The Ledger Nano S screen is 128 x 32 pixels. Each element
 * in the array defines an element to be drawn on-screen.
 *
 * @see ledger.h for macro definitions
 */
static bagl_element_t const ledger_ui_approve[] = {
  LEDGER_UI_BACKGROUND(),
  LEDGER_UI_ICON_LEFT(0x00, BAGL_GLYPH_ICON_CROSS),
  LEDGER_UI_ICON_RIGHT(0x00, BAGL_GLYPH_ICON_CHECK),
  LEDGER_UI_TEXT(0x00, 0, 12, 128, "OK?")
};

/**
 * Message display screen for on-device confirmations.
 *
 * The Ledger Nano S screen is 128 x 32 pixels. Each element in
 * the array defines an element to be drawn on-screen. The text
 * fields are updated using the global ledger ui context.
 */
static bagl_element_t const ledger_ui_display[] = {
  LEDGER_UI_BACKGROUND(),
  LEDGER_UI_ICON_LEFT(0x01, BAGL_GLYPH_ICON_LEFT),
  LEDGER_UI_ICON_RIGHT(0x02, BAGL_GLYPH_ICON_RIGHT),
  LEDGER_UI_TEXT(0x00, 0, 12, 128, g_ledger.ui.header),
  LEDGER_UI_TEXT(0x00, 0, 26, 128, g_ledger.ui.viewport)
};

/**
 * Handles button events for the approval screen.
 *
 * NOTE: the name of a button event handler must match the
 * name of the corresponding screen with '_button' appended.
 */
static uint32_t
ledger_ui_approve_button(uint32_t mask, uint32_t ctr) {
  switch (mask) {
    case BUTTON_EVT_RELEASED | BUTTON_LEFT: {
      ledger_apdu_buffer_clear();
      ledger_apdu_exchange(IO_RETURN_AFTER_TX, 0, HNS_CONDITIONS_OF_USE_NOT_SATISFIED);
      ledger_ui_idle();
      break;
    }

    case BUTTON_EVT_RELEASED | BUTTON_RIGHT: {
      uint8_t len = ledger_apdu_cache_flush(0);
      ledger_apdu_exchange(IO_RETURN_AFTER_TX, len, HNS_OK);
      ledger_ui_idle();
      break;
    }
  }

  return 0;
}

/**
 * Handles button events for the display screen.
 *
 * NOTE: the name of a button event handler must match the
 * name of the corresponding screen with '_button' appended.
 */
static uint32_t
ledger_ui_display_button(uint32_t mask, uint32_t ctr) {
  char *viewport = g_ledger.ui.viewport;
  char *message = g_ledger.ui.message;
  uint8_t *pos = &g_ledger.ui.message_pos;
  uint8_t *len = &g_ledger.ui.message_len;

  switch (mask) {
    case BUTTON_LEFT:
    case BUTTON_EVT_FAST | BUTTON_LEFT: {
      if (*pos > 0)
        (*pos)--;

      memmove(viewport, message + *pos, 12);
      UX_REDISPLAY();
      break;
    }

    case BUTTON_RIGHT:
    case BUTTON_EVT_FAST | BUTTON_RIGHT: {
      if (*pos < *len - 12)
        (*pos)++;

      memmove(viewport, message + *pos, 12);
      UX_REDISPLAY();
      break;
    }

    case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT: {
      UX_DISPLAY(ledger_ui_approve, NULL);
      break;
    }
  }

  return 0;
}

/**
 * Preprocessor for the display button event handler.
 *
 * The display screen allows users to scroll through text
 * displayed on-screen. This function handles the display logic.
 */
static bagl_element_t const *
ledger_ui_display_prepro(const bagl_element_t *e) {
  uint8_t *pos = &g_ledger.ui.message_pos;
  uint8_t *len = &g_ledger.ui.message_len;

  switch (e->component.userid) {
    case 1:
      return (*pos == 0) ? NULL : e;

    case 2:
      return (*pos == *len - 12) ? NULL : e;

    default:
      return e;
  }
}

void
ledger_ui_idle(void) {
  UX_MENU_DISPLAY(0, main_menu, NULL);
}

void
ledger_ui_init(void) {
  UX_INIT();
  ledger_ui_idle();
}

bool
ledger_ui_update(char *header, char *message, uint8_t *flags) {
  size_t header_len = strlen(header);
  size_t message_len = strlen(message);

  if (header_len >= sizeof(g_ledger.ui.header))
    return false;

  if (header_len >= sizeof(g_ledger.ui.message))
    return false;

  memmove(g_ledger.ui.header, header, header_len + 1);
  memmove(g_ledger.ui.message, message, message_len + 1);
  memmove(g_ledger.ui.viewport, g_ledger.ui.message, 12);
  g_ledger.ui.viewport[12] = '\0';
  g_ledger.ui.message_len = message_len;
  g_ledger.ui.message_pos = 0;

  UX_DISPLAY(ledger_ui_display, ledger_ui_display_prepro);
  *flags |= IO_ASYNCH_REPLY;

  return true;
}
#endif
