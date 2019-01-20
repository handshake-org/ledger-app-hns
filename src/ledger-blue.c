#include "glyphs.h"
#include "ledger.h"
#include "utils.h"

#if defined(TARGET_BLUE)

#define HNS_COLOR_MAIN 0x222222
#define HNS_COLOR_ALT  0xFFFFFF

/**
 * For more details on UI elements see:
 * https://github.com/ledgerhq/blue-secure-sdk
 */

#define LEDGER_UI_BACKGROUND() \
  {{BAGL_RECTANGLE, 0x00, 0, 20, 320, 48, 0, 0, \
    BAGL_FILL, HNS_COLOR_MAIN, HNS_COLOR_MAIN, 0, 0}, \
    NULL, 0, 0, 0, NULL, NULL, NULL}, \
  {{BAGL_RECTANGLE, 0x00, 0, 68, 320, 413, 0, 0, \
    BAGL_FILL, HNS_COLOR_ALT, HNS_COLOR_ALT, 0, 0}, \
    NULL, 0, 0, 0, NULL, NULL, NULL}

#define LEDGER_UI_HEADER() \
  {{BAGL_LABELINE, 0x00, 0, 45, 320, 30, 0, 0, 0, HNS_COLOR_ALT, \
    HNS_COLOR_MAIN, BAGL_FONT_OPEN_SANS_SEMIBOLD_10_13PX | \
    BAGL_FONT_ALIGNMENT_CENTER, 0}, \
    HNS_APP_NAME, 0, 0, 0, NULL, NULL, NULL}, \
  {{BAGL_RECTANGLE, 0x00, 0, 19, 56, 44, 0, 0, \
    BAGL_FILL, HNS_COLOR_MAIN, HNS_COLOR_MAIN, 0, 0}, \
    NULL, 0, 0, 0, 0, NULL, NULL}, \
  {{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 264, 19, 56, 44, 0, 0, \
    BAGL_FILL, HNS_COLOR_MAIN, HNS_COLOR_ALT, BAGL_FONT_SYMBOLS_0 | \
    BAGL_FONT_ALIGNMENT_CENTER | BAGL_FONT_ALIGNMENT_MIDDLE, 0}, \
    BAGL_FONT_SYMBOLS_0_DASHBOARD, 0, HNS_COLOR_MAIN, \
    HNS_COLOR_ALT, handle_exit_press, NULL, NULL}

#define LEDGER_UI_LG_TEXT(y, w, text) \
  {{BAGL_LABELINE, 0x00, 0, y, w, 30, 0, 0, \
    BAGL_FILL, HNS_COLOR_MAIN, HNS_COLOR_ALT, \
    BAGL_FONT_OPEN_SANS_LIGHT_16_22PX | BAGL_FONT_ALIGNMENT_CENTER, 0}, \
    text, 0, 0, 0, NULL, NULL, NULL}

#define LEDGER_UI_MD_TEXT(y, w, text) \
  {{BAGL_LABELINE, 0x00, 0, y, w, 30, 0, 0, \
    BAGL_FILL, HNS_COLOR_MAIN, HNS_COLOR_ALT, \
    BAGL_FONT_OPEN_SANS_REGULAR_10_13PX | BAGL_FONT_ALIGNMENT_CENTER, 0}, \
    text, 0, 0, 0, NULL, NULL, NULL}

#define LEDGER_UI_SM_TEXT(y, w, text) \
  {{BAGL_LABELINE, 0x00, 0, y, w, 30, 0, 0, \
    BAGL_FILL, HNS_COLOR_MAIN, HNS_COLOR_ALT, \
    BAGL_FONT_OPEN_SANS_REGULAR_8_11PX | BAGL_FONT_ALIGNMENT_CENTER, 0}, \
    text, 0, 0, 0, NULL, NULL, NULL}

static const bagl_element_t *
handle_exit_press(const bagl_element_t *e) {
  ledger_exit(0);
  return NULL;
}

static const bagl_element_t main_page[] = {
  LEDGER_UI_BACKGROUND(),
  LEDGER_UI_HEADER(),
  LEDGER_UI_LG_TEXT(270, 320, "Open Handshake wallet"),
  LEDGER_UI_MD_TEXT(308, 320, "Connect the Ledger Blue and open your"),
  LEDGER_UI_MD_TEXT(331, 320, "preferred wallet to view your accounts."),
  LEDGER_UI_SM_TEXT(450, 320, "Confirmation requests will show as needed."),
};

static unsigned int
main_page_button(uint32_t mask, uint32_t ctr) {
  return 0;
}

void
ledger_ui_init(void) {
  UX_INIT();
  ledger_ui_idle();
}

void
ledger_ui_idle(void) {
  g_ledger_ui_step_count = 0;
  UX_SET_STATUS_BAR_COLOR(HNS_COLOR_ALT, HNS_COLOR_MAIN);
  UX_DISPLAY(main_page, NULL);
}
#endif
