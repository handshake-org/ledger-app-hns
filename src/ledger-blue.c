#include "glyphs.h"
#include "ledger.h"
#include "utils.h"

#if defined(TARGET_BLUE)

#define HNS_COLOR_MAIN 0x222222
#define HNS_COLOR_ALT  0xFFFFFF

const bagl_element_t *
ui_touch_exit(const bagl_element_t *e) {
  ledger_exit(0);
  return NULL;
}

uint32_t
ui_idle_button(uint32_t mask, uint32_t ctr) {
  return 0;
}

/**
 *
 * typedef enum bagl_components_type_e_ {
 *   BAGL_NONE = 0,
 *   BAGL_BUTTON = 1,
 *   BAGL_LABEL,
 *   BAGL_RECTANGLE,
 *   BAGL_LINE,
 *   BAGL_ICON,
 *   BAGL_CIRCLE,
 *   BAGL_LABELINE,
 *   BAGL_FLAG_TOUCHABLE = 0x80,
 * } bagl_components_type_e;
 *
 * typedef struct {
 *   bagl_components_type_e type;
 *   unsigned char userid;
 *   short x;
 *   short y;
 *   unsigned short width;
 *   unsigned short height;
 *   unsigned char stroke;
 *   unsigned char radius;
 *   unsigned char fill;
 *   unsigned int fgcolor;
 *   unsigned int bgcolor;
 *   unsigned short font_id;
 *   unsigned char icon_id;
 * } bagl_component_t;
 *
 * struct bagl_element_e {
 *   bagl_component_t component;
 *   const char *text;
 *   unsigned char touch_area_brim;
 *   int overfgcolor;
 *   int overbgcolor;
 *   bagl_element_callback_t tap;
 *   bagl_element_callback_t out;
 *   bagl_element_callback_t over;
 * };
 *
 * typedef struct bagl_element_e bagl_element_t;
 *
 * For more details see:
 * https://github.com/ledgerhq/blue-secure-sdk
 */

const bagl_element_t ui_idle[] = {

  /**
   * Header background
   */

  {{BAGL_RECTANGLE, 0x00, 0, 20, 320, 48, 0, 0,
    BAGL_FILL, HNS_COLOR_MAIN, HNS_COLOR_MAIN, 0, 0},
    NULL, 0, 0, 0, NULL, NULL, NULL},

  /**
   * Content background
   */

  {{BAGL_RECTANGLE, 0x00, 0, 68, 320, 413, 0, 0,
    BAGL_FILL, HNS_COLOR_ALT, HNS_COLOR_ALT, 0, 0},
    NULL, 0, 0, 0, NULL, NULL, NULL},

  /**
   * Header views
   */

  {{BAGL_LABELINE, 0x00, 0, 45, 320, 30, 0, 0, 0, HNS_COLOR_ALT,
    HNS_COLOR_MAIN, BAGL_FONT_OPEN_SANS_SEMIBOLD_10_13PX |
    BAGL_FONT_ALIGNMENT_CENTER, 0},
    HNS_APP_NAME, 0, 0, 0, NULL, NULL, NULL},

  {{BAGL_RECTANGLE, 0x00, 0, 19, 56, 44, 0, 0,
  	BAGL_FILL, HNS_COLOR_MAIN, HNS_COLOR_MAIN, 0, 0},
    NULL, 0, 0, 0, 0, NULL, NULL},

  {{BAGL_RECTANGLE | BAGL_FLAG_TOUCHABLE, 0x00, 264, 19, 56, 44, 0, 0,
	BAGL_FILL, HNS_COLOR_MAIN, HNS_COLOR_ALT, BAGL_FONT_SYMBOLS_0 |
    BAGL_FONT_ALIGNMENT_CENTER | BAGL_FONT_ALIGNMENT_MIDDLE, 0},
    BAGL_FONT_SYMBOLS_0_DASHBOARD, 0, HNS_COLOR_MAIN,
    HNS_COLOR_ALT, ui_touch_exit, NULL, NULL},

	/**
   * Content views
   */

  {{BAGL_LABELINE, 0x00, 0, 270, 320, 30, 0, 0,
    BAGL_FILL, HNS_COLOR_MAIN, HNS_COLOR_ALT,
    BAGL_FONT_OPEN_SANS_LIGHT_16_22PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
    "Open Handshake wallet", 0, 0, 0, NULL, NULL, NULL},

  {{BAGL_LABELINE, 0x00, 0, 308, 320, 30, 0, 0,
    BAGL_FILL, HNS_COLOR_MAIN, HNS_COLOR_ALT,
    BAGL_FONT_OPEN_SANS_REGULAR_10_13PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
    "Connect the Ledger Blue and open your", 0,	0, 0, NULL, NULL, NULL},

  {{BAGL_LABELINE, 0x00, 0, 331, 320, 30, 0, 0,
    BAGL_FILL, HNS_COLOR_MAIN, HNS_COLOR_ALT,
    BAGL_FONT_OPEN_SANS_REGULAR_10_13PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
    "preferred wallet to view your accounts.", 0, 0, 0,	NULL, NULL, NULL},

  {{BAGL_LABELINE, 0x00, 0, 450, 320, 30, 0, 0,
    BAGL_FILL, HNS_COLOR_MAIN, HNS_COLOR_ALT,
    BAGL_FONT_OPEN_SANS_REGULAR_8_11PX | BAGL_FONT_ALIGNMENT_CENTER, 0},
    "Approval requests will show automatically.", 0, 0, 0, NULL, NULL, NULL},
};

void
ledger_ui_init(void) {
  UX_INIT();
  ledger_ui_idle();
}

void
ledger_ui_idle(void) {
  g_ledger_ui_step_count = 0;
  UX_SET_STATUS_BAR_COLOR(HNS_COLOR_ALT, HNS_COLOR_MAIN);
  UX_DISPLAY(ui_idle, NULL);
}
#endif
