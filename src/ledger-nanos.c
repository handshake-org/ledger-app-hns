#include "glyphs.h"
#include "ledger.h"
#include "utils.h"

#if defined(TARGET_NANOS)

ux_menu_entry_t const main_menu[];

ux_menu_entry_t const about_menu[] = {
  {NULL, NULL, 0, NULL, "Version", APPVERSION, 0, 0},
  {main_menu, NULL, 1, &C_nanos_icon_back, "Back", NULL, 61, 40},
  UX_MENU_END
};

ux_menu_entry_t const main_menu[] = {
  {NULL, NULL, 0, NULL, "Use wallet to", "view accounts", 0, 0},
  {about_menu, NULL, 0, NULL, "About", NULL, 0, 0},
  {NULL, ledger_exit, 0, &C_nanos_icon_dashboard, "Quit app", NULL, 50, 29},
  UX_MENU_END
};

void
ledger_ui_init(void) {
  UX_INIT();
  ledger_ui_idle();
}

void
ledger_ui_idle(void) {
  g_ledger_ui_step_count = 0;
  UX_MENU_DISPLAY(0, main_menu, NULL);
}
#endif
