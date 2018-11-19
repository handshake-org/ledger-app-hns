#include "glyphs.h"
#include "ledger.h"

#if defined(TARGET_NANOS)

ux_menu_entry_t const menu_main[];

ux_menu_entry_t const menu_about[] = {
  {NULL, NULL, 0, NULL, "Version", APPVERSION, 0, 0},
  {menu_main, NULL, 1, &C_nanos_icon_back, "Back", NULL, 61, 40},
  UX_MENU_END
};

ux_menu_entry_t const menu_main[] = {
  {NULL, NULL, 0, NULL, "Use wallet to", "view accounts", 0, 0},
  {menu_about, NULL, 0, NULL, "About", NULL, 0, 0},
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
  UX_MENU_DISPLAY(0, menu_main, NULL);
}
#endif
