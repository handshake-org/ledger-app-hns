#include "ledger.h"

uint16_t g_ledger_ui_step;
uint16_t g_ledger_ui_step_count;

void
ledger_boot(void) {
  os_boot();
}

void
ledger_reset(void) {
  reset();
}

void
ledger_exit(unsigned int exit_code) {
  BEGIN_TRY_L(exit) {
    TRY_L(exit) {
      os_sched_exit(exit_code);
    }
    FINALLY_L(exit);
  }
  END_TRY_L(exit);
}

uint16_t
ledger_apdu_exchange(uint8_t flags, uint16_t len) {
  return io_exchange(CHANNEL_APDU | flags, len);
}

unsigned int
ledger_pin_validated(void) {
  return os_global_pin_is_validated();
}

uint8_t *
ledger_init(void) {
  io_seproxyhal_init();
  os_memset(G_io_apdu_buffer, 0, 255);
  USB_power(false);
  USB_power(true);
  ledger_ui_init();

  return G_io_apdu_buffer;
}

void
ledger_bip32_node_derive(
  ledger_bip32_node_t * n,
  uint32_t * path,
  uint8_t depth,
  char * hrp
) {
  cx_ecfp_private_key_t private;
  cx_ecfp_public_key_t public;
  uint8_t pkh[20];

  os_perso_derive_node_bip32(CX_CURVE_256K1, path, depth, n->prv, n->code);
  cx_ecdsa_init_private_key(CX_CURVE_256K1, n->prv, 32, &private);
  cx_ecfp_generate_pair(CX_CURVE_256K1, &public, &private, true);
  os_memmove(n->pub, public.W, sizeof(n->pub));
  n->pub[0] = public.W[64] & 1 ? 0x03 : 0x02;
  n->path = path;
  n->depth = depth;

  if (blake2b(pkh, sizeof(pkh), NULL, 0, n->pub, sizeof(n->pub)))
    THROW(EXCEPTION);

  if (!segwit_addr_encode(n->addr, hrp, 0, pkh, sizeof(pkh)))
    THROW(EXCEPTION);
}

/**
 * BOLOS SDK variable declarations
 *
 * For more details see:
 * https://github.com/ledgerhq/nanos-secure-sdk
 */

uint8_t G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];
ux_state_t ux;

/**
 * BOLOS SDK function declarations
 *
 * For more details see:
 * https://github.com/ledgerhq/nanos-secure-sdk
 *
 */

uint8_t
io_event(uint8_t channel) {
  switch (G_io_seproxyhal_spi_buffer[0]) {
    case SEPROXYHAL_TAG_FINGER_EVENT:
      UX_FINGER_EVENT(G_io_seproxyhal_spi_buffer);
      break;

    case SEPROXYHAL_TAG_BUTTON_PUSH_EVENT:
      UX_BUTTON_PUSH_EVENT(G_io_seproxyhal_spi_buffer);
      break;

    case SEPROXYHAL_TAG_DISPLAY_PROCESSED_EVENT:
      UX_DISPLAYED_EVENT({});
      break;

    case SEPROXYHAL_TAG_TICKER_EVENT:
      UX_TICKER_EVENT(G_io_seproxyhal_spi_buffer, {
        if (g_ledger_ui_step_count > 0 && UX_ALLOWED)
          g_ledger_ui_step = (g_ledger_ui_step + 1) % g_ledger_ui_step_count;

        UX_REDISPLAY();
      });
      break;

    case SEPROXYHAL_TAG_STATUS_EVENT:
      if (G_io_apdu_media == IO_APDU_MEDIA_USB_HID &&
          !(U4BE(G_io_seproxyhal_spi_buffer, 3) &
            SEPROXYHAL_TAG_STATUS_EVENT_FLAG_USB_POWERED)) {
        THROW(EXCEPTION_IO_RESET);
      }
      // Intentional fall through.
    default:
      UX_DEFAULT_EVENT();
      break;
  }

  if (!io_seproxyhal_spi_is_status_sent())
    io_seproxyhal_general_status();

  return 1;
}

uint16_t
io_exchange_al(uint8_t channel, uint16_t tx_len) {
  switch (channel & ~IO_FLAGS) {
    case CHANNEL_SPI:
      if (tx_len) {
        io_seproxyhal_spi_send(G_io_apdu_buffer, tx_len);

        if (channel & IO_RESET_AFTER_REPLIED)
          reset();

        return 0;
      } else {
        return io_seproxyhal_spi_recv(
          G_io_apdu_buffer, sizeof(G_io_apdu_buffer), 0);
      }
      break;

    case CHANNEL_KEYBOARD:
      break;

    default:
      THROW(INVALID_PARAMETER);
      break;
  }

  return 0;
}

void
io_seproxyhal_display(const bagl_element_t *element) {
  io_seproxyhal_display_default((bagl_element_t *)element);
}
