#include "ledger.h"

uint16_t g_ledger_ui_step;
uint16_t g_ledger_ui_step_count;

/**
 * The following functions are defined in ledger.h
 *
 * static inline void ledger_boot(void);
 * static inline void ledger_reset(void);
 * static inline void ledger_exit(void);
 * static inline uint16_t ledger_apdu_exchange(void);
 * static inline unsigned int ledger_pin_validated(void);
 */

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
  uint8_t depth
) {
  cx_ecfp_private_key_t private;
  cx_ecfp_public_key_t public;
  os_perso_derive_node_bip32(CX_CURVE_256K1, path, depth, n->prv, n->code);
  cx_ecdsa_init_private_key(CX_CURVE_256K1, n->prv, 32, &private);
  cx_ecfp_generate_pair(CX_CURVE_256K1, &public, &private, true);
  os_memmove(n->pub, public.W, sizeof(n->pub));
  n->pub[0] = public.W[64] & 1 ? 0x03 : 0x02;
  n->path = path;
  n->depth = depth;
  n->private = private;
  n->public = public;
}

void
ledger_ecdsa_sign(
  cx_ecfp_private_key_t priv,
  uint8_t * hash,
  size_t hash_len,
  uint8_t * sig,
  size_t sig_len
) {
  unsigned int info = 0;

  cx_ecdsa_sign(&priv, CX_LAST | CX_RND_TRNG, CX_SHA256,
    hash, hash_len, sig, &info);

  if (info & CX_ECCINFO_PARITY_ODD) {
    sig[0] |= 0x01;
  }
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
