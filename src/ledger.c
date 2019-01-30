#include <stdbool.h>
#include "ledger.h"
#include "libbase58.h"

typedef cx_ecfp_private_key_t ledger_private_key_t;
typedef cx_ecfp_public_key_t ledger_public_key_t;

uint8_t *g_ledger_apdu_buffer;
uint16_t g_ledger_apdu_buffer_size;
uint16_t g_ledger_ui_step;
uint16_t g_ledger_ui_step_count;

uint8_t *
ledger_init(void) {
  g_ledger_apdu_buffer = G_io_apdu_buffer;
  g_ledger_apdu_buffer_size = sizeof(G_io_apdu_buffer);
  os_memset(G_io_apdu_buffer, 0, g_ledger_apdu_buffer_size);

  io_seproxyhal_init();
  USB_power(false);
  USB_power(true);
  ledger_ui_init();

  return G_io_apdu_buffer;
}

typedef struct ledger_bip32_node_s {
  uint8_t chaincode[32];
  ledger_private_key_t prv;
  ledger_public_key_t pub;
} ledger_bip32_node_t;

static void
ledger_ecdsa_derive_node(
  uint32_t *path,
  uint8_t depth,
  ledger_bip32_node_t *n
) {
  uint8_t priv[32];
  os_perso_derive_node_bip32(CX_CURVE_256K1, path, depth, priv, n->chaincode);
  cx_ecdsa_init_private_key(CX_CURVE_256K1, priv, 32, &n->prv);
  cx_ecfp_generate_pair(CX_CURVE_256K1, &n->pub, &n->prv, true);
  n->pub.W[0] = n->pub.W[64] & 1 ? 0x03 : 0x02;
}

bool
ledger_sha256(void *digest, const void *data, size_t data_sz) {
  if (digest == NULL)
    return false;

  if (data == NULL)
    return false;

  if (data_sz < 1)
    return false;

  cx_sha256_t sha256;
  cx_sha256_init(&sha256);
  cx_hash(&sha256.header, CX_LAST, data, data_sz, digest);

  return true;
}

void
ledger_ecdsa_derive_xpub(ledger_xpub_t *xpub) {
  // Derive child node and store pubkey & chain code.
  ledger_bip32_node_t n;
  ledger_ecdsa_derive_node(xpub->path, xpub->depth, &n);
  memmove(xpub->key, n.pub.W, sizeof(xpub->key));
  memmove(xpub->code, n.chaincode, sizeof(xpub->code));
  memset(&n.prv, 0, sizeof(n.prv));

  // Set parent fingerprint to 0x00000000.
  memset(xpub->fp, 0, sizeof(xpub->fp));

  // If parent exists, store fingerprint.
  if (xpub->depth > 1) {
    uint8_t buffer[32];
    union {
      cx_sha256_t sha256;
      cx_ripemd160_t ripemd;
    } ctx;

    ledger_ecdsa_derive_node(xpub->path, xpub->depth - 1, &n);
    cx_sha256_init(&ctx.sha256);
    cx_hash(&ctx.sha256.header, CX_LAST, n.pub.W, 33, buffer);
    cx_ripemd160_init(&ctx.ripemd);
    cx_hash(&ctx.ripemd.header, CX_LAST, buffer, sizeof(buffer), NULL);
    memmove(xpub->fp, ctx.ripemd.acc, sizeof(xpub->fp));
    memset(&n.prv, 0, sizeof(n.prv));
  }
}

void
ledger_ecdsa_sign(
  uint32_t *path,
  uint8_t depth,
  uint8_t *hash,
  size_t hash_len,
  uint8_t *sig
) {
  ledger_bip32_node_t n;
  ledger_ecdsa_derive_node(path, depth, &n);
  cx_ecdsa_sign(&n.prv, CX_RND_RFC6979 | CX_LAST, CX_SHA256,
    hash, hash_len, sig, NULL);
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
