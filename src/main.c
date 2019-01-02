#include "apdu.h"
#include "ledger.h"
#include "utils.h"

#define CLA_GENERAL 0xe0
#define INS_FIRMWARE 0x40
#define INS_PUBKEY 0x42
#define INS_SIGN 0x44

global_ctx_t global;

static inline void
hns_boot(void) {
  asm volatile("cpsie i");
  ledger_boot();
}

static inline void
hns_loop() {
  global.tx.init = false;
  volatile uint8_t * buf = ledger_init();
  volatile uint8_t len = 0;
  volatile uint8_t flags = 0;
  volatile uint8_t halted = 0;
  volatile uint16_t sw;

  for (;;) {
    len = ledger_apdu_exchange(flags, len);

    if(halted)
      break;

    BEGIN_TRY {
      TRY {
        sw  = HNS_SW_OK;
        uint8_t p1 = buf[HNS_OFFSET_P1];
        uint8_t p2 = buf[HNS_OFFSET_P2];
        uint8_t cla = buf[HNS_OFFSET_CLA];
        uint8_t ins = buf[HNS_OFFSET_INS];
        uint8_t lc  = buf[HNS_OFFSET_LC];
        volatile uint8_t * in = buf + HNS_OFFSET_CDATA;
        volatile uint8_t * out = buf;

        if (cla != CLA_GENERAL) {
          sw = HNS_SW_CLA_NOT_SUPPORTED;
          goto send_sw;
        }

        if ((len - 5) != lc) {
          sw = HNS_SW_INCORRECT_LENGTH;
          goto send_sw;
        }

        switch(ins) {
          case INS_FIRMWARE:
            len = hns_apdu_get_firmware_version(p1, p2, lc, in, &flags);
            break;
          case INS_PUBKEY:
            len = hns_apdu_get_wallet_public_key(p1, p2, lc, in, out, &flags);
            break;
          case INS_SIGN:
            len = hns_apdu_tx_sign(p1, p2, lc, in, out, &flags);
            break;
          default:
            sw = HNS_SW_INS_NOT_SUPPORTED;
            break;
        }

      send_sw:
        buf[len++] = sw >> 8;
        buf[len++] = sw & 0xff;
      }
      CATCH(EXCEPTION_IO_RESET) {
        THROW(EXCEPTION_IO_RESET);
      }
      CATCH_OTHER(e) {
        halted = 1;
        buf[0] = 0x6F;
        buf[1] = e;
        len = 2;
      }
      FINALLY;
    }
    END_TRY;
  }
}

static inline void
hns_main(void) {
  BEGIN_TRY {
    for (;;) {
      TRY {
        hns_loop();
      }
      CATCH(EXCEPTION_IO_RESET) {
        continue;
      }
      CATCH_ALL {
        break;
      }
      FINALLY;
    }
    ledger_exit(-1);
  }
  END_TRY;
}

__attribute__((section(".boot")))
int
main(void) {
  hns_boot();
  hns_main();

  return 0;
}
