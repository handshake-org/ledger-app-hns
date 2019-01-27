#include "apdu.h"
#include "ledger.h"
#include "utils.h"

#define CLA_GENERAL 0xe0
#define INS_FIRMWARE 0x40
#define INS_PUBKEY 0x42
#define INS_SIGNATURE 0x44

global_apdu_ctx_t global;

static inline void
hns_boot(void) {
  asm volatile("cpsie i");
  ledger_boot();
}

static inline void
hns_loop() {
  volatile uint8_t *buf = ledger_init();
  volatile uint8_t flags = 0;
  volatile uint16_t len = 0;
  volatile uint16_t sw = 0;

  for (;;) {
    len = ledger_apdu_exchange(flags, len, sw);

    BEGIN_TRY {
      TRY {
        volatile uint8_t * in = buf + HNS_OFFSET_CDATA;
        volatile uint8_t * out = buf;
        uint8_t p1 = buf[HNS_OFFSET_P1];
        uint8_t p2 = buf[HNS_OFFSET_P2];
        uint8_t cla = buf[HNS_OFFSET_CLA];
        uint8_t ins = buf[HNS_OFFSET_INS];
        uint8_t lc  = buf[HNS_OFFSET_LC];
        sw = HNS_OK;
        flags = 0;

        if (cla != CLA_GENERAL)
          THROW(HNS_CLA_NOT_SUPPORTED);

        if ((len - 5) != lc)
          THROW(HNS_INCORRECT_LC);

        switch(ins) {
          case INS_FIRMWARE:
            len = hns_apdu_get_app_version(p1, p2, lc, in, out, &flags);
            break;
          case INS_PUBKEY:
            len = hns_apdu_get_public_key(p1, p2, lc, in, out, &flags);
            break;
          case INS_SIGNATURE:
            len = hns_apdu_get_input_signature(p1, p2, lc, in, out, &flags);
            break;
          default:
            sw = HNS_INS_NOT_SUPPORTED;
            break;
        }
      }
      CATCH(LEDGER_RESET) {
        THROW(LEDGER_RESET);
      }
      CATCH_OTHER(e) {
        memset(buf, 0, g_ledger_apdu_buffer_size);
        sw = (e < 0x100) ? 0x6f00|e : e;
        len = 0;
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
      CATCH(LEDGER_RESET) {
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
