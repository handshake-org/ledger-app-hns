#include "apdu.h"
#include "ledger.h"

static void
hns_boot(void) {
  asm volatile("cpsie i");
  ledger_boot();
}

static void
hns_loop() {
  volatile uint8_t * buf = ledger_init();
  volatile uint8_t len = 0;
  volatile uint8_t flags = 0;
  volatile uint8_t halted = 0;
  volatile uint16_t sw;

  for (;;) {
    len = ledger_apdu_exchange(flags, len);

    if(halted)
      ledger_reset();

    BEGIN_TRY {
      TRY {
        uint8_t cla = buf[HNS_OFFSET_CLA];
        uint8_t ins = buf[HNS_OFFSET_INS];
        uint8_t lc  = buf[HNS_OFFSET_LC];
        sw  = HNS_SW_OK;

        if (cla != 0xE0) {
          sw = HNS_SW_CLA_NOT_SUPPORTED;
          goto send_sw;
        }

        if ((len - 5) != lc) {
          sw = HNS_SW_INCORRECT_LENGTH;
          goto send_sw;
        }

        switch(ins) {
          case 0xC4:
            len = hns_apdu_get_firmware_version(buf, &flags);
            break;
          case 0x40:
            len = hns_apdu_get_wallet_public_key(buf, &flags);
            break;
          default:
            sw = HNS_SW_INS_NOT_SUPPORTED;
            break;
        }

      send_sw:
        buf[len] = sw >> 8;
        buf[len] = sw & 0xff;
        len += 2;
      }
      CATCH(EXCEPTION_IO_RESET) {
        THROW(EXCEPTION_IO_RESET);
      }
      CATCH(HNS_EX_INCORRECT_P1_P2) {
        sw = HNS_SW_INCORRECT_P1_P2;
      }
      CATCH(HNS_EX_INCORRECT_LENGTH) {
        sw = HNS_SW_INCORRECT_LENGTH;
      }
      CATCH(HNS_EX_SECURITY_STATUS_NOT_SATISFIED) {
        sw = HNS_SW_SECURITY_STATUS_NOT_SATISFIED;
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

static void
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
