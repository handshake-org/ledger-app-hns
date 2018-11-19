#ifndef _HNS_APDU_H
#define _HNS_APDU_H

#include <stdbool.h>
#include <stdint.h>
#include "utils.h"

#define HNS_APDU_COUNT 2
#define HNS_OFFSET_CLA 0x00
#define HNS_OFFSET_INS 0x01
#define HNS_OFFSET_P1 0x02
#define HNS_OFFSET_P2 0x03
#define HNS_OFFSET_LC 0x04
#define HNS_OFFSET_CDATA 0x05

#define HNS_SW_OK 0x9000
#define HNS_SW_INCORRECT_P1_P2 0x6B00
#define HNS_SW_INCORRECT_LENGTH 0x6700
#define HNS_SW_SECURITY_STATUS_NOT_SATISFIED 0x6982
#define HNS_SW_INS_NOT_SUPPORTED 0x6D00
#define HNS_SW_CLA_NOT_SUPPORTED 0x6E00
#define HNS_SW_INCORRECT_DATA 0x6A80

#define HNS_EX_INCORRECT_P1_P2 19
#define HNS_EX_INCORRECT_LENGTH 20
#define HNS_EX_SECURITY_STATUS_NOT_SATISFIED 21

volatile uint8_t
hns_apdu_get_firmware_version(volatile uint8_t *, volatile uint8_t *);

volatile uint8_t
hns_apdu_get_wallet_public_key(volatile uint8_t *, volatile uint8_t *);
#endif
