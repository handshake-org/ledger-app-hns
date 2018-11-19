# Handshake wallet application : Common Technical Specifications

Boyma Fahnbulleh <boymanjor@protonmail.com>
Ledger Firmware Team <hello@ledger.fr>
Application version 0.1.0

## About

This specification describes the APDU messages interface to communicate
with the Handshake wallet application. It is based on the HW.1 firmware spec
detailed on https://github.com/LedgerHQ/btchip-doc and the ledger-btc-app spec
detailed on https://github.com/LedgerHQ/ledger-app-btc/blob/master/doc/btc.asc

## Transport protocol

### General transport description

Ledger APDU requests and responses are encapsulated using a flexible
protocol allowing fragmentation of large payloads over different underlying
transport mechanisms.

The common transport header is defined as follows:

| Description                           | Length |
| ------------------------------------- | ------ |
| Communication channel ID (big endian) | 2      |
| Command tag                           | 1      |
| Packet sequence index (big endian)    | 2      |
| Payload                               | var    |

The Communication channel ID allows commands multiplexing over the same
physical link. It is not used for the time being, and should be set to 0101
to avoid compatibility issues with implementations ignoring a leading 00 byte.

The Command tag describes the message content. Use TAG_APDU (0x05) for standard
APDU payloads, or TAG_PING (0x02) for a simple link test.

The Packet sequence index describes the current sequence for fragmented payloads.
The first fragment index is 0x00.

### APDU Command payload encoding

APDU Command payloads are encoded as follows:

| Description              | Length |
| ------------------------ | ------ |
| APDU length (big endian) | 2      |
| APDU CLA                 | 1      |
| APDU INS                 | 1      |
| APDU P1                  | 1      |
| APDU P2                  | 1      |
| APDU length              | 1      |
| Optional APDU data       | var    |

APDU payload is encoded according to the APDU case:

| Case Number  | Lc  | Le  | Case description                                        |
| ------------ | --- | --- | ------------------------------------------------------- |
| 1            | 0   | 0   | No data in either direction - L is set to 00            |
| 2            | 0   | !0  | Input Data present, no Output Data - L is set to Lc     |
| 3            | !0  | 0   | Output Data present, no Input Data - L is set to Le     |
| 4            | !0  | !0  | Both Input and Output Data are present - L is set to Lc |

### APDU Response payload encoding

APDU Response payloads are encoded as follows:

| Description                        | Length |
| ---------------------------------- | ------ |
| APDU response length (big endian)  | 2      |
| APDU response data and Status Word | var    |

### USB mapping

Messages are exchanged with the dongle over HID endpoints over interrupt
transfers, with each chunk being 64 bytes long. The HID Report ID is ignored.

## Status words

The following standard Status Words are returned for all APDUs - some specific
Status Words can be used for specific commands and are mentioned in the command description.

Status words

| SW   | Description                                                                   |
| ---- | ------------------------------------------------------------------------------|
| 6700 | Incorrect length                                                              |
| 6982 | Security status not satisfied (dongle is locked or busy with another request) |
| 6985 | User declined the request                                                     |
| 6A80 | Invalid input data                                                            |
| 6A81 | Failed to verify the provided signature                                       |
| 6A82 | Parent block data cache-miss (cache parent before sign)                       |
| 6B00 | Incorrect parameter P1 or P2                                                  |
| 6Fxx | Technical problem (Internal error, please report)                             |
| 9000 | Normal ending of the command                                                  |

## Wallet usage APDUs

### GET FIRMWARE VERSION
#### Description

This command returns the firmware version of the dongle and additional
features supported.

#### Coding

##### Command

| CLA | INS | P1  | P2  | Lc  | Le  |
| --- | --- | --- | --- | --- | --- |
| E0  | C4  | 00  | 00  | 00  | 03  |

##### Input data

None

##### Output data

| Description                                     | Length |
| ----------------------------------------------- | ------ |
| \*Features flags                                | 1      |
| Architecture (only since Ledger Wallet, or RFU) | 1      |
| Firmware major version                          | 1      |
| Firmware minor version                          | 1      |
| Firmware patch version                          | 1      |
| Loader ID major version (if applicable)         | 1      |
| Loader ID minor version (if applicable)         | 1      |

##### Feature flags
0x01 : public keys are compressed (otherwise not compressed)
0x02 : implementation running with screen + buttons handled by the Secure Element
0x04 : implementation running with screen + buttons handled externally
0x08 : NFC transport and payment extensions supported
0x10 : BLE transport and low power extensions supported
0x20 : implementation running on a Trusted Execution Environment

### GET WALLET PUBLIC KEY
#### Description

This command returns the public key and Bech32 encoded address for the given
BIP 32 path.

#### Coding
##### Command

| CLA | INS | P1  | P2  | Lc  | Le  |
| --- | --- | --- | --- | --- | --- |
| E0  | 40  | 00  | 00  | var | var |


##### Input data

| Description                                      | Length |
| ------------------------------------------------ | ------ |
| Number of BIP 32 derivations to perform (max 10) | 1      |
| First derivation index (big endian)              | 4      |
| ...                                              | 4      |
| Last derivation index (big endian)               | 4      |

##### Output data

| Description             | Length |
| ----------------------- | ------ |
| Public key length       | 1      |
| Uncompressed public Key | var    |
| HNS address length      | 1      |
| HNS address             | var    |
| BIP32 chain code        | 32     |

## Test and utility APDUs

### Get app configuration
#### Description

This command returns the application configuration.

#### Coding
##### Command

| CLA | INS | P1  | P2  | Lc  | Le  |
| --- | --- | --- | --- | --- | --- |
| A1  | 01  | 00  | 00  | 00  |     |

##### Input data

None

##### Output data

| Description       | Length |
| ----------------- | ------ |
| Major app version | 1      |
| Minor app version | 1      |
| Patch app version | 1      |
| Network length    | 1      |
| Network           | var    |

