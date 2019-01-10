# APDU Command Specification for HNS Ledger App

Boyma Fahnbulleh <boymanjor@protonmail.com>
Application version 0.1.0

## About

This specification describes the APDU command interface to communicate with
the Handshake wallet application.

## APDU Commands

### GET APP VERSION
#### Description

This command returns the application's version number.

#### Coding
##### Command

| CLA   | INS   | P1   | P2   | LC   |
| ----- | ----- | ---- | ---- | ---- |
| 0xe0  | 0x40  | 0x00 | 0x00 | 0x00 |

##### Input data

None

##### Output data

| Description       | Length |
| ----------------- | ------ |
| App major version | 1      |
| App minor version | 1      |
| App patch version | 1      |

### GET PUBLIC KEY
#### Description

This command returns the extended public key and Bech32 encoded address for
the given BIP 32 path. The first argument can be used to require on-device
confirmation of the public key or address. The second argument controls the
network to use when generating the address.

#### Coding
##### Command

| CLA   | INS   | P1   | P2    | LC  |
| ----- | ----- | ---- | ----- | --- |
| 0xe0  | 0x42  | var* | var** | var |

* The second lsb can be set to require on-device confirmation. The lsb
controls which value to display. Setting it displays the pubkey.

** 0x00 = mainnet, 0x01 = testnet, 0x02 = simnet, 0x03 = regtest

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
| Compressed public Key   | var    |
| HNS address length      | 1      |
| HNS address             | var    |
| BIP32 chain code        | 32     |

