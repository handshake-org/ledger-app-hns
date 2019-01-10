# ledger-app-hns

This is a key management application for the Handshake Protocol. It runs on
the Ledger Nano S and Ledger Blue personal security devices. It allows users
to create extended public keys and addresses as well as create signatures
for valid Handshake transactions. It can be used with the [hns-ledger] client
library to interact with wallet software.

This document serves as an overview of the relevant technical and licensing
details for this application. For more general information on developing
for Ledger personal security devices please read the official Ledger developer
documentation [here][ledger].

For a walkthrough of a Ledger application, check out the [nanos-app-sia][sia]
project. The Nebulous Inc. developers have done a wonderful job of documenting
both the high-level architecture and low-level implementation details of
Nano S app development.

## APDU Command Specification

This application interacts with a computer host through the APDU communication
protocol. This specification describes the APDU command interface for
`ledger-app-hns`.

The basic structure of an APDU command consists of a 5 byte header followed
by a variable amount of command input data, if necessary. The header for
an HNS Ledger application command takes the following structure:

>NOTE: for the remainder of this document all lengths are displayed in bytes.

| Field | Len | Purpose                                               |
| ----  | --- | ----------------------------------------------------- |
| CLA   | 1   | Instruction class - the type of command (always 0xe0) |
| INS   | 1   | Instruction code - the specific command               |
| P1    | 1   | Instruction param #1                                  |
| P2    | 1   | Instruction param #2                                  |
| LC    | 1   | Length of command's input data                        |

>NOTE: the above description is unique to this application. Specifically,
the APDU protocl allows for a larger LC field. A more general description
of the APDU message protocol can be found [here][apdu].

### GET APP VERSION
#### Description

This command returns the application's version number.

#### Structure
##### Header

| CLA   | INS   | P1   | P2   | LC   |
| ----- | ----- | ---- | ---- | ---- |
| 0xe0  | 0x40  | 0x00 | 0x00 | 0x00 |

##### Input data

None

##### Output data

| Field         | Len |
| ------------- | --- |
| major version | 1   |
| minor version | 1   |
| patch version | 1   |

### GET PUBLIC KEY
#### Description

This command returns the extended public key and Bech32 encoded address for
the given BIP 32 path.

The first instruction param (P1) can be used to require on-device confirmation
of the public key or address. The second lsb can be set to require on-device
confirmation. The lsb controls which value to display.

The second instruction param (P2) controls theSetting it displays the pubkey,
i.e. network to use when generating the address.

#### Structure
##### Header

| CLA   | INS   | P1   | P2    | LC  |
| ----- | ----- | ---- | ----- | --- |
| 0xe0  | 0x42  | *var | **var | var |

* P1:
- 0x00 = No confimation
- 0x01 = No confimation
- 0x02 = Address confirmation
- 0x03 = Public key confirmation

** P2:
- 0x00 = mainnet
- 0x01 = testnet
- 0x02 = simnet
- 0x03 = regtest

##### Input data <a href="#encoded-path"></a>

| Field                               | Len |
| ----------------------------------- | --- |
| # of derivations (max 10)           | 1   |
| First derivation index (big endian) | 4   |
| ...                                 | 4   |
| Last derivation index (big endian)  | 4   |

##### Output data

| Field             | Len |
| ----------------- | --- |
| public key length | 1   |
| public key        | var |
| address length    | 1   |
| address           | var |
| chaincode         | 32  |

### SIGN TX
#### Description

This command handles the entire signature creation process. It
operates in two modes: parse and sign. When engaged in parse mode,
transaction details are sent to the device where they are parsed,
cached, and prepared for signing. Once all tx details have been
parsed, the user can send signature requests to the device for
each input.

Both modes may require multiple exchanges between the client and
the application. The first instruction param (P1) indicates if a
message is the initial one.

The second instruction param (P2) indicates the operation mode.
The initial parse message clears any cached transaction details
from memory. The initial signature request requires on-device
confirmation of the calculated txid.

#### Structure - Parse Mode
##### Header

| CLA   | INS   | P1   | P2    | LC  |
| ----- | ----- | ---- | ----- | --- |
| 0xe0  | 0x44  | *var | 0x00  | var |

* P1:
- 0x01 = Initial message
- 0x00 = Following message

##### Input data

>NOTE: the tx details should be sent over in packets of up to 331 bytes.

| Field         | Len |
| ------------- | --- |
| version       | 4   |
| locktime      | var |
| # of inputs   | 1   |
| # of outputs  | 1   |
| sz of outputs | var |
| *inputs       | var |
| **outputs     | var |

* Input serialization

| Field         | Len |
| ------------- | --- |
| prevout       | 36  |
| value         | 8   |
| sequence      | 4   |
| script length | var |
| script        | var |

** Output serialization

| Field         | Len |
| ------------- | --- |
| value         | 8   |
| ***address    | var |
| ****covenant  | var |

*** Address serialization

| Field       | Len |
| ----------- | --- |
| version     | 1   |
| hash length | 1   |
| hash        | var |

**** Covenant serialization

| Field       | Len |
| ----------- | --- |
| type        | 1   |
| # of items  | var |
| items       | var |

##### Output data

None

#### Structure - Sign Mode
##### Header

| CLA   | INS  | P1   | P2   | LC  |
| ----- | ---- | ---- | ---- | --- |
| 0xe0  | 0x44 | *var | 0x01 | var |

* P1:
- 0x01 = Initial signature request (on-device txid confirmation required)
- 0x00 = Additional signature request

##### Input data

| Field               | Len |
| ------------------- | --- |
| *encoded BIP32 path | var |
| input index         | 1   |
| sighash type        | 4   |

* See serialization format [above](#encoded-path)

##### Output data

| Field      | Len |
| ---------- | --- |
| signature  | var |

## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`

## License

- Copyright (c) 2018, Boyma Fahnbulleh (MIT License).

Parts of this software are based on [ledger-app-btc][btc], [blue-app-nano][nano],
[nanos-app-sia][sia] and [hnsd][hnsd].

### ledger-app-btc

- Copyright (c) 2016-2018, Ledger (Apache License).

### blue-app-nano

- Copyright (c) 2018, Mart Roosmaa (Apache License).

### nanos-app-sia

- Copyright (c) 2018, Nebulous Inc. (MIT License).

### hnsd

- Copyright (c) 2018, Christopher Jeffrey (MIT License).

See LICENSE for more info.

[ledger]: https://ledger.readhthedocs.io/en/latest/index.html
[apdu]: https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit
[sia]: https://gitlab.com/nebulouslabs/nanos-app-sia
[btc]: https://github.com/ledgerhq/ledger-app-btc
[nano]: https://github.com/roosmaa/blue-app-nano
[hnsd]: https://github.com/handshake-org/hnsd
