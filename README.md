# ledger-app-hns

This is a key management application for the Handshake Protocol. It runs on
the Ledger Nano S personal security device and allows users to create extended
public keys, addresses, and signatures for valid Handshake transactions. It
can be used with the [hsd-ledger][hsd-ledger] client library to interact with
wallet software.

This document serves as an overview of the relevant technical and licensing
details for this application. For more general information on developing
for Ledger personal security devices please read the official Ledger developer
documentation [here][ledger].

For a walkthrough of a Ledger application, check out the [nanos-app-sia][sia]
project. The Nebulous Inc. developers have done a wonderful job of documenting
both the high-level architecture and low-level implementation details of
Nano S app development.


## Docker Build

Run `make docker` to compile the application in a Docker container.
The Dockerfile is heavily inspired by
<https://github.com/mkrufky/ledger-app-eth-dockerized>.

To load the app on a device outside of Ledger Live, clone
[nanos-secure-sdk](https://github.com/LedgerHQ/nanos-secure-sdk), check
out the branch that corresponds to the device firmware,
create a python virtual environment and install the dependencies,
set the environment variable `BOLOS_SDK` to be the absolute path
to the cloned git repo and then run `make docker-load`.
Be sure that the device is plugged in, unlocked and not currently
connected to another application.


## APDU Command Specification

This application interacts with a computer host through the APDU communication
protocol. This specification describes the APDU command interface for
`ledger-app-hns`.

The basic structure of an APDU command consists of a 5 byte header followed
by a variable amount of command input data. The header for an HNS Ledger
application command takes the following structure:

>NOTE: For the remainder of this document all lengths are represented in bytes.
All data is represented as little-endian bytestrings except where noted.

| Field | Len | Purpose                                               |
| ----  | --- | ----------------------------------------------------- |
| CLA   | 1   | Instruction class - the type of command (always 0xe0) |
| INS   | 1   | Instruction code - the specific command               |
| P1    | 1   | Instruction param #1                                  |
| P2    | 1   | Instruction param #2                                  |
| LC    | 1   | Length of command input data                          |

\*The above description is unique to this application. Specifically, the APDU protocol
allows for a larger LC field. A more general description of the APDU message protocol
can be found [here][apdu].

## Commands

- [GET APP VERSION](#get-app-version)
- [GET PUBLIC KEY](#get-public-key)
- [GET INPUT SIGNATURE](#get-input-signature)


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

This command returns a public key for the given BIP32 path.
Using the APDU parameter fields it can also return a Bech32
encoded address for the public key, or the details needed
reconstruct the extended public key at the specified level
in the HD tree.

The first instruction param (P1) can be used to require on-device
confirmation by setting the least significant bit. The next two
lowest bits are used to signify the network. The network flag is
only used for xpub confirmation. Address generation will parse the
network from the derivation path. If an unknown coin type is passed
during address generation, an error will be returned.

The second instruction param indicates which, if any, additional details
to return, i.e. extended public details and/or address. If confirmation
is turned on, and an address is generated, the address will be displayed
on screen. The next precedence will be given to extended public key
details. Otherwise, the public key will be displayed for confirmation.

>NOTE: an on-device warning will be displayed for non-hardened
derivation at the BIP44 account level or above. It will also be
displayed for derivations past the address index level.

#### Structure
##### Header

| CLA   | INS   | P1   | P2    | LC  |
| ----- | ----- | ---- | ----- | --- |
| 0xe0  | 0x42  | *var | **var | var |

\* P1:

- 0x00 = No confimation
- 0x01 = Require confirmation

0x06 is used as a mask to check second and third least significant bits.
- 0x00 = Mainnet
- 0x02 = Testnet
- 0x04 = Regtest
- 0x06 = Simnet

\* P2:
- 0x00 = Public key only
- 0x01 = Public key + chain code + parent fingerprint
- 0x02 = Public key + address
- 0x03 = Public key + chain code + parent fingerprint + address

##### Input data <a href="#encoded-path"></a>

| Field                               | Len |
| ----------------------------------- | --- |
| # of derivations (max 5)            | 1   |
| First derivation index (big-endian) | 4   |
| ...                                 | 4   |
| Last derivation index (big-endian)  | 4   |

##### Output data

| Field                           | Len |
| -------------------------       | --- |
| public key                      | 33  |
| chain code length               | 1   |
| chain code                      | var |
| parent fingerprint length       | 1   |
| parent fingerprint (big-endian) | var |
| address length                  | 1   |
| address                         | var |


### GET INPUT SIGNATURE
#### Description

This command handles the entire input signature creation process.
It operates in two modes: [parse](#parse) and [sign](#sign). When
engaged in parse mode, transaction details are sent to the device
where they are parsed, cached, and prepared for signing. Once all
tx details have been parsed, the user can send signature requests
for each input. The first signature request for a particular tx
requires on-device confirmation of the txid.

Both modes may require multiple message exchanges between the
client and the device. The first instruction param (P1) indicates
if a message is the initial one. An initial parse message clears
any cached transaction details from memory and restarts the signing
process. The initial message in a signature request should pass the
path of the signing key, the sighash type, the input, and the first
182 bytes of the input script (including the varint script size).
If the entire script does not fit into the first message, additional
messages will be necessary to send the rest of the script. The
subsequent messages should only include the remaining script bytes.

The second instruction param (P2) indicates the operation mode.

>NOTE: Signature requests for non-standard BIP44 address paths
will be rejected.

#### Structure - Parse Mode <a href="#parse"></a>
##### Header

| CLA   | INS   | P1   | P2    | LC  |
| ----- | ----- | ---- | ----- | --- |
| 0xe0  | 0x44  | *var | 0x00  | var |

\* P1:
- 0x01 = Initial message
- 0x00 = Following message

##### Input data

>NOTE: The transaction details should be sent in packets of up to
255 bytes. This is because the APDU command data length is represented
as a uint8_t.

| Field         | Len |
| ------------- | --- |
| version       | 4   |
| locktime      | var |
| # of inputs   | 1   |
| # of outputs  | 1   |
| sz of outputs | var |
| *inputs       | var |
| **outputs     | var |

\* Input serialization for parse mode

| Field         | Len |
| ------------- | --- |
| prevout       | 36  |
| sequence      | 4   |

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

#### Structure - Sign Mode <a href="#sign"></a>
##### Header

| CLA   | INS  | P1   | P2   | LC  |
| ----- | ---- | ---- | ---- | --- |
| 0xe0  | 0x44 | *var | 0x01 | var |

\* P1:
- 0x01 = Initial signature request (on-device txid confirmation required)
- 0x00 = Additional signature request

##### Input data

| Field               | Len |
| ------------------- | --- |
| *encoded BIP32 path | var |
| sighash type        | 4   |
| **input             | var |

\* See serialization format [above](#encoded-path). Non-standard BIP44 address
paths will be rejected.

** Input serialization for sign mode

| Field         | Len |
| ------------- | --- |
| prevout       | 36  |
| value         | 8   |
| sequence      | 4   |
| script length | var |
| script        | var |

>NOTE: If the size of the input data is larger than the APDU buffer size, the
script must be split into smaller packet sizes and sent in multiple messages.
Subsequent messages should only send the remaining script bytes. All other
input data i.e., the path, sighash type, prevout, value, sequence, and script
length, should not be resent.

##### Output data

| Field      | Len |
| ---------- | --- |
| signature  | var |

>NOTE: The application keeps track of the number of script bytes it has parsed
and will return a SUCCESS status word, without any response data, if it
successfully parsed the input data, but is expecting more bytes. After parsing
all script bytes, the signature will be generated and returned.

## Contribution and License Agreement

If you contribute code to this project, you are implicitly allowing your code
to be distributed under the MIT license. You are also implicitly verifying that
all code is your original work. `</legalese>`


## License

- Copyright (c) 2018, Boyma Fahnbulleh (MIT License).

Parts of this software are based on [ledger-app-btc][btc], [blue-app-nano][nano],
[nanos-app-sia][sia] and [hnsd][hnsd].

### ledger-app-btc

- Copyright (c) 2016, Ledger (Apache License).

### blue-app-nano

- Copyright (c) 2018, Mart Roosmaa (Apache License).

### nanos-app-sia

- Copyright (c) 2018, Nebulous Inc. (MIT License).

### hnsd

- Copyright (c) 2018, Christopher Jeffrey (MIT License).

See LICENSE for more info.

[hsd-ledger]: https://github.com/boymanjor/hsd-ledger
[ledger]: https://ledger.readhthedocs.io/en/latest/index.html
[apdu]: https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit
[sia]: https://gitlab.com/nebulouslabs/nanos-app-sia
[btc]: https://github.com/ledgerhq/ledger-app-btc
[nano]: https://github.com/roosmaa/blue-app-nano
[hnsd]: https://github.com/handshake-org/hnsd
