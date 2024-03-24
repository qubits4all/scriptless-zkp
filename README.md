# Scriptless-ZKP

## Cryptographic Protocols & Blockchain-Agnostic Protocols R&D
### Adaptor & multi-party signatures, zero-knowledge proofs (ZKPs) & "scriptless" scripts

This Git repo has been constructed for organizing research and development (R&D) into cryptographic protocols,
including multi-party signatures, adaptor signatures, zero-knowledge proofs, and "scriptless" scripts.

An additional research focus is on applications to cross-blockchain operations, including [blockchain-agnostic
(universal) atomic swaps](https://eprint.iacr.org/2021/1612) and zero-knowledge contingent payment (zkCP) protocols.

**DISCLAIMER:** This codebase is presently in an early pre-Alpha version status focused on R&D, has _**not**_ yet
undergone any in-depth security audits, and as such should _**not**_ be used in any Production system.
- Please refer to the attached Mozilla Public License v2.0 ([LICENSE](https://github.com/qubits4all/scriptless-zkp/blob/develop/LICENSE)) for an associated disclaimer of any and
all liability or warrantability related to its use.

### Functional Existing Modules
**NOTE:** R&D-only Status (see above disclaimer)

- **Schnorr Signatures on Elliptic Curves** (ECC Schnorr) [`scriptless_zkp.ecc.signatures.schnorr`]
  - Currently supported (Weierstrass) prime-order curves: **NIST P-256** (`secp256r1`)
- **HMAC-based & Blake2b-based Keyed Hash Cryptographic Commitments** [`scriptless_zkp.commitments.hmac_commitments`]
- **Non-Interactive Zero-Knowledge** (NIZK) **Proofs of Knowledge** (PoKs) **of Discrete Logarithms** (over Elliptic
Curves) [`scriptless_zkp.ecc.zkp`]
- **Two-Party ECC Schnorr Signatures** (w/ indistinguishability from single-party ECC Schnorr signatures)
[`scriptless_zkp.ecc.signatures.two_party_schnorr`]

### Planned Future Work & Coming Soon

#### Coming Soon:
- ~~HMAC-based Cryptographic Commitments~~
- ~~Two-Party ECC Schnorr Signatures~~
- ~~Non-Interactive Zero-Knowledge (NIZK) Proofs of Knowledge (PoKs) of Discrete Logarithms (over Elliptic
Curves)~~
- **NIZK Proofs of Knowledge** (PoKs) **of _Equal_ Discrete Logarithms**
(based on the [Chaum-Pedersen protocol](https://link.springer.com/content/pdf/10.1007/3-540-48071-4_7.pdf))
- Support additional prime-order elliptic curves (ECC Schnorr, Two-Party ECC Schnorr and NIZK PoKs of Discrete Log
modules):
  - NIST P-384 (`secp384r1`)
  - NIST P-521 (`secp521r1`)

#### Planned Future Work:
- **Adaptor Signatures for ECC Schnorr** (single-party)
- Support for **[BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) compatible ECC Schnorr 
Signatures** (on the `secp256k1` elliptic curve used by Bitcoin & Ethereum)
- **BIP-340 compatible Two-Party ECC Schnorr Signatures**
- **Two-Party Adaptor Signatures for ECC Schnorr** (BIP-340 compatible)
- **Pedersen Commitments** & **Vector Pedersen Commitments** (on elliptic curves)
- **Zero-Knowledge Range Proofs** (based on [Bulletproofs](https://eprint.iacr.org/2017/1066.pdf))
- **Two-Party ECDSA Signatures** (based on [Yehuda Lindell's protocol](https://eprint.iacr.org/2017/552.pdf))
- **Two-Party Adaptor Signatures for ECDSA**
