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

#### Digital Signatures (single-party) [[scriptless_zkp.ecc.signatures](https://github.com/qubits4all/scriptless-zkp/tree/develop/src/python/scriptless_zkp/ecc/signatures)]
  - **Schnorr Signatures on Elliptic Curves** (ECC Schnorr) [`scriptless_zkp.ecc.signatures.schnorr`]
    - Supported elliptic curves: **NIST P-256** (`secp256r1`), NIST P-384 (`secp384r1`), NIST P-521 (`secp521r1`)
  - **Adaptor Signatures for ECC Schnorr** (a.k.a. Verifiable Encrypted Signatures) [`scriptless_zkp.ecc.signatures.adaptor_schnorr`]
    - Supported elliptic curves: **NIST P-256** (`secp256r1`), NIST P-384 (`secp384r1`), NIST P-521 (`secp521r1`)

#### Two-Party Digital Signatures  [[scriptless_zkp.ecc.signatures](https://github.com/qubits4all/scriptless-zkp/tree/develop/src/python/scriptless_zkp/ecc/signatures)]
  - **Two-Party ECC Schnorr Signatures** [`scriptless_zkp.ecc.signatures.two_party_schnorr`]
    - Features verification via a joint public key & indistinguishability from single-party ECC Schnorr signatures.

#### Elliptic Curve Cryptography (ECC) [[scriptless_zkp.ecc](https://github.com/qubits4all/scriptless-zkp/tree/develop/src/python/scriptless_zkp/ecc)]
  - Support for prime-order elliptic curves (Weierstrass form) [`scriptless_zkp.ecc.weierstrass_curves`]
    - **NIST P-256** (`secp256r1`), **NIST P-384** (`secp384r1`), **NIST P-521** (`secp521r1`)
  - Support derivation of effectively independent ECC generator points [`scriptless_zkp.ecc.ecc_utils`]
    - Generation of elliptic curve generator points for which _nobody_ knows the discrete logarithm w.r.t. the base
    point `G`.

#### Cryptographic Commitments [[scriptless_zkp.commitments](https://github.com/qubits4all/scriptless-zkp/tree/develop/src/python/scriptless_zkp/commitments)]
  - **HMAC-based & Blake2b-based Keyed-Hash Commitments** [`scriptless_zkp.commitments.hmac_commitments`]

#### Non-Interactive Zero-Knowledge (NIZK) Proofs (over Elliptic Curves) [[scriptless_zkp.ecc.zkp](https://github.com/qubits4all/scriptless-zkp/tree/develop/src/python/scriptless_zkp/ecc/zkp)]
  - **NIZK Proofs of Knowledge** (PoKs) **of a Discrete Logarithm** [`scriptless_zkp.ecc.zkp.nizk_dlog_proof`]
  - **NIZK Proofs of Knowledge** (PoKs) **of _Equal_ Discrete Logarithms**
  [`scriptless_zkp.ecc.zkp.nizk_equal_dlogs_proof`]
    - Based on the [Chaum-Pedersen protocol](https://link.springer.com/content/pdf/10.1007/3-540-48071-4_7.pdf) adapted for elliptic curves, generalized from 2 equal discrete logs
    to support from 1 to N equal discrete logs, and made non-interactive via the [Fiat-Shamir transform](
    https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic).
  - **ZK Proof-Commitments for NIZK Proofs of Knowledge** (PoKs) **of a Discrete Logarithm**
  [`scriptless_zkp.ecc.zkp.nizk_dlog_proof_commitments`]
    - Combines an NIZK proof and a cryptographic commitment to the proof & its public parameters, which is useful in
    multi-party protocols involving ZK proofs (e.g., for ensuring correct protocol execution by each party).


### Planned Future Work & Coming Soon

#### Coming Soon:

- ~~Non-Interactive Zero-Knowledge (NIZK) Proofs of Knowledge (PoKs) of Discrete Logarithms (over Elliptic
Curves)~~
- ~~NIZK Proofs of Knowledge (PoKs) of _Equal_ Discrete Logarithms
(based on the Chaum-Pedersen protocol)~~
- **Two-Party Adaptor Signatures for ECC Schnorr**
  - (incl. optional specification of a domain separation tag)
- Two-Party ECC Schnorr and NIZK PoKs of Discrete Log modules
  - Support additional prime-order elliptic curves:
    - NIST P-384 (`secp384r1`)
    - NIST P-521 (`secp521r1`)


#### Planned Future Work:

- ~~Adaptor Signatures for ECC Schnorr (single-party)~~
- Support for **[BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) compatible ECC Schnorr Signatures**
  - Using the `secp256k1` elliptic curve used by the Bitcoin & Ethereum blockchains, and incorporating specific Bitcoin
  BIP-340 standard domain separation tags into the various cryptographic hash operations.
- Support for **BIP-340 compatible Two-Party ECC Schnorr Signatures**
- **Two-Party Adaptor Signatures for ECC Schnorr** (BIP-340 compatible)
- **Pedersen Commitments** & **Vector Pedersen Commitments** (over Elliptic Curves)
- **Zero-Knowledge Range Proofs** (based on [Bulletproofs](https://eprint.iacr.org/2017/1066.pdf))
- **Two-Party ECDSA Signatures** (based on [Yehuda Lindell's protocol](https://eprint.iacr.org/2017/552.pdf))
- **Two-Party Adaptor Signatures for ECDSA**
