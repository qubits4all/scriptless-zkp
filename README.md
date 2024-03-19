## Scriptless-ZKP

### Cryptographic protocols R&D: Adaptor & multi-party signatures, ZK proofs and "scriptless" scripts

This Git repo has been constructed for organizing research and development (R&D) into cryptographic protocols, including multi-party
signatures, adaptor signatures, zero-knowledge proofs, and "scriptless" scripts.
An additional focus is on applications to cross-blockchain operations, including blockchain-agnostic atomic swaps.

**DISCLAIMER:** This codebase is presently in an early pre-Alpha version status focused on R&D, has _**not**_ yet undergone any
in-depth security audits, and as such should _**not**_ be used in any Production system.
Please refer to the attached Mozilla Public License v2.0 ([LICENSE](https://github.com/qubits4all/scriptless-zkp/blob/develop/LICENSE))
for an associated disclaimer of any and all liability related to its use.

### Functional Existing Modules
**NOTE:** R&D-only Status (see above disclaimer)

- **Schnorr Signatures on Elliptic Curves** (`scriptless_zkp.ecc.schnorr`)
  - Currently supported (Weierstrass) prime-order curves:
    - **NIST P-256** (secp256r1)
  - TODO: Planned support for (Weierstrass) prime-order curves:
    - NIST P-384 (secp384r1)
    - NIST P-521 (secp521r1)
  - TODO: Planned support for curve(s), pending support in a backing dependency:
    - secp256k1 (used for ECDSA on Bitcoin & Ethereum blockchains)

### Planned Future Work & Coming Soon

#### Coming Soon:
- **Two-Party ECC Schnorr Signatures**
  - Including distributed multi-party computation of joint public key & private key-shares, and ZKP-based
  detection of deviations from correct protocol operation by either party.
- **Non-interactive Zero-Knowledge** (NIZK) **Proofs of Knowledge** (PoKs) **of Discrete Logarithms** (over Elliptic Curves)
- **NIZK Proofs of Knowledge** (PoKs) **of _Equal_ Discrete Logarithms** (based on [Chaum/Pedersen protocol](https://link.springer.com/content/pdf/10.1007/3-540-48071-4_7.pdf))
- **HMAC-based Cryptographic Commitments**

#### Planned Future Work:
- **Pedersen Commitments** & **Vector Pedersen Commitments** (on Elliptic Curves)
- **Adaptor Signatures for ECC Schnorr** (single-party)
- Support for **BIP-340 compatible ECC Schnorr Signatures** (on the secp256k1 elliptic curve used by Bitcoin)
- **BIP-340 compatible Two-Party ECC Schnorr Signatures**
- **Zero-Knowledge Range Proofs** (based on Bulletproofs)
- **Two-Party ECDSA Signatures** (based on [Yehuda Lindell's protocol](https://eprint.iacr.org/2017/552.pdf))
- **Two-Party Adaptor Signatures for ECC Schnorr** (BIP-340 compatible)
- **Two-Party Adaptor Signatures for ECDSA**
