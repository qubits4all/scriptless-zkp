"""Common constants used in the 'scriptless_zkp.ecc' package."""

DEFAULT_ECC_PRIVATE_KEY_ENCODING_METHOD: str = 'DER'
DEFAULT_ECC_POINT_ENCODING_METHOD: str = 'SEC1'

MIN_PKCS8_PASSPHRASE_LENGTH: int = 8
"""Minimum passphrase string/bytes length for KDF-based PKCS#8 key-wrap encryption (e.g. of ECC private keys)."""

MAX_PKCS8_HMAC_SHA1_PASSPHRASE_LENGTH: int = 64
"""
Maximum passphrase string/bytes length for KDF-based PKCS#8 key-wrap encryption, when using an HMAC/SHA-1 variant
(e.g., PBKDF2 w/ HMAC/SHA-1 & AES-CBC). Passphrases longer than 64 bytes (512 bits) will produce identical keys, due
to SHA-1's block-size (512 bits). This limit is also intended to prevent denial-of-service attacks, made possible
when no limit is imposed on user-entered passphrases.
"""

MIN_PKCS8_SALT_BYTES: int = 16  # 128 bits
"""
Minimum PKCS#8 salt length (bytes), per NIST guidelines in SP 800-132.
(See: "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf")
"""

MAX_PKCS8_HMAC_SHA1_SALT_BYTES: int = 64      # equal to SHA-1 block-size: 512 bits

DEFAULT_PKCS8_HMAC_SHA1_SALT_BYTES: int = 32  # 256 bits
"""Default PKCS#8 salt length (bytes), for KDF-based key-wrap encryption (e.g. of ECC private keys)."""

OWASP_PBKDF2_SHA1_ITERATIONS: int = 1_300_000
"""
Recommended iterations for PBKDF2 with HMAC/SHA-1, per OWASP 2023 guidelines for protection against GPU-based attacks.
(See: "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2")
"""

OWASP_PBKDF2_SHA256_ITERATIONS: int = 600_000
"""
Recommended iterations for PBKDF2 with HMAC/SHA-256, per OWASP 2023 guidelines for protection against GPU-based attacks.
(See: "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2")
"""

OWASP_PBKDF2_SHA512_ITERATIONS: int = 210_000
"""
Recommended iterations for PBKDF2 with HMAC/SHA-512, per OWASP 2023 guidelines for protection against GPU-based attacks.
(See: "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2")
"""

# PKCS#8 KDF configurations w/ PBKDF2, supported by the PyCryptodome library for password-based key-wrap encryption of
# ECC private keys:
PKCS8_ECC_KDF_PBKDF2_SHA1_AES128_CBC: str = 'PBKDF2WithHMAC-SHA1AndAES128-CBC'  # PBKDF2 w/ HMAC-SHA1 & AES-128-CBC
PKCS8_ECC_KDF_PBKDF2_SHA1_AES192_CBC: str = 'PBKDF2WithHMAC-SHA1AndAES192-CBC'  # PBKDF2 w/ HMAC-SHA1 & AES-192-CBC
PKCS8_ECC_KDF_PBKDF2_SHA1_AES256_CBC: str = 'PBKDF2WithHMAC-SHA1AndAES256-CBC'  # PBKDF2 w/ HMAC-SHA1 & AES-256-CBC

DEFAULT_ECC_PRIVATE_KEY_PKCS8_KDF: str = PKCS8_ECC_KDF_PBKDF2_SHA1_AES128_CBC
"""
Default password-based key derivation function (KDF) for PKCS#8 key-wrap encryption of ECC private keys,
using a provided passphrase.
"""
