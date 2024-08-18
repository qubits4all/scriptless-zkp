###############################################################################
# (c) 2024 W. Spann Systems Consulting
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###############################################################################

"""Common constants used in the `scriptless_zkp.he` homomorphic encryption (HE) package."""

# PKCS#8 password-based key-wrap encryption constants re: passphrase lengths:

MIN_PKCS8_PASSPHRASE_LENGTH: int = 10  # min. passphrase length (bytes) for KDF-based PKCS#8 key-wrap encryption
"""
Minimum passphrase length (bytes) per OWASP guidelines.
:see: `OWASP Top Ten Proactive Controls 2018: Implement Digital Identity <https://top10proactive.owasp.org/v3/en/c6-digital-identity>`_
"""

MAX_PKCS8_HMAC_SHA2_PASSPHRASE_LENGTH: int = 64  # max. passphrase length (bytes) for HMAC/SHA-2-based KDF

MAX_PKCS8_HMAC_SHA3_PASSPHRASE_LENGTH: int = 72  # max. passphrase length (bytes) for HMAC/SHA-3-based KDF


# PKCS#8 password-based key-wrap encryption constants re: salt lengths:

MIN_PKCS8_HMAC_SALT_BYTES: int = 16  # 128 bits
"""
Minimum PKCS#8 salt length (bytes), per NIST guidelines in SP 800-132.
:see: `NIST Special Publication 800-132: Recommendation for Password-Based Key Derivation <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf>`_
"""

MAX_PKCS8_HMAC_SHA2_SALT_BYTES: int = 64      # equal to the SHA-256 block-size: 512 bits

MAX_PKCS8_HMAC_SHA3_SALT_BYTES: int = 72      # equal to the SHA3-512 block-size: 576 bits

DEFAULT_PKCS8_HMAC_SALT_BYTES: int = 32  # 256 bits
"""Default PKCS#8 salt length (bytes), for KDF-based key-wrap encryption (e.g. of private keys)."""


# PKCS#8 password-based key-wrap encryption constants re: HMAC iterations:

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


DEFAULT_HMAC_HASH_ALGORITHM: str = "HMAC-SHA3-256"

DEFAULT_PKCS8_AES_KEY_BYTES: int = 16  # AES-128 key size (128 bits)


# PBKDF2 KDF configuration constants:

# PKCS#8 KDF configurations w/ PBKDF2 (HMAC-SHA-2 family) for password-based key-wrap encryption of private keys:
PKCS8_KDF_PBKDF2_SHA224_AES128_CBC: str = 'PBKDF2WithHMAC-SHA224AndAES128-CBC'  # PBKDF2 w/ HMAC-SHA224 & AES-128-CBC
PKCS8_KDF_PBKDF2_SHA256_AES128_CBC: str = 'PBKDF2WithHMAC-SHA256AndAES128-CBC'  # PBKDF2 w/ HMAC-SHA256 & AES-128-CBC
PKCS8_KDF_PBKDF2_SHA384_AES192_CBC: str = 'PBKDF2WithHMAC-SHA384AndAES192-CBC'  # PBKDF2 w/ HMAC-SHA384 & AES-192-CBC
PKCS8_KDF_PBKDF2_SHA512_AES256_CBC: str = 'PBKDF2WithHMAC-SHA512AndAES256-CBC'  # PBKDF2 w/ HMAC-SHA512 & AES-256-CBC

# PKCS#8 KDF configurations w/ PBKDF2 (HMAC-SHA-3 family) for password-based key-wrap encryption of private keys:
PKCS8_KDF_PBKDF2_SHA3_224_AES128_CBC: str = 'PBKDF2WithHMAC-SHA3-224AndAES128-CBC'  # PBKDF2 w/ HMAC-SHA3-224 & AES-128-CBC
PKCS8_KDF_PBKDF2_SHA3_256_AES128_CBC: str = 'PBKDF2WithHMAC-SHA3-256AndAES128-CBC'  # PBKDF2 w/ HMAC-SHA3-256 & AES-128-CBC
PKCS8_KDF_PBKDF2_SHA3_384_AES192_CBC: str = 'PBKDF2WithHMAC-SHA3-384AndAES192-CBC'  # PBKDF2 w/ HMAC-SHA3-384 & AES-192-CBC
PKCS8_KDF_PBKDF2_SHA3_512_AES256_CBC: str = 'PBKDF2WithHMAC-SHA3-512AndAES256-CBC'  # PBKDF2 w/ HMAC-SHA3-512 & AES-256-CBC

DEFAULT_PRIVATE_KEY_PKCS8_KDF: str = PKCS8_KDF_PBKDF2_SHA3_256_AES128_CBC  # default PKCS#8 KDF for private keys
