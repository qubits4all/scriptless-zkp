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

from __future__ import annotations

import base64
import binascii

from dataclasses import dataclass

from Cryptodome.Util import number
from Cryptodome.IO import PKCS8

import libnum

from scriptless_zkp import utils, number_theory
from scriptless_zkp.he import (
    DEFAULT_HMAC_HASH_ALGORITHM, DEFAULT_PKCS8_HMAC_SALT_BYTES, DEFAULT_PKCS8_AES_KEY_BYTES,
    MIN_PKCS8_PASSPHRASE_LENGTH, PKCS8_KDF_PBKDF2_SHA224_AES128_CBC, PKCS8_KDF_PBKDF2_SHA256_AES128_CBC,
    PKCS8_KDF_PBKDF2_SHA384_AES192_CBC, PKCS8_KDF_PBKDF2_SHA512_AES256_CBC, PKCS8_KDF_PBKDF2_SHA3_224_AES128_CBC,
    PKCS8_KDF_PBKDF2_SHA3_256_AES128_CBC, PKCS8_KDF_PBKDF2_SHA3_384_AES192_CBC, PKCS8_KDF_PBKDF2_SHA3_512_AES256_CBC,
    OWASP_PBKDF2_SHA256_ITERATIONS
)
from scriptless_zkp.number_theory import random_strong_prime, mod_inverse
from scriptless_zkp.utils import safe_divide

MIN_KEY_SIZE: int = 2048      # Note: Min. key-size for use in Y. Lindell's 2-Party ECDSA protocol w/ 256-bit ECC keys.
DEFAULT_KEY_SIZE: int = 3072  # Default based on NIST recommended min. RSA key size of 3072 bits.
RSA_OID: str = '1.2.840.113549.1.1.1'  # RSA OID used as a placeholder for Paillier private keys (no specific OID).


# TODO: Replace use of Python's built-in `pow` with a constant-time modular exponentiation implementation
#   (e.g., the gmpy2 library's `gmpy2.powmod_sec(x, y, m)` function), to mitigate the risk of timing attacks.
@dataclass
class PaillierPrivateKey:
    p: int   # private prime p
    q: int   # private prime q

    # noinspection NonAsciiCharacters
    λ: int   # private key lambda: `λ(n) = lcm(p-1, q-1)` -- The Carmichael function of public modulus n
    n: int   # public modulus: `n = p * q`, for private p, q prime
    mu: int  # modular inverse of private key lambda: `λ(n)^-1 mod n`
    n2: int  # cached square `n^2` of the public modulus `n`

    # noinspection NonAsciiCharacters
    def __init__(self, private_prime_p: int, private_prime_q: int, validate: bool = False):
        self.p = private_prime_p
        self.q = private_prime_q

        # Compute the private key: `λ(n) := lcm(p-1, q-1)` (i.e., the Carmichael function of n).
        self.λ = self._calc_private_lambda(private_prime_p, private_prime_q)
        self.n = private_prime_p * private_prime_q
        self.n2 = self.n ** 2

        if validate:
            self._validate(private_prime_p, private_prime_q, self.n)

        # Calculate the modular inverse of the private key lambda: `λ(n)^-1 mod n`
        self.mu = mod_inverse(self.λ, self.n)

    @staticmethod
    def _calc_private_lambda(p: int, q: int) -> int:
        """
        Computes the private key's lambda value: `λ(n) = lcm(p-1, q-1)` (i.e., the Carmichael function of `n`) for a
        Paillier key-pair, given the two prime factors `p` and `q` of the public modulus `n = p * q`.

        :param p: The first prime factor `p` of the public modulus `n = p * q`.
        :param q: The second prime factor `q` of the public modulus `n = p * q`.
        :return: A Paillier private key's lambda value: `λ(n) = lcm(p-1, q-1)` (i.e., the Carmichael function of `n`).
        """
        return libnum.lcm(p - 1, q - 1)

    @staticmethod
    def _validate(private_prime_p: int, private_prime_q: int, public_modulus: int) -> None:
        if private_prime_p == private_prime_q:
            raise ValueError("Invalid Paillier private key -- prime factors 'p' and 'q' must be distinct.")

        min_private_primes_size: int = MIN_KEY_SIZE // 2 - 1
        if (
            private_prime_p.bit_length() < min_private_primes_size
                or private_prime_q.bit_length() < min_private_primes_size
        ):
            raise ValueError(
                f"Invalid Paillier private key -- private prime factors 'p' and 'q' of the public modulus must be at"
                f" least [{min_private_primes_size}] bits each."
            )

        if public_modulus.bit_length() < MIN_KEY_SIZE - 1:
            raise ValueError(
                f"Invalid Paillier private key -- public modulus must be at least [{MIN_KEY_SIZE - 2}] bits."
            )

    def validate_private_key(self) -> None:
        """
        Determines if this Paillier private key is valid, raising a `ValueError` if not. Validations performed include
        verifying whether its public modulus meets this module's minimum key-size requirement (i.e., 2047-bits).

        :raises ValueError: If this Paillier private key is invalid.
        """
        return self._validate(self.p, self.q, self.n)

    def __str__(self) -> str:
        """
        Returns a base64-based encoding of this Paillier private key, which uses the following format:
            `{private_lambda_base64}:{public_modulus_base64}`
        """
        return self._encode_to_base64()

    def __repr__(self) -> str:
        """
        Returns a string representation of the Paillier private key (base64-encoded), in the format:
            `PaillierPrivateKey(λ, n)='{private_lambda_base64}:{public_modulus_base64}'`
        """
        return (
            f"PaillierPrivateKey(λ, n)='{self._encode_to_base64()}'"
        )

    # noinspection DuplicatedCode
    @classmethod
    def _decode_from_base64(cls, encoded_private_key: str) -> PaillierPrivateKey:
        parsed_fields: list[str] = encoded_private_key.split(':')
        if len(parsed_fields) != 2:
            raise ValueError(
                f"Invalid encoded Paillier private key format -- two base64-encoded fields expected"
                f" [fields_count={len(parsed_fields)}]"
            )

        private_prime_p_base64, private_prime_q_base64 = parsed_fields

        try:
            private_prime_p: int = number.bytes_to_long(
                base64.b64decode(private_prime_p_base64, validate=True)
            )
            private_prime_q: int = number.bytes_to_long(
                base64.b64decode(private_prime_q_base64, validate=True)
            )
        except binascii.Error as b64ex:
            raise ValueError(f"Invalid base64 encoding for Paillier private key -- exception: {b64ex}")
        else:
            return cls(private_prime_p, private_prime_q, validate=True)

    def private_lambda(self) -> int:
        return self.λ

    def private_lambda_inverse(self) -> int:
        return self.mu

    def public_modulus(self) -> int:
        return self.n

    def public_modulus_squared(self) -> int:
        return self.n2

    def export_private_key(
            self,
            passphrase: str | None,
            pbkdf2_iterations: int = OWASP_PBKDF2_SHA256_ITERATIONS,  # default: 600,000 per OWASP 2023 guidelines
            hmac_hash_algorithm: str = DEFAULT_HMAC_HASH_ALGORITHM,   # default: HMAC-SHA3-256
            salt_size_bytes: int = DEFAULT_PKCS8_HMAC_SALT_BYTES,     # default: 32 bytes (256 bits)
            aes_key_size_bytes: int = DEFAULT_PKCS8_AES_KEY_BYTES     # default: AES-128 (16 bytes)
    ) -> str:
        """
        Exports this Paillier private key as a PKCS#8 encrypted private key, using the provided passphrase for
        password-based key-wrap encryption using PBKDF2 for symmetric (AES) key derivation and AES-CBC for encryption
        of the encoded Paillier private key; or simply encodes the private key to a base64-based string encoding, if no
        passphrase is provided.

        :param passphrase: a passphrase to use in encrypting this private key, using PKCS#8 password-based key-wrap
               encryption; or None if the private key should only be encoded to a base64-based string encoding.
        :param pbkdf2_iterations: the number of iterations to use in the PBKDF2 key derivation function for symmetric
               key-wrap encryption (default: `OWASP_PBKDF2_SHA256_ITERATIONS` per OWASP 2023 guidelines).
        :param hmac_hash_algorithm: the cryptographic hash algorithm to be used with HMAC in the PBKDF2 key derivation
               function for symmetric key-wrap encryption (default: `DEFAULT_HMAC_HASH_ALGORITHM`).
        :param salt_size_bytes: the size of the random salt value to be used in the PBKDF2 key derivation function for
               symmetric key-wrap encryption (default: `DEFAULT_PKCS8_HMAC_SALT_BYTES`).
        :param aes_key_size_bytes: the size of the AES key to be used in the AES-CBC encryption of the encoded private
               key (default: `DEFAULT_PKCS8_AES_KEY_BYTES`).
        :return: the PKCS#8 encrypted private key as a string-encoded representation, which includes PBKDF2 parameters
                 and the HMAC salt necessary for decrypting the private key.
        :raises ValueError: if the passphrase is too short for PKCS#8 encryption (i.e., < `MIN_PKCS8_PASSPHRASE_LENGTH`
                characters), if provided.
        """
        encoded_private_key: bytes = self._encode_to_base64().encode('utf-8')

        if passphrase is not None:
            if len(passphrase) < MIN_PKCS8_PASSPHRASE_LENGTH:
                raise ValueError(
                    f"Unsupported passphrase length [{len(passphrase)}] for PKCS#8-based Paillier private key"
                    f" encryption -- minimum length (chars.): {MIN_PKCS8_PASSPHRASE_LENGTH}"
                )

            # Encrypt encoded private key using PKCS#8 password-based encryption, using PBKDF2 for key-wrap (symmetric)
            # key derivation and AES-CBC for encryption (e.g., PBKDF2 w/ HMAC-SHA3-256 & AES-128-CBC by default).
            encrypted_private_key_asn1_der, pbkdf2_params = self._pkcs8_encrypt_encoded_private_key(
                encoded_private_key,
                passphrase.encode('utf-8'),
                pbkdf2_iterations=pbkdf2_iterations,
                hmac_hash_algorithm=hmac_hash_algorithm,
                salt_size_bytes=salt_size_bytes,
                aes_key_size_bytes=aes_key_size_bytes
            )

            return self._encode_pkcs8_encrypted_private_key(encrypted_private_key_asn1_der, pbkdf2_params)
        else:  # no passphrase provided
            # Encode private key to ASN.1 DER format (using a PKCS#8 container), but don't encrypt the private key.
            encoded_private_key_asn1_der: bytes = self._pkcs8_encode_private_key(encoded_private_key)

            # Return the ASN.1 DER encoded private key as a base64-encoded string.
            return base64.b64encode(encoded_private_key_asn1_der).decode('utf-8')

    @staticmethod
    def _pkcs8_encode_private_key(
        encoded_private_key: bytes
    ) -> bytes:
        """
        Encodes a Paillier private key in a PKCS#8 container using ASN.1 DER format, but without any encryption.

        :param encoded_private_key: a string-encoding of the Paillier private key to be encrypted, which uses
               base64-encoded fields for the private key's prime factors `p` and `q` (separated by a colon ':'
               delimiter).
        :return: the PKCS#8 encoded private key in the binary ASN.1 DER format.
        """

        # Note: The standard RSA OID is used here as a placeholder for Paillier private keys, as there is no specific
        #   standardized ASN.1 OID for Paillier private keys, as of the time of writing (2024), and Paillier private
        #   keys are actually fully compatible with conventional RSA private keys, when using the two private prime
        #   factors `p` & `q` of the public modulus `n` as the private key's components (i.e., as opposed to the
        #   Paillier-specific private lambda-based representation).
        rsa_oid: str = RSA_OID

        return PKCS8.wrap(
            private_key=encoded_private_key,
            key_oid=rsa_oid,
            passphrase=None,
            protection=None
        )

    @staticmethod
    def _pkcs8_encrypt_encoded_private_key(
            encoded_private_key: bytes,
            passphrase: bytes,
            pbkdf2_iterations: int = OWASP_PBKDF2_SHA256_ITERATIONS,
            hmac_hash_algorithm: str = DEFAULT_HMAC_HASH_ALGORITHM,  # default: HMAC-SHA3-256
            salt_size_bytes: int = DEFAULT_PKCS8_HMAC_SALT_BYTES,    # default: 32 bytes (256 bits)
            aes_key_size_bytes: int = DEFAULT_PKCS8_AES_KEY_BYTES    # default: AES-128 key size (16 bytes)
    ) -> tuple[bytes, dict[str, int]]:
        """
        Encrypts the base64-encoded Paillier private key using PKCS#8 password-based key-wrap encryption, using PBKDF2
        for password-based symmetric (AES) key derivation and AES-CBC for encryption of the provided encoded private
        key, returning a string encoding of the encrypted private key (including PBKDF2 parameters and a salt value
        required for decryption).

        :param encoded_private_key: a string-encoding of the Paillier private key to be encrypted, which uses
               base64-encoded fields for the private key's prime factors `p` and `q` (separated by a colon ':'
               delimiter).
        :param passphrase: a passphrase to use in encrypting this private key, using PKCS#8 password-based key-wrap
               encryption; or None if the private key should only be encoded to a base64-based string encoding.
        :param pbkdf2_iterations: the number of iterations to use in the PBKDF2 key derivation function for symmetric
               key-wrap encryption (default: `OWASP_PBKDF2_SHA256_ITERATIONS` per OWASP 2023 guidelines).
        :param hmac_hash_algorithm: the cryptographic hash algorithm to be used with HMAC in the PBKDF2 key derivation
               function for symmetric key-wrap encryption (default: `DEFAULT_HMAC_HASH_ALGORITHM`).
        :param salt_size_bytes: the size of the random salt value to be used in the PBKDF2 key derivation function for
               symmetric key-wrap encryption (default: `DEFAULT_PKCS8_HMAC_SALT_BYTES`).
        :param aes_key_size_bytes: the size of the AES key to be used in the AES-CBC encryption of the encoded private
               key (default: `DEFAULT_PKCS8_AES_KEY_BYTES`).
        :return: the PKCS#8 encrypted private key in the binary ASN.1 DER format, along with a dictionary containing the
                 PBKDF2 parameters used for symmetric key derivation (i.e., the number of iterations & size of the
                 random salt used).
        """
        supported_PBKDF2_profiles: set[str] = PaillierPrivateKey._supported_pbkdf2_profiles()

        aes_key_size_bits: int = aes_key_size_bytes * 8
        pbkdf2_profile: str = f"PBKDF2With{hmac_hash_algorithm}AndAES{aes_key_size_bits}-CBC"

        if pbkdf2_profile not in supported_PBKDF2_profiles:
            raise ValueError(
                f"Unsupported PKCS#8 KDF profile: '{pbkdf2_profile}' for password-based key-wrap encryption of Paillier"
                f" private keys -- supported profiles: {supported_PBKDF2_profiles}"
            )

        # PBKDF2 parameters used for PKCS#8-based key-wrap encryption.
        pbkdf2_params: dict[str, int] = {
            'iteration_count': pbkdf2_iterations,  # KDF iterations for PKCS#8 key-wrap encryption
            'salt_size': salt_size_bytes           # size of random salt for use by KDF
        }

        # Note: The standard RSA OID is used here as a placeholder for Paillier private keys, as there is no specific
        #   standardized ASN.1 OID for Paillier private keys, as of the time of writing (2024), and Paillier private
        #   keys are actually fully compatible with conventional RSA private keys, when using the two private prime
        #   factors `p` & `q` of the public modulus `n` as the private key's components (i.e., as opposed to the
        #   Paillier-specific private lambda-based representation).
        rsa_oid: str = RSA_OID

        return PKCS8.wrap(
            private_key=encoded_private_key,
            key_oid=rsa_oid,
            passphrase=passphrase,
            protection=pbkdf2_profile,
            prot_params=pbkdf2_params
        ), pbkdf2_params

    @staticmethod
    def _encode_pkcs8_encrypted_private_key(
            encrypted_private_key_asn1_der: bytes,
            pbkdf2_params: dict[str, int]
    ) -> str:
        """
        Encodes a PKCS#8 encrypted private key, including the PBKDF2 parameters and HMAC salt value required for
        successful decryption, in a string format that can be stored or transmitted securely.

        Uses the string encoding format, as defined in the Password Hashing Competition's string format spec:
        https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md

        :param encrypted_private_key_asn1_der: an encrypted private key wrapped in a PKCS#8 container, and encoded in
               the (ASN.1) DER binary format, which includes the PBKDF2 (HMAC) salt value used during (symmetric)
               key-wrap encryption key derivation.
        :param pbkdf2_params: the PBKDF2 parameters used for symmetric key derivation, including the number of
               iterations and the size of the random salt value.
        :return: a string-encoded representation of the PKCS#8 encrypted private key, including PBKDF2 parameters
                 necessary for successful decryption.
        """
        VERSION: int = 1
        encrypted_private_key_base64: str = base64.b64encode(encrypted_private_key_asn1_der).decode('utf-8')

        pbkdf2_iterations: int = pbkdf2_params['iteration_count']
        salt_size: int = pbkdf2_params['salt_size']

        return (
            f"$pbkdf2$v={VERSION}$iterations={pbkdf2_iterations},salt_size={salt_size}${encrypted_private_key_base64}"
        )

    @staticmethod
    def _supported_pbkdf2_profiles() -> set[str]:
        """
        Returns the set of supported PKCS#8 password-based key-wrap encryption profiles, using PBKDF2 for symmetric
        (AES) key derivation and AES-CBC for encryption of the encoded Paillier private key.

        Supported profiles currently include PBKDF2 using HMAC with SHA-2 family (SHA-224, SHA-256, SHA-384, SHA-512)
        and SHA-3 family (SHA3-224, SHA3-256, SHA3-384, SHA3-512) cryptographic hashes, and AES-CBC encryption using key
        sizes of 128, 192 or 256 bits. Supported AES key sizes have been chosen based on the hash algorithm's output
        (e.g., AES-128 for SHA-256, AES-192 for SHA-384, and AES-256 for SHA-512).

        :return: the set of supported PKCS#8 password-based key-wrap encryption profiles.
        """
        return {
            PKCS8_KDF_PBKDF2_SHA224_AES128_CBC,
            PKCS8_KDF_PBKDF2_SHA256_AES128_CBC,
            PKCS8_KDF_PBKDF2_SHA384_AES192_CBC,
            PKCS8_KDF_PBKDF2_SHA512_AES256_CBC,
            PKCS8_KDF_PBKDF2_SHA3_224_AES128_CBC,
            PKCS8_KDF_PBKDF2_SHA3_256_AES128_CBC,
            PKCS8_KDF_PBKDF2_SHA3_384_AES192_CBC,
            PKCS8_KDF_PBKDF2_SHA3_512_AES256_CBC
        }

    @classmethod
    def import_private_key(
            cls,
            encoded_private_key: str,
            passphrase: str | None = None
    ) -> PaillierPrivateKey:
        """
        Imports a Paillier private key from a PKCS#8 encrypted private key, using the provided passphrase for
        password-based key-wrap decryption of the private key.

        :param encoded_private_key: Paillier private key to be imported, provided in a string encoding, which may be
               PKCS#8 encrypted.
        :param passphrase: passphrase to use for decrypting a PKCS#8 encrypted private key; or None if the private
               key is not encrypted.
        :return: a successfully decoded and/or decrypted Paillier private key.
        :raises ValueError: if the encoded private key is invalidly encoded, or is encrypted and could not be decrypted.
        """
        if passphrase is not None:
            encrypted_private_key_asn1_der, pbkdf2_params = cls._decode_pkcs8_encrypted_private_key(
                encoded_private_key
            )

            # Decrypt PKCS#8 encrypted Paillier private key.
            private_key_base64_bytes: bytes = cls._pkcs8_decrypt_private_key(
                encrypted_private_key_asn1_der,
                passphrase
            )

            return cls._decode_from_base64(private_key_base64_bytes.decode('utf-8'))
        else:  # no passphrase provided
            # Decode the base64-encoded ASN.1 DER byte string of the Paillier private key, to obtain the DER bytes.
            encoded_private_key_bytes: bytes = base64.b64decode(encoded_private_key)

            # Decode an ASN.1 DER-encoded Paillier private key, which was not encrypted.
            decoded_private_key: bytes = cls._decode_pkcs8_unencrypted_private_key(encoded_private_key_bytes)

            return cls._decode_from_base64(decoded_private_key.decode('utf-8'))

    @staticmethod
    def _pkcs8_decrypt_private_key(encrypted_private_key_asn1_der: bytes, passphrase: str) -> bytes:
        """
        Decrypts a PKCS#8 encrypted Paillier private key, using the provided passphrase for password-based (PBKDF2)
        key-wrap decryption of the private key.
        """
        oid, private_key, assoc_params = PKCS8.unwrap(encrypted_private_key_asn1_der, passphrase)

        return private_key

    @staticmethod
    def _decode_pkcs8_unencrypted_private_key(encoded_private_key_asn1_der: bytes) -> bytes:
        oid, private_key, assoc_params = PKCS8.unwrap(encoded_private_key_asn1_der, passphrase=None)

        return private_key

    @staticmethod
    def _decode_pkcs8_encrypted_private_key(encrypted_private_key: str) -> tuple[bytes, dict[str, int]]:
        """
        Decodes a PKCS#8 encrypted Paillier private key, including the PBKDF2 parameters used for symmetric key
        derivation, from a string-encoded representation.

        The particular string encoding used is based on the Argon2-related string encoding format (i.e., that used in
        the Password Hashing Competition), which includes the PBKDF2 parameters necessary for re-derivation of the
        symmetric key required for decryption. The encrypted private key field is a base64-encoded ASN.1 DER byte
        string.

        The encoded private key format is expected to be in the following format:
            `$pbkdf2$v={VERSION}$iterations={ITERATIONS}${ENCRYPTED_PRIVATE_KEY_ASN1_DER_BASE64}`

        :see: `Password Hashing Competition: String Format <https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md>`_

        :param encrypted_private_key: a string-encoded representation of the PKCS#8 encrypted private key, which
               includes PBKDF2 parameters necessary for re-derivation of the symmetric key required for decryption.
        :return: a tuple containing the encrypted private key (as an ASN.1 DER-encoded byte string) and the PBKDF2
                 parameters used for re-derivation of the symmetric key for decryption.
        :raises ValueError: if the string-encoded PKCS#8 encrypted private key is invalidly formatted.
        """
        KDF_ALGO_POS: int = 0
        ENCODING_VERSION_POS: int = 1
        KDF_PARAMS_POS: int = 2
        ENCRYPTED_KEY_POS: int = 3

        EXPECTED_FIELDS_COUNT: int = 4
        SUPPORTED_KDF_ALGOS: set[str] = {'pbkdf2'}
        SUPPORTED_ENCODING_VERSIONS: set[int] = {1}

        fields: list[str] = encrypted_private_key.lstrip('$').split('$')
        if len(fields) != EXPECTED_FIELDS_COUNT:
            raise ValueError(
                f"Invalid Paillier encrypted private key format -- expected 4 fields, but found {len(fields)}."
            )

        encoding_version_param: list[str] = fields[ENCODING_VERSION_POS].split('=')
        if len(encoding_version_param) != 2 or encoding_version_param[0] != 'v':
            raise ValueError(
                f"Invalid Paillier encrypted private key format -- expected 'v' version field, but found:"
                f" {fields[ENCODING_VERSION_POS]}"
            )
        elif int(encoding_version_param[1]) not in SUPPORTED_ENCODING_VERSIONS:
            raise ValueError(
                f"Unsupported Paillier encrypted private key encoding version:"
                f" '{encoding_version_param[ENCODING_VERSION_POS]}' -- supported encoding versions: {SUPPORTED_ENCODING_VERSIONS}"
            )

        # Ensure the key-derivation function (KDF) is supported (i.e., that it is PBKDF2).
        if fields[KDF_ALGO_POS] not in SUPPORTED_KDF_ALGOS:
            raise ValueError(
                f"Unsupported PKCS#8 password-based key-wrap encryption format: '{fields[KDF_ALGO_POS]}' for Paillier"
                f" private key -- expected KDF in: {SUPPORTED_KDF_ALGOS}"
            )

        pbkdf2_params: dict[str, int] = {}
        try:
            # Parse the PBKDF2 parameters into key-value pairs:
            params: list[str] = fields[KDF_PARAMS_POS].split(',')
            for param in params:
                key, value = param.split('=')
                pbkdf2_params[key] = int(value)
        except KeyError as kex:
            raise ValueError(
                f"Invalid Paillier encrypted private key format -- invalidly formatted KDF parameter(s)"
                f" -- exception: {kex}"
            ) from kex
        except ValueError as vex:
            raise ValueError(
                f"Invalid Paillier encrypted private key format -- invalidly formatted KDF parameter(s) or parameter"
                f" value(s) -- exception: {vex}"
            ) from vex

        # Extract the base64-encoded ASN.1 DER byte string of the encrypted private key.
        encrypted_private_key_der: bytes = base64.b64decode(fields[ENCRYPTED_KEY_POS])

        return encrypted_private_key_der, pbkdf2_params

    def _encode_to_base64(self) -> str:
        """
        Returns a base64-based encoding of this Paillier private key, which uses the following format:
            `{private_prime_p_base64}:{private_prime_q_base64}`
        """
        private_prime_p_base64: str = base64.b64encode(
            number.long_to_bytes(self.p)
        ).decode('utf-8')

        private_prime_q_base64: str = base64.b64encode(
            number.long_to_bytes(self.q)
        ).decode('utf-8')

        return f"{private_prime_p_base64}:{private_prime_q_base64}"

    def decrypt(self, ciphertext: EncryptedUnsignedInteger) -> int:
        """
        Decrypts an encrypted non-negative integer using the Paillier private key. Decryption of ciphertext `c` is
        performed as:
            Dec(sk=lam, c): `m = L(c^λ mod n^2) * μ mod n`, where `L(u) = (u - 1) / n` and `μ ≡ λ^-1 mod n`.
        :param ciphertext: The encrypted non-negative integer value to be decrypted, which must be in the range
               `[1, n^2)` to be a valid Paillier ciphertext.
        :return: The decrypted non-negative integer value.
        :raises ValueError: If the ciphertext is out of range for decryption (i.e., if it lies outside of: `[1, n^2)` ).
        """
        # Ensure the ciphertext `c` is in the range `[1, n^2)` (i.e., `c` ∈ `Z_{n^2}*`), as required for decryption.
        if ciphertext.encrypted < 1 or ciphertext.encrypted >= self.n2:
            raise ValueError(
                "Ciphertext is out of range for decryption -- valid Paillier ciphertexts lie in the range: [1, n^2),"
                " where n is the public modulus."
            )

        # Dec(sk=lam, c): `m = L(c^λ mod n^2) * μ mod n`, where `L(u) = (u - 1) / n` and `μ ≡ λ^-1 mod n`
        return self._L(
            pow(ciphertext.encrypted, self.λ, self.n2),
            self.n
        ) * self.mu % self.n

    # noinspection PyPep8Naming
    @staticmethod
    def _L(u, n) -> int:
        """
        Computes the formula: L(u) := (u - 1) / n
        This formula produces an integer result for all u ∈ S_n, where S_n := {u < n^2 | u ≡ 1 mod n}.
        :raises AssertionError: If the input `u` is not in the range [1, n^2) or is not congruent to 1 modulo `n`.
        """
        # Ensure u ∈ Z_{n^2}^* (i.e., u is an element of the multiplicative group of integers modulo n^2).
        assert 0 < u < n ** 2, "u must be in the range [1, n^2)."
        # Ensure that L(u, n) is well-defined (i.e., u ≡ 1 mod n).
        assert u % n == 1, "u must be congruent to 1 modulo n."
        
        return safe_divide(u - 1, n)


# TODO: Replace use of Python's built-in `pow` with a constant-time modular exponentiation implementation
#   (e.g., the gmpy2 library's `gmpy2.powmod_sec(x, y, m)` function), to mitigate the risk of timing attacks.
@dataclass
class PaillierPublicKey:
    n: int   # public modulus: `n = p * q`, for private p, q prime
    g: int   # public generator `g ∈ B` of the set of n-th residues modulo n^2 (i.e., `g` generates CR[n])
    n2: int  # cached square `n^2` of the public modulus `n`

    def __init__(self, public_modulus: int, public_generator: int, validate: bool = False):
        if validate:
            self._validate(public_modulus, public_generator)

        self.n = public_modulus
        self.g = public_generator
        self.n2 = public_modulus ** 2

    @classmethod
    def import_public_key(cls, encoded_public_key: str) -> PaillierPublicKey:
        return cls._decode_from_base64(encoded_public_key)

    # noinspection DuplicatedCode
    @classmethod
    def _decode_from_base64(cls, encoded_public_key: str) -> PaillierPublicKey:
        parsed_fields: list[str] = encoded_public_key.split(':')
        if len(parsed_fields) != 2:
            raise ValueError(
                f"Invalid encoded Paillier public key format -- two base64-encoded fields expected"
                f" [fields_count={len(parsed_fields)}]"
            )

        public_modulus_base64, public_generator_base64 = parsed_fields

        try:
            public_modulus: int = number.bytes_to_long(
                base64.b64decode(public_modulus_base64, validate=True)
            )
            public_generator: int = number.bytes_to_long(
                base64.b64decode(public_generator_base64, validate=True)
            )
        except binascii.Error as b64ex:
            raise ValueError(f"Invalid base64 encoding for Paillier public key -- exception: {b64ex}")
        else:
            return cls(public_modulus, public_generator, validate=True)

    def validate_public_key(self) -> None:
        """
        Determines if this Paillier public key is valid, raising a `ValueError` if not. Validations performed include
        verifying whether its public modulus meets this module's minimum key-size requirement (i.e., 2047-bits), and
        verifying whether its public generator is valid (i.e., whether it's a valid generator of the group of n-th
        residues modulo n^2) and is a value supported by this module's Paillier implementation.

        Note: This implementation uses a specific generator `g` (i.e., `g = n + 1`, where `n` is the public modulus) as
        an optimization for Paillier encryption and decryption, as defined as an option in the original Paillier
        cryptosystem.

        :raises ValueError: If this Paillier public key is invalid.
        """
        self._validate(self.n, self.g)

    @staticmethod
    def _validate(public_modulus: int, public_generator: int) -> None:
        # Verify the Paillier public key's modulus is at least 2047 bits (i.e., MIN_KEY_SIZE - 1).
        # Note: The modulus `n : = p*q`, where `p` and `q` are prime, can be between 2047 & 2048 bits, due to the
        #   1024-bit primes `p` & `q` allowed values lying inside the range: [2^(1023) + 1, 2^(1024) - 1]
        if public_modulus.bit_length() < (MIN_KEY_SIZE - 1):
            raise ValueError(
                f"Invalid Paillier public key -- public modulus must be at least [{MIN_KEY_SIZE - 1}] bits."
            )

        # Require generator `g` to equal `n + 1`, as this impl. uses this specific generator as an optimization.
        if public_generator != public_modulus + 1:
            raise ValueError(
                "Unsupported Paillier public key -- the public generator 'g' must be equal to 'n + 1', where 'n' is the"
                " public modulus."
            )

    def __str__(self) -> str:
        """
        Returns a base64-based encoding of this Paillier public key, which uses the following format:
            `{public_modulus_base64}:{public_generator_base64}`
        """
        return self._encode_to_base64()

    def __repr__(self) -> str:
        """
        Returns a string representation of the Paillier public key (base64-encoded), in the format:
            `PaillierPublicKey(n, g)='{public_modulus_base64}:{public_generator_base64}'`
        """
        return (
            f"PaillierPublicKey(n, g)='{self._encode_to_base64()}'"
        )

    def public_modulus(self) -> int:
        return self.n

    def public_generator(self) -> int:
        return self.g

    def public_modulus_squared(self) -> int:
        return self.n2

    def export_public_key(self) -> str:
        return self._encode_to_base64()

    def _encode_to_base64(self) -> str:
        """
        Returns a base64-based encoding of this Paillier public key, which uses the following format:
            `{public_modulus_base64}:{public_generator_base64}`
        """
        public_modulus_base64: str = base64.b64encode(number.long_to_bytes(self.n)).decode('utf-8')
        public_generator_base64: str = base64.b64encode(number.long_to_bytes(self.g)).decode('utf-8')

        return f"{public_modulus_base64}:{public_generator_base64}"

    def encrypt(self, message: int) -> EncryptedUnsignedInteger:
        """
        Encrypts a non-negative integer message using the Paillier public key, using a randomly generated blinding
        factor. Encryption of message `m` is performed as:
            `Enc(pk=n, m): c = g^m * r^n mod n^2`,
        where the base `r`, of blinding factor `r^n`, is a random integer in `Z_{n}^* \ {1, n-1}`, the multiplicative
        group of integers modulo `n` (so `r` must be co-prime with `n`, or equivalently `gcd(r, n) == 1`), but excluding
        `1` and `n-1` (i.e., to avoid degenerate ciphertexts otherwise produced by these values of `r`).

        - Note: If the blinding factor 1 were permitted, this results in a degenerate ciphertext:
            `c = g^m * 1^n mod n^2` == `g^m mod n^2`,
          which features no randomization at all, and would immediately leak the plaintext message `m == 0` as `c == 1`.
        - Note: If the blinding factor `n-1` were permitted, this also results in a degenerate ciphertext:
            `c = g^m * (n-1)^n mod n^2` == `g^m * (-1)^n mod n^2` == `g^m mod n^2` (i.e., since `n` is even),
          which causes ciphertexts to occupy a distinguishable, tiny interval; leak one extra bit about `r`, and enable
          easy testing for `m == 0`.
        :param message: The non-negative integer message to be encrypted, which must lie in the range `[0, n)` to be a
               valid Paillier message.
        :return: The encrypted non-negative integer message, as a Paillier ciphertext, an integer `c` ∈ [2, n^2).
        :raises ValueError: If the message is out of range for encryption (i.e., if it lies outside of: `[0, n)` ).
        """
        # Generate a random blinding factor (base) `r` in the range [2, n-1), which is also co-prime with `n`
        # (i.e., `gcd(r, n) == 1`), so that `r` is in the multiplicative group of integers modulo `n`
        # (i.e., r ∈ `Z_{n}^*`).
        blinding_factor_base: int = self.generate_random_blinding_factor_base()

        return self.encrypt_with_blinding_factor(message, blinding_factor_base)

    def encrypt_with_blinding_factor(self, message: int, blinding_factor_base: int) -> EncryptedUnsignedInteger:
        """
        Encrypts a non-negative integer message using the Paillier public key, with a specified random blinding factor
        base `r` used in the encryption. Encryption of message `m` is performed as:
            Enc(pk=n, m): `c = g^m * r^n mod n^2`, where the base `r`, of the blinding factor `r^n`, is a random integer
        in `Z_{n}^* \ {1, n-1}`, the multiplicative group of integers modulo `n` (so `r` must be co-prime with `n`, or
        equivalently `gcd(r, n) == 1`), but excluding `1` and `n-1` (i.e., to avoid degenerate ciphertexts otherwise
        produced by these values of `r`).

        - Note: If the blinding factor 1 were permitted, this results in a degenerate ciphertext:
            `c = g^m * 1^n mod n^2` == `g^m mod n^2`,
          which features no randomization at all, and would immediately leak the plaintext message `m == 0` as `c == 1`.
        - Note: If the blinding factor `n-1` were permitted, this also results in a degenerate ciphertext:
            `c = g^m * (n-1)^n mod n^2` == `g^m * (-1)^n mod n^2` == `g^m mod n^2` (i.e., since `n` is even),
          which causes ciphertexts to occupy a distinguishable, tiny interval; leak one extra bit about `r`, and enable
          easy testing for `m == 0`.
        :param message: The non-negative integer message to be encrypted, which must lie in the range `[0, n)` to be a
               valid Paillier message.
        :param blinding_factor_base: The random base `r` of the blinding factor `r^n`, used in the encryption.
        :return: The encrypted non-negative integer message, as a Paillier ciphertext, an integer `c` ∈ [2, n^2).
        :raises ValueError: If the message is out of range for encryption (i.e., if it lies outside of: `[0, n)` ), or
                if the blinding factor base `r` is out of range (i.e., if it lies outside of: `[2, n-1)` ) or is not
                co-prime with the public modulus `n`.
        """
        # Ensure the message `m` is a non-negative integer in the range [0, n) (i.e., `m` ∈ `Z_{n}`, the (additive)
        # group of integers modulo `n`).
        if message < 0 or message >= self.n:
            raise ValueError("Message is out of range for encryption -- must be an integer in the range: [0, n - 1].")

        # Ensure the blinding factor base `r` is a (random) integer in the range `[2, n-1)`, which is also co-prime
        # with `n` (i.e., `gcd(r, n) == 1`), so that `r` is in the multiplicative group of integers modulo `n`
        # (i.e., r ∈ `Z_{n}^*`).
        self._validate_blinding_factor_base(blinding_factor_base)

        return EncryptedUnsignedInteger(
            self._encrypt_nonnegative_int(message, blinding_factor_base),
            self
        )

    def _encrypt_nonnegative_int(self, message: int, blinding_factor_base: int) -> int:
        """
        Encrypts a non-negative integer message using the Paillier public key, with a specified random blinding factor
        base `r` used in the encryption. Encryption of message `m` is performed as:
            Enc(pk=n, m): `c = g^m * r^n mod n^2`, where the base `r`, of the blinding factor `r^n`, is a random integer
        in `Z_{n}^* \ {1, n-1}` (i.e., r ∈ [2, n-1) ) and is co-prime with `n` (i.e., `gcd(r, n) == 1`).
        :param message: The non-negative integer message to be encrypted, which must lie in the range `[0, n)` to be a
               valid Paillier message.
        :param blinding_factor_base: The random base `r` of the blinding factor `r^n`, used in the encryption.
        :return: The encrypted non-negative integer message, as a Paillier ciphertext, an integer `c` ∈ [2, n^2).
        :raises AssertionError: If the message is out of range for encryption (i.e., if it lies outside of: `[0, n)` ).
        :raises AssertionError: If the blinding factor base `r` is out of range (i.e., if it lies outside of:
                `[2, n-1)` ).
        """
        # Ensure the message `m` is a non-negative integer in the range [0, n) (i.e., `m` ∈ `Z_{n}`, the (additive)
        # group of integers modulo `n`).
        assert 0 <= message < self.n, "Message must be a non-negative integer in the range [0, n)."
        # Ensure the blinding factor base `r` is a (random) integer in the range [2, n-1) (i.e., r ∈ `Z_{n}^*`).
        assert 1 < blinding_factor_base < self.n - 1, "Blinding factor base 'r' must be in the range [2, n-1)."

        if self.g == self.n + 1:
            # Use optimization: `g^m ≡ (1 + n*m) mod n^2`, when `g == n + 1`.
            return (
                (1 + self.n * message) * pow(blinding_factor_base, self.n, self.n2)
            ) % self.n2
        else:
            return (
                pow(self.g, message, self.n2) * pow(blinding_factor_base, self.n, self.n2)
            ) % self.n2

    def encrypt_and_return_blinding_factor(self, message: int) -> (EncryptedUnsignedInteger, int):
        """
        Encrypts a non-negative integer message using the Paillier public key, returning the encrypted message and the
        random blinding factor used in the encryption. Encryption of message `m` is performed as:
            Enc(pk=n, m): `c = g^m * r^n mod n^2`, where the base `r`, of the blinding factor `r^n`, is a random integer
        in `Z_{n}^* \ {1, n-1}` (i.e., r ∈ [2, n-1) ) and is co-prime with `n` (i.e., `gcd(r, n) == 1`).

        The values `1` and `n-1` are excluded here when choosing the blinding factor base `r` (i.e., to avoid degenerate
        ciphertexts otherwise produced by these values of `r`).

        - Note: If the blinding factor 1 were permitted, this results in a degenerate ciphertext:
            `c = g^m * 1^n mod n^2` == `g^m mod n^2`,
          which features no randomization at all, and would immediately leak the plaintext message `m == 0` as `c == 1`.
        - Note: If the blinding factor `n-1` were permitted, this also results in a degenerate ciphertext:
            `c = g^m * (n-1)^n mod n^2` == `g^m * (-1)^n mod n^2` == `g^m mod n^2` (i.e., since `n` is even),
          which causes ciphertexts to occupy a distinguishable, tiny interval; leak one extra bit about `r`, and enable
          easy testing for `m == 0`.
        :param message: The non-negative integer message to be encrypted, which must lie in the range `[0, n)` to be a
               valid Paillier message.
        :return: A tuple containing the encrypted non-negative integer message, as a Paillier ciphertext, an integer
                 `c` ∈ [2, n^2), and the random blinding factor `r` used in the encryption.
        :raises ValueError: If the message is out of range for encryption (i.e., if it lies outside of: `[0, n)` ).
        :raises AssertionError: If the generated random blinding factor base `r` is out of range (i.e., if it lies
                outside of: `[2, n-1)` ).
        """
        # Generate a random blinding factor (base) `r` in the range [2, n-1), which is also co-prime with `n`
        # (i.e., `gcd(r, n) == 1`), so that `r` is in the multiplicative group of integers modulo `n`
        # (i.e., r ∈ `Z_{n}^*`).
        blinding_factor_base: int = self.generate_random_blinding_factor_base()

        return self.encrypt_with_blinding_factor(message, blinding_factor_base), blinding_factor_base

    def generate_random_blinding_factor_base(self) -> int:
        """
        Generates a random blinding factor (base) `r ∈ Z_{n}^* \ {1, n-1}`, the multiplicative group of integers modulo
        `n`, but excluding `1` and `n-1` (i.e., to avoid degenerate ciphertexts otherwise produced by these values).
        - Note: This function randomly selects `r ∈ [2, n-1)`, followed by a check to ensure `r` & `n` are co-prime
        (i.e., `gcd(r, n) = 1`), as required for Paillier decryption to actually return a valid plaintext.

        :return: A random blinding factor base `r` in the range `[2, n-1)` with `gcd(r, n) = 1` (i.e., such that `r` is
                 co-prime with `n`).
        """
        # Select a random blinding factor base until a valid one is found (i.e., one that is co-prime with `n`).
        while True:
            # Generate a random blinding factor (base) `r` in the range [2, n-1).
            blinding_factor_base: int = utils.random_integer_in_range(2, self.n - 1)
            # Ensure `gcd(r, n) = 1` (i.e., `r` is co-prime with `n`), as required for Paillier decryption to work.
            if number_theory.is_coprime(blinding_factor_base, self.n):
                return blinding_factor_base

    def _validate_blinding_factor_base(self, blinding_factor_base: int) -> None:
        """
        Validates the provided blinding factor base `r`, ensuring it is in the range `[2, n-1)` and is co-prime with
        the public modulus `n` (i.e., `gcd(r, n) = 1`), as required for Paillier decryption to work.

        :param blinding_factor_base: The blinding factor base `r` to validate.
        :raises ValueError: If the blinding factor base is out of range (i.e., does not lie in: `[2, n-1)` ), or is not
                co-prime with the public modulus `n` (i.e., `gcd(r, n) ≠ 1`).
        """
        if blinding_factor_base < 2 or blinding_factor_base >= self.n - 1:
            raise ValueError(
                f"Paillier blinding factor (base) 'r' must be in the range: [2, n - 2]."
                f" [blinding_factor_base={blinding_factor_base}, public_modulus_n={self.n}]"
            )

        if not number_theory.is_coprime(blinding_factor_base, self.n):
            raise ValueError(
                f"Paillier blinding factor (base) 'r' must be co-prime with the public modulus 'n'"
                f" [blinding_factor_base={blinding_factor_base}, public_modulus_n={self.n}]"
            )


@dataclass
class PaillierKeyPair:
    public_key: PaillierPublicKey
    private_key: PaillierPrivateKey

    def __init__(self, public_key: PaillierPublicKey, private_key: PaillierPrivateKey, validate: bool = False):
        if validate:
            self._validate(public_key, private_key)

        self.public_key = public_key
        self.private_key = private_key

    @staticmethod
    def _validate(public_key: PaillierPublicKey, private_key: PaillierPrivateKey) -> None:
        if private_key.n != public_key.n:
            raise ValueError("Paillier public and private keys must have the same public modulus.")

        private_key.validate_private_key()

        public_key.validate_public_key()

        # Verify: `g^λ == 1 mod n`, where g is the public generator, n := p * q is the public modulus
        #   (for primes p and q), and λ := λ(n) = lcm(p-1, q-1) is the private key.
        if pow(public_key.g, private_key.λ, public_key.n) != 1:
            raise ValueError(
                "Invalid Paillier public/private key pair -- The public key's generator `g` raised to the private key"
                " `λ(n)` should be congruent to 1 modulo `n` (i.e., g^λ == 1 mod n)."
            )

        # Verify: `g^nλ == 1 mod n^2`, where g is the public generator, n := p * q is the public modulus
        #   (for primes p and q), and λ := λ(n) = lcm(p-1, q-1) is the private key.
        if pow(public_key.g, public_key.n * private_key.λ, public_key.n2) != 1:
            raise ValueError(
                "Invalid Paillier public/private key pair -- The public key's generator `g` raised to the product of"
                " the public key `n` and the private key `λ(n)` should be congruent to 1 modulo `n^2`"
                " (i.e., `g^nλ == 1 mod n^2`)."
            )

    @classmethod
    def generate(cls, key_size_bits: int = DEFAULT_KEY_SIZE) -> PaillierKeyPair:
        if key_size_bits < MIN_KEY_SIZE:
            raise ValueError(f"Paillier key-size must be at least [{MIN_KEY_SIZE}] bits.")

        prime_factor_size_bits: int = key_size_bits // 2

        # Generate two large "strong" primes: `p` and `q`, of roughly equal size (half the key size in bits), which also
        # aren't "too close together" (i.e., `|p - q| >= nroot(n, 4)`), and their product: `n = p * q`.
        p, q, n = cls._generate_primes(prime_factor_size_bits)

        # Choose `g = n + 1`, a known generator `g ∈ B` of the set of n-th residues modulo n^2, where `B` := the set of
        # elements of Z_{n^2}^* with order `n * 𝜶`, for 𝜶 ∈ [1, λ(n)].
        g = n + 1

        priv_key = PaillierPrivateKey(p, q)
        pub_key = PaillierPublicKey(n, g)

        return cls(pub_key, priv_key)

    @staticmethod
    def _generate_primes(size_bits: int) -> tuple[int, int, int]:
        """
        Generates two "strong" primes (i.e., a prime `p` such that `p - 1` and `p + 1` both have at least one large
        prime factor), using the specified bit-size for each prime. Using "strong" primes thereby provides protection
        against sophisticated factoring algorithms like Pollard's p-1 method.

        Additionally, this method ensures the absolute difference of the two primes are greater or equal to the 4th root
        of `n` (i.e., `|p - q| >= nroot(n, 4)`), which is a recommended security measure for Paillier key (and RSA key)
        generation. (This ensures the two primes are not "too close together", in order to thwart brute-force attacks
        seeking to factor the public modulus `n` via Fermat’s difference of squares method.)

        :param size_bits: The bit-size to use for each of the two "strong" primes to be generated. (Each prime will lie
               in the range: `[2^(size_bits-1) + 1, 2^size_bits - 1]`.)
        :return: A tuple of two "strong" prime numbers: `p` and `q`, generated using the specified bit-size, along with
                 their product, the public modulus `n = p * q` of size (2 * size_bits) bits.
        """
        while True:
            p: int = random_strong_prime(size_bits)
            q: int = random_strong_prime(size_bits)
            if p == q:
                continue

            n: int = p * q  # candidate public modulus: `n = p * q`

            abs_diff: int = abs(p - q)
            # Compute the (truncated) 4th root of the public modulus `n = p * q`.
            fourth_root_n: int = libnum.nroot(n, 4)

            # Ensure the two primes `p` and `q` are not "too close together" (i.e., `|p - q| >= nroot(n, 4)`).
            if abs_diff >= fourth_root_n:
                return p, q, n   # return "strong" primes `p` and `q`, and public modulus `n`

    def validate_key_pair(self) -> None:
        """
        Verifies whether a Paillier key-pair is valid, raising a `ValueError` if not. Validations of the public key's
        modulus and generator are performed, in addition to two sophisticated tests of the private key's validity,
        which involve modular congruence identities due to Carmichael's theorem.

        These validations are especially useful for verifying a Paillier key-pair's validity following deserialization.

        :raises ValueError: If this Paillier key-pair is invalid.
        """
        self._validate(self.public_key, self.private_key)

    def export_private_key(self, passphrase: str | None) -> str:
        return self.private_key.export_private_key(passphrase)

    def export_public_key(self) -> str:
        return self.public_key.export_public_key()


# TODO: Replace use of Python's built-in `pow` with a constant-time modular exponentiation implementation
#   (e.g., the gmpy2 library's `gmpy2.powmod_sec(x, y, m)` function), to mitigate the risk of timing attacks.
@dataclass
class EncryptedUnsignedInteger:
    """
    EncryptedUnsignedInteger represents an unsigned integer value encrypted using the Paillier cryptosystem.
    """
    encrypted: int                 # encrypted ciphertext (an integer `c` ∈ [1, n^2), where `n` is the public modulus)
    public_key: PaillierPublicKey  # public key used to produce this ciphertext (required for homomorphic operations)

    def __init__(self, encrypted: int, public_key: PaillierPublicKey):
        if encrypted < 1 or encrypted >= public_key.n2:
            raise ValueError(
                f"Invalid Paillier ciphertext -- valid ciphertexts 'c' are integers satisfying: 1 < c < n^2, where"
                f" n^2 is the square of the public key's modulus."
            )

        self.encrypted = encrypted
        self.public_key = public_key

    @classmethod
    def from_base64_encoding(cls, ciphertext_base64: str, public_key: PaillierPublicKey) -> EncryptedUnsignedInteger:
        try:
            ciphertext: int = number.bytes_to_long(
                base64.b64decode(ciphertext_base64, validate=True)
            )
        except binascii.Error as b64ex:
            raise ValueError(f"Invalid base64 encoding for Paillier ciphertext -- exception: {b64ex}")
        else:
            return cls(ciphertext, public_key)

    def __str__(self) -> str:
        """Returns a base64-based encoding of this Paillier ciphertext."""
        return self.encode_to_base64()

    def __repr__(self) -> str:
        return (
            f"EncryptedUnsignedInteger(ciphertext_base64='{self.encode_to_base64()}',"
            f" public_key='{self.public_key._encode_to_base64()}')"
        )

    def __add__(self, other: EncryptedUnsignedInteger | int) -> EncryptedUnsignedInteger:
        """
        Homomorphic addition of two Paillier encrypted integers, using the left-addition operator
        (i.e., `c3 := Enc(p1 + p2) = Enc(p1) * Enc(p2) mod n^2`, where `p1` and `p2` plaintext non-negative integers,
        and `c3` is a Paillier ciphertext).

        Alternatively, if passed a non-negative integer, it performs homomorphic addition of an encryption of the
        provided plaintext non-negative integer scalar with this ciphertext
        (i.e., `c2 := Enc(p1 + s) = Enc(p1) * Enc(s) mod n^2`, where `p1` is the original plaintext non-negative
        integer encrypted as this ciphertext, `s` is the provided plaintext non-negative integer scalar, and `c2` is the
        resulting Paillier ciphertext encrypting the plaintext sum: `p1 + s`).

        Usage: `EncryptedUnsignedInteger + EncryptedUnsignedInteger` or `EncryptedUnsignedInteger + message_integer`
        """
        return self.add(other)

    def __radd__(self, scalar: int) -> EncryptedUnsignedInteger:
        """
        Homomorphic addition of an encrypted integer with a plaintext non-negative integer scalar, using the
        right-addition operator (i.e., `c2 := Enc(s + p1) = Enc(s) * Enc(p1) mod n^2`, where `p1` is the original
        plaintext non-negative integer encrypted as this ciphertext, `s` is the provided plaintext non-negative integer
        scalar, and `c2` is the resulting Paillier ciphertext encrypting the plaintext sum: `s + p1`).

        Usage: `scalar_integer + EncryptedUnsignedInteger`
        """
        return self.add(scalar)

    def __mul__(self, scalar: int) -> EncryptedUnsignedInteger:
        """
        Homomorphic scalar multiplication of an encrypted integer by a plaintext "scalar" value, using the left-multiply
        operator.

        (i.e., `c2 := Enc(p1 * s) = Enc(p1)^s mod n^2`, where `p1` is a plaintext non-negative integer encrypted as this
        ciphertext, `s` is the provided plaintext non-negative integer "scalar" multiplier, and `c2` is the resulting
        Paillier ciphertext encrypting the plaintext product: `p1 * s`.)

        Usage: `EncryptedUnsignedInteger * scalar_integer`

        Note: This method is called when the Paillier ciphertext is on the left-hand side of the multiplication
        operator.
        """
        return self.multiply(scalar)

    def __rmul__(self, scalar: int) -> EncryptedUnsignedInteger:
        """
        Homomorphic scalar multiplication of an encrypted integer by a plaintext "scalar" value, using the
        right-multiply operator.

        (i.e., `c2 := Enc(s * p1) = Enc(p1)^s mod n^2`, where `p1` is a plaintext non-negative integer encrypted as this
        ciphertext, `s` is the provided plaintext non-negative integer "scalar" multiplier, and `c2` is the resulting
        Paillier ciphertext encrypting the plaintext product: `s * p1`.)

        Usage: `scalar_integer * EncryptedUnsignedInteger`

        Note: This method is called when the Paillier ciphertext is on the right-hand side of the multiplication
        operator.
        """
        return self.__mul__(scalar)

    def decrypt(self, private_key: PaillierPrivateKey) -> int:
        return private_key.decrypt(self)

    def encode_to_base64(self) -> str:
        return base64.b64encode(
            number.long_to_bytes(self.encrypted)
        ).decode('utf-8')

    def add(self, other: EncryptedUnsignedInteger | int) -> EncryptedUnsignedInteger:
        """
        Homomorphic addition of two Paillier encrypted non-negative integers
        (i.e., `c3 := Enc(p1 + p2) = Enc(p1) * Enc(p2) mod n^2`, where `p1` and `p2` plaintext non-negative integers,
        and `c3` is a Paillier ciphertext).

        Alternatively, if passed a non-negative integer scalar, it performs homomorphic addition of an encryption of the
        provided scalar with this ciphertext (i.e., `c2 := Enc(p1 + s) = Enc(p1) * Enc(s) mod n^2`, where `p1` is the
        original plaintext non-negative integer encrypted as this ciphertext, `s` is the provided plaintext non-negative
        integer scalar, and `c2'` is the resulting homomorphic sum, a Paillier ciphertext encrypting the plaintext sum:
        `p1 + s`).

        - Note: The special case of a scalar summand of 0 is a no-op for this method, returning the original ciphertext
        unchanged. For use in secure multi-party computation (MPC) protocols, it's recommended to use the
        `add_and_obfuscate(...)` method here instead of this `add(...)` method, if a scalar summand of 0 could be
        provided by the protocol and both the original ciphertext & sum ciphertext will be shared with a 3rd party, to
        avoid leaking the fact that the scalar added was 0.
          - However, if performing a sequence of homomorphic operations, it can be more efficient to simply re-blind
          the final ciphertext result at the end of the sequence, using the `obfuscate()` method, rather than using
          `add_and_obfuscate(...)` for each scalar addition or homomorphic addition operation (and/or
          `multiply_and_obfuscate(...)` for each homomorphic scalar multiplication operation).
        """
        if type(other) is int:
            return self._add_scalar(other)
        elif isinstance(other, EncryptedUnsignedInteger):
            return self._add_ciphertexts(other)
        else:
            raise ValueError("Homomorphic addition operands must be of type EncryptedUnsignedInteger or int.")

    def _add_ciphertexts(self, other: EncryptedUnsignedInteger) -> EncryptedUnsignedInteger:
        """
        Homomorphic addition of two Paillier non-negative encrypted integers, using the left-addition operator
        (i.e., `c3 := Enc(p1 + p2) = Enc(p1) * Enc(p2) mod n^2`, where `p1` and `p2` plaintext non-negative integers,
        and `c3` is a Paillier ciphertext).
        """
        if self.public_key != other.public_key:
            raise ValueError("Homomorphic addition operands must have the same Paillier public key.")

        return EncryptedUnsignedInteger(
            (self.encrypted * other.encrypted) % self.public_key.n2,
            self.public_key
        )

    def _add_scalar(self, scalar: int) -> EncryptedUnsignedInteger:
        """
        Homomorphic addition of an encrypted non-negative integer with a plaintext non-negative integer scalar, using
        the right-addition operator (i.e., `c2 := Enc(p1 + s) = Enc(p1) * g^s mod n^2`, where `p1` is the original
        plaintext non-negative integer encrypted as this ciphertext, `s` is the provided plaintext non-negative integer
        scalar, and `c2` is the resulting Paillier ciphertext encrypting the plaintext sum: `p1 + s`).
        """
        if scalar < 0 or scalar >= self.public_key.n:
            raise ValueError("Scalar integer must be a non-negative integer in the range [0, n).")

        # Re-blind the ciphertext if the scalar summand is 0, to avoid leaking the fact that the scalar added was 0
        # (i.e., retaining indistinguishability of the ciphertext).
        if scalar == 0:
            return self.add_and_obfuscate(scalar)

        if self.public_key.g == self.public_key.n + 1:
            # Homomorphic addition of scalar without re-blinding: `c2 := Enc(p + s) = Enc(p) * (1 + n*s) mod n^2`,
            # using the optimization: `g^s ≡ (1 + n)^s ≡ (1 + n*s) mod n^2`, when `g == n + 1`.
            return EncryptedUnsignedInteger(
                (self.encrypted * (1 + self.public_key.n * scalar)) % self.public_key.n2,
                self.public_key
            )
        else:
            # Homomorphic addition of scalar without re-blinding: `c2 := Enc(p + s) = Enc(p) * g^s mod n^2`
            return EncryptedUnsignedInteger(
                (self.encrypted * pow(self.public_key.g, scalar, self.public_key.n2)) % self.public_key.n2,
                self.public_key
            )

    def add_and_obfuscate(self, other: EncryptedUnsignedInteger | int) -> EncryptedUnsignedInteger:
        """
        Homomorphic addition of two Paillier encrypted non-negative integers, followed by ciphertext obfuscation
        (re-blinding) (i.e., `c3' := Enc'(p1 + p2) = Enc(p1) * Enc(p2) * r^n mod n^2`), where `p1` and `p2` are
        plaintext non-negative integers encrypted as this and the `other_encrypted` ciphertexts, respectively, and `c3'`
        is the resulting re-blinded (obfuscated) homomorphic sum, a Paillier ciphertext encrypting the plaintext sum:
        `p1 + p2`.

        Alternatively, if passed a non-negative integer scalar, it performs homomorphic addition of an encryption of the
        provided scalar with this ciphertext (i.e., `c2' := Enc'(p1 + s) = Enc(p1) * Enc(s) mod n^2`, where `p1` is the
        original plaintext non-negative integer encrypted as this ciphertext, `s` is the provided plaintext non-negative
        integer scalar, and `c2'` is the resulting re-blinded (obfuscated) homomorphic sum, a Paillier ciphertext
        encrypting the plaintext sum: `p1 + s`).

        This combined operation is useful for preserving privacy in secure multi-party computation (MPC) protocols
        involving homomorphic operations, as it re-blinds the resulting homomorphic sum with a random blinding factor
        (`r^n`, where `r` ∈ [1, n) ), which doesn't affect the encrypted plaintext due to its cancellation during
        decryption, but makes the resulting ciphertext indistinguishable from other ciphertexts.
        """
        if type(other) is int:
            return self._add_scalar_and_reblind(other)
        elif isinstance(other, EncryptedUnsignedInteger):
            return self._add_ciphertexts_and_reblind(other)
        else:
            raise ValueError("Homomorphic addition operands must be of type EncryptedUnsignedInteger or int.")

    def _add_ciphertexts_and_reblind(self, other: EncryptedUnsignedInteger) -> EncryptedUnsignedInteger:
        """
        Homomorphic addition of two Paillier encrypted non-negative integers, followed by ciphertext re-blinding
        (i.e., `c3' := Enc'(p1 + p2) = Enc(p1) * Enc(p2) * r^n mod n^2`), where `p1` and `p2` are plaintext non-negative
        integers encrypted as this and the `other` ciphertexts, respectively, and `c3'` is the resulting re-blinded
        (obfuscated) homomorphic sum, a Paillier ciphertext encrypting the plaintext sum: `p1 + p2`.
        """
        if self.public_key != other.public_key:
            raise ValueError("Homomorphic addition operands must have the same Paillier public key.")

        # Generate a random blinding factor (base) `r` in the range [2, n-1), which is also co-prime with `n`
        # (i.e., `gcd(r, n) == 1`).
        blinding_factor_base: int = self.public_key.generate_random_blinding_factor_base()

        # Calculate the re-blinding factor `r^n` (i.e., `r^n mod n^2`).
        blinding_factor: int = pow(blinding_factor_base, self.public_key.n, self.public_key.n2)

        return EncryptedUnsignedInteger(
            (self.encrypted * other.encrypted * blinding_factor) % self.public_key.n2,
            self.public_key
        )

    def _add_scalar_and_reblind(self, scalar: int) -> EncryptedUnsignedInteger:
        """
        Homomorphic addition of an encrypted non-negative integer with a plaintext non-negative integer scalar, followed
        by ciphertext re-blinding (i.e., `c2' := Enc'(p1 + s) = Enc(p1) * g^s * r^n = Enc(p1) * Enc(s) mod n^2`), where
        `p1` is the original plaintext non-negative integer encrypted as this ciphertext, `s` is the provided plaintext
        non-negative integer scalar, and `c2'` is the resulting re-blinded homomorphic sum, a Paillier ciphertext
        encrypting the plaintext sum: `p1 + s`.
        """
        if scalar < 0 or scalar >= self.public_key.n:
            raise ValueError("Scalar integer must be a non-negative integer in the range [0, n).")

        # Generate a random blinding factor (base) `r` in the range [2, n-1), which is also co-prime with `n`
        # (i.e., `gcd(r, n) == 1`).
        blinding_factor_base: int = self.public_key.generate_random_blinding_factor_base()

        # Calculate the re-blinding factor `r^n` (i.e., `r^n mod n^2`).
        blinding_factor: int = pow(blinding_factor_base, self.public_key.n, self.public_key.n2)

        if self.public_key.g == self.public_key.n + 1:
            # Use optimization: `g^s ≡ (1 + n)^s ≡ (1 + n*s) mod n^2`, when `g == n + 1`.
            return EncryptedUnsignedInteger(
                (
                    self.encrypted * (1 + self.public_key.n * scalar) * blinding_factor
                ) % self.public_key.n2,
                self.public_key
            )
        else:
            return EncryptedUnsignedInteger(
                (
                    self.encrypted * pow(self.public_key.g, scalar, self.public_key.n2) * blinding_factor
                ) % self.public_key.n2,
                self.public_key
            )

    def multiply(self, scalar: int) -> EncryptedUnsignedInteger:
        """
        Homomorphic scalar multiplication of an encrypted integer by a plaintext "scalar" value.

        (i.e., `c2 := Enc(p1 * s) = Enc(p1)^s mod n^2`, where `p1` is a plaintext non-negative integer encrypted as this
        ciphertext, `s` is the provided plaintext non-negative integer "scalar" multiplier, and `c2` is the resulting
        homomorphic scalar product, a Paillier ciphertext encrypting the plaintext product: `p1 * s`.)

        - Note: The special cases of a scalar multiplier of zero or one are handled separately, as these require
        re-blinding of the ciphertext to avoid leaking information with the ciphertext that's otherwise produced
        (i.e., that the encrypted plaintext result is `0` itself, in the case of the zero multiplier:
            `Enc(p1 * 0) = Enc(p1)^0 = 1`,
        or breaking indistinguishability and leaking the multiplier (i.e., in the case of a scalar multiplier of `1`:
            `Enc(p1 * 1) = Enc(p1)^1 = Enc(p1)`

          - The revised re-blinded operation for scalar `s = 0` is:
              `c2' := Enc'(p1 * 0) = Enc(p1)^0 * r^n mod n^2`,
          where `r` ∈ [1, n) is a random blinding factor base, and `c2'` is the resulting re-blinded ciphertext.
          - The revised re-blinded operation for scalar `s = 1` is:
              `c2' := Enc'(p1 * 1) = Enc(p1)^1 * r^n mod n^2`
        :param scalar: The plaintext non-negative integer "scalar" multiplier to multiply the encrypted integer by.
        :return: The resulting homomorphic scalar product, a Paillier ciphertext encrypting the plaintext product:
                 `p1 * s`, where `p1` is the original plaintext non-negative integer encrypted as this ciphertext,
                 and `s` is the provided plaintext non-negative integer "scalar" multiplier.
        :raises ValueError: If the scalar is a negative integer.
        """
        # Ensure that the scalar is a non-negative integer, as Paillier encryption only natively supports non-negative
        # integer plaintexts.
        if scalar < 0:
            raise ValueError(
                "The 'scalar' multiplier used in Paillier homomorphic scalar multiplication must be a non-negative"
                " integer."
            )
        elif scalar == 0:
            # Perform necessary re-blinding of the ciphertext, since naïve homomorphic scalar multiplication by zero
            # results in an unblinded ciphertext value of 1, which trivially leaks the encrypted plaintext result of 0.
            return self.multiply_and_obfuscate(scalar)
        elif scalar == 1:
            # Perform necessary re-blinding of the ciphertext, since naïve homomorphic scalar multiplication by 1
            # results in the original ciphertext (i.e., breaking indistinguishability), and leaking the fact that the
            # scalar multiplier was 1.
            return self.multiply_and_obfuscate(scalar)
        else:
            return EncryptedUnsignedInteger(
                pow(self.encrypted, scalar, self.public_key.n2),
                self.public_key
            )

    def multiply_and_obfuscate(self, scalar: int) -> EncryptedUnsignedInteger:
        """
        Homomorphic scalar multiplication of an encrypted non-negative integer by a plaintext non-negative integer
        "scalar", followed by ciphertext obfuscation (re-blinding). This combined operation is useful for preserving
        privacy in secure multi-party computation (MPC) protocols involving homomorphic operations, as is re-blinds the
        resulting ciphertext product with a random blinding factor (`r^n`, where `r` ∈ [1, n) ), which doesn't affect
        the encrypted plaintext due to its cancellation during decryption, but makes the resulting ciphertext
        indistinguishable from other ciphertexts.

        (i.e., `c2' := Enc'(p1 * s) = Enc(p1)^s * r^n mod n^2`, where `p1` is a plaintext non-negative integer encrypted
        as this ciphertext, `s` is the provided plaintext non-negative integer "scalar" multiplier, and `c2` is the
        resulting homomorphic scalar product, a Paillier ciphertext encrypting the plaintext product: `p1 * s`).
        """
        # Ensure that the scalar is a non-negative integer, as Paillier encryption only natively supports non-negative
        # integer plaintexts.
        if scalar < 0:
            raise ValueError(
                "The 'scalar' multiplier used in Paillier homomorphic scalar multiplication must be a non-negative"
                " integer."
            )

        # Generate a random blinding factor (base) `r` in the range [2, n-1), which is also co-prime with `n`
        # (i.e., `gcd(r, n) == 1`).
        blinding_factor_base: int = self.public_key.generate_random_blinding_factor_base()

        return EncryptedUnsignedInteger(
            (
                pow(
                    self.encrypted, scalar, self.public_key.n2
                ) * pow(
                    blinding_factor_base, self.public_key.n, self.public_key.n2
                )
            ) % self.public_key.n2,
            self.public_key
        )

    def obfuscate(self) -> EncryptedUnsignedInteger:
        """
        Obfuscates (re-blinds) this Paillier ciphertext's encrypted non-negative integer, by multiplying it by a new
        random blinding factor (`r^n`, where `r` ∈ [2, n-1) ), which doesn't affect the encrypted plaintext due to its
        cancellation during decryption, but makes the resulting ciphertext indistinguishable from other ciphertexts
        (i.e., `c' = c * r^n mod n^2`).

        This operation is useful for preserving privacy in multi-party computations involving homomorphic operations.
        Following any homomorphic operation or sequence of homomorphic operations, prior to sharing the resulting
        ciphertext(s) with a 3rd party, it is recommended to obfuscate the produced ciphertext(s) first.

        Note: Homomorphic "scalar" multiplication by small integers (e.g., 32-bit integers) can otherwise leave the
        "scalar" multiplier vulnerable to discovery by a 3rd party, via brute-force search of the "scalar" space, when
        the original ciphertext and product of the homomorphic "scalar" multiplication are shared with a 3rd party.
        (i.e., An adversary can then calculate the homomorphic "scalar" product, of the original ciphertext and each
        possible scalar in such smaller scalar spaces, and compare the resulting ciphertexts against the ciphertext
        scalar product that was shared, to determine the scalar multiplier that was used in the original homomorphic
        "scalar" multiplication.)
        """
        # Generate a random blinding factor (base) `r` in the range [2, n-1), which is also co-prime with `n`
        # (i.e., `gcd(r, n) == 1`).
        blinding_factor_base: int = self.public_key.generate_random_blinding_factor_base()

        # Obfuscate the ciphertext by multiplying it by a blinding factor `r^n` (i.e., `c' = c * r^n mod n^2`).
        return EncryptedUnsignedInteger(
            self.encrypted * pow(blinding_factor_base, self.public_key.n, self.public_key.n2) % self.public_key.n2,
            self.public_key
        )
