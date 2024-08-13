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

from scriptless_zkp import utils
from scriptless_zkp.he import (
    DEFAULT_HMAC_HASH_ALGORITHM, DEFAULT_PKCS8_HMAC_SALT_BYTES, DEFAULT_PKCS8_AES_KEY_BYTES,
    MIN_PKCS8_PASSPHRASE_LENGTH, PKCS8_KDF_PBKDF2_SHA224_AES128_CBC, PKCS8_KDF_PBKDF2_SHA256_AES128_CBC,
    PKCS8_KDF_PBKDF2_SHA384_AES192_CBC, PKCS8_KDF_PBKDF2_SHA512_AES256_CBC, PKCS8_KDF_PBKDF2_SHA3_224_AES128_CBC,
    PKCS8_KDF_PBKDF2_SHA3_256_AES128_CBC, PKCS8_KDF_PBKDF2_SHA3_384_AES192_CBC, PKCS8_KDF_PBKDF2_SHA3_512_AES256_CBC,
    OWASP_PBKDF2_SHA256_ITERATIONS
)
from scriptless_zkp.number_theory import random_strong_prime, mod_inverse

MIN_KEY_SIZE: int = 2048      # Note: Min. key-size for use in Y. Lindell's 2-Party ECDSA protocol w/ 256-bit ECC keys.
DEFAULT_KEY_SIZE: int = 3072  # Default based on NIST recommended min. RSA key size of 3072 bits.


@dataclass
class PaillierPrivateKey:
    λ: int                  # private key lambda: `λ(n) = lcm(p-1, q-1)` -- The Carmichael function of public modulus n
    n: int                  # public modulus: `n = p * q`, for private p, q prime
    mu: int                 # modular inverse of private key lambda: `λ(n)^-1 mod n`
    _n2: int | None = None  # cached square `n^2` of the public modulus `n`

    def __init__(self, private_lambda: int, public_modulus: int):
        self._validate(public_modulus)

        self.λ = private_lambda
        self.n = public_modulus
        # Calculate the modular inverse of the private key lambda: `λ(n)^-1 mod n`
        self.mu = mod_inverse(private_lambda, public_modulus)

    @staticmethod
    def _validate(public_modulus: int) -> None:
        # Verify the Paillier private key's public modulus is at least 2047 bits (i.e., MIN_KEY_SIZE - 1).
        # Note: The modulus `n : = p*q`, where `p` and `q` are prime, can be between 2047 & 2048 bits, due to the
        #   1024-bit primes `p` & `q` allowed values lying inside the range: [2^(1023) + 1, 2^(1024) - 1]
        if public_modulus.bit_length() < (MIN_KEY_SIZE - 1):
            raise ValueError(
                f"Invalid Paillier private key -- public modulus must be at least [{MIN_KEY_SIZE - 1}] bits."
            )

    def validate_private_key(self) -> None:
        """
        Determines if this Paillier private key is valid, raising a `ValueError` if not. Validations performed include
        verifying whether its public modulus meets this module's minimum key-size requirement (i.e., 2047-bits).

        :raises ValueError: If this Paillier private key is invalid.
        """
        return self._validate(self.n)

    def __str__(self) -> str:
        """
        Returns a base64-based encoding of this Paillier private key, which uses the following format:
            `{private_lambda_base64}:{public_modulus_base64}`
        """
        return self.encode_to_base64()

    def __repr__(self) -> str:
        """
        Returns a string representation of the Paillier private key (base64-encoded), in the format:
            `PaillierPrivateKey(λ, n)='{private_lambda_base64}:{public_modulus_base64}'`
        """
        return (
            f"PaillierPrivateKey(λ, n)='{self.encode_to_base64()}'"
        )

    # noinspection DuplicatedCode
    @classmethod
    def from_base64_encoding(cls, encoded_private_key: str) -> PaillierPrivateKey:
        parsed_fields: list[str] = encoded_private_key.split(':')
        if len(parsed_fields) != 2:
            raise ValueError(
                f"Invalid encoded Paillier private key format -- two base64-encoded fields expected"
                f" [fields_count={len(parsed_fields)}]"
            )

        private_lambda_base64, public_modulus_base64 = parsed_fields

        try:
            private_lambda: int = number.bytes_to_long(
                base64.b64decode(private_lambda_base64, validate=True)
            )
            public_modulus: int = number.bytes_to_long(
                base64.b64decode(public_modulus_base64, validate=True)
            )
        except binascii.Error as b64ex:
            raise ValueError(f"Invalid base64 encoding for Paillier private key -- exception: {b64ex}")
        else:
            return cls(private_lambda, public_modulus)

    @property
    def n2(self) -> int:
        # Lazily compute n^2 and cache the result, on first access.
        if self._n2 is None:
            self._n2 = self.n ** 2

        return self._n2

    def private_lambda(self) -> int:
        return self.λ

    def private_lambda_inverse(self) -> int:
        return self.mu

    def public_modulus(self) -> int:
        return self.n

    def public_modulus_squared(self) -> int:
        return self.n2

    def export_private_key(self, passphrase: str | None = None) -> str:
        """
        Exports this Paillier private key as a PKCS#8 encrypted private key, using the provided passphrase for
        password-based key-wrap encryption using PBKDF2 for symmetric (AES) key derivation and AES-CBC for encryption
        of the encoded Paillier private key; or simply encodes the private key to a base64-based string encoding, if no
        passphrase is provided.

        :param passphrase: a passphrase to use in encrypting this private key, using PKCS#8 password-based key-wrap
               encryption; or None if the private key should only be encoded to a base64-based string encoding.
        :return: the PKCS#8 encrypted private key as a string-encoded representation, which includes PBKDF2 parameters
                 and the HMAC salt necessary for decrypting the private key.
        """
        encoded_key_base64: str = self.encode_to_base64()

        if passphrase is not None:
            if len(passphrase) < MIN_PKCS8_PASSPHRASE_LENGTH:
                raise ValueError(
                    f"Unsupported passphrase length [{len(passphrase)}] for PKCS#8-based Pailler private key encryption"
                    f" -- minimum length (chars.): {MIN_PKCS8_PASSPHRASE_LENGTH}"
                )

            # Encrypt encoded private key using PKCS#8 password-based encryption, using PBKDF2 for key-wrap (symmetric)
            # key derivation and AES-CBC for encryption (i.e., PBKDF2 w/ HMAC-SHA3-256 & AES-128-CBC by default).
            encrypted_private_key_asn1_der: bytes = self._pkcs8_encrypt_encoded_private_key(
                encoded_key_base64.encode('utf-8'),
                passphrase.encode('utf-8')
            )
            return self._encode_pkcs8_encrypted_private_key(encrypted_private_key_asn1_der)
        else:
            return encoded_key_base64

    def _pkcs8_encrypt_encoded_private_key(
            self,
            private_key_base64: bytes,
            passphrase: bytes,
            pbkdf2_iterations: int = OWASP_PBKDF2_SHA256_ITERATIONS,
            hmac_hash_algorithm: str = DEFAULT_HMAC_HASH_ALGORITHM,  # default: HMAC-SHA3-256
            salt_size_bytes: int = DEFAULT_PKCS8_HMAC_SALT_BYTES,    # default: 32 bytes (256 bits)
            aes_key_size_bytes: int = DEFAULT_PKCS8_AES_KEY_BYTES    # default: AES-128 key size (16 bytes)
    ) -> bytes:
        """
        Encrypts the base64-encoded Paillier private key using PKCS#8 password-based key-wrap encryption, using PBKDF2
        for password-based symmetric (AES) key derivation and AES-CBC for encryption of the provided encoded private
        key, returning a string encoding of the encrypted private key (including PBKDF2 parameters and a salt value
        required for decryption).
        """
        supported_PBKDF2_profiles: set[str] = self._supported_pbkdf2_profiles()

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

        return PKCS8.wrap(
            private_key=private_key_base64,
            key_oid="",                      # empty OID for Paillier private key (no standard OID defined)
            passphrase=passphrase,
            protection=pbkdf2_profile,
            prot_params=pbkdf2_params
        )

    @staticmethod
    def _encode_pkcs8_encrypted_private_key(
            encrypted_private_key_asn1_der: bytes,
            pbkdf2_iterations: int
    ) -> str:
        """
        Encodes a PKCS#8 encrypted private key, including the PBKDF2 parameters and HMAC salt value required for
        successful decryption, in a string format that can be stored or transmitted securely.

        Uses the string encoding format, as defined in the Password Hashing Competition's string format spec:
        https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md

        :param encrypted_private_key_asn1_der: an encrypted private key wrapped in a PKCS#8 container, and encoded in
               the (ASN.1) DER binary format, which includes the PBKDF2 (HMAC) salt value used during (symmetric)
               key-wrap encryption key derivation.
        :param pbkdf2_iterations: the number of iterations used in the PBKDF2 key derivation function.
        :return: a string-encoded representation of the PKCS#8 encrypted private key, including PBKDF2 parameters
                 necessary for successful decryption.
        """
        VERSION: int = 1
        encrypted_private_key_base64: str = base64.b64encode(encrypted_private_key_asn1_der).decode('utf-8')

        return f"$pbkdf2$v={VERSION}$iterations={pbkdf2_iterations}${encrypted_private_key_base64}"

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

    def import_private_key(
            self,
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
            encrypted_private_key_asn1_der, pbkdf2_params = self._decode_pkcs8_encrypted_private_key(
                encoded_private_key
            )

            # Decrypt PKCS#8 encrypted Paillier private key.
            private_key_base64_bytes: bytes = self._pkcs8_decrypt_private_key(
                encrypted_private_key_asn1_der,
                passphrase
            )

            return self.from_base64_encoding(private_key_base64_bytes.decode('utf-8'))
        else:
            return self.from_base64_encoding(encoded_private_key)

    # TODO: Implement PKCS#8-based private key decryption, using the PyCryptodome library's 'PKCS8' module.
    def _pkcs8_decrypt_private_key(self, encrypted_private_key_asn1_der: bytes, passphrase: str) -> bytes:
        pass

    # TODO: Implement a decoding method for PKCS#8 encrypted Paillier private keys, which parses the PBKDF2 parameters
    #   required for decryption.
    # Note: Consider using the Argon2-related string encoding format (i.e., that used in the Password Hashing
    #   Competition: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md).
    def _decode_pkcs8_encrypted_private_key(self, encrypted_private_key: str) -> (bytes, dict[str, int]):
        pass

    def encode_to_base64(self) -> str:
        """
        Returns a base64-based encoding of this Paillier private key, which uses the following format:
            `{private_lambda_base64}:{public_modulus_base64}`
        """
        private_lambda_base64: str = base64.b64encode(
            number.long_to_bytes(self.λ)
        ).decode('utf-8')

        public_modulus_base64: str = base64.b64encode(
            number.long_to_bytes(self.n)
        ).decode('utf-8')

        return f"{private_lambda_base64}:{public_modulus_base64}"

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
        # Ensure u ∈ Z_{n^2}^* (i.e., u is a non-zero element of the multiplicative group of integers modulo n^2).
        assert 0 < u < n ** 2, "u must be in the range [1, n^2)."
        # Ensure that L(u, n) is well-defined (i.e., u ≡ 1 mod n).
        assert u % n == 1, "u must be congruent to 1 modulo n."

        return (u - 1) // n


@dataclass
class PaillierPublicKey:
    n: int                 # public modulus: `n = p * q`, for private p, q prime
    g: int                 # public generator `g ∈ B` of the set of n-th residues modulo n^2 (i.e., `g` generates CR[n])
    _n2: int | None = None

    def __init__(self, public_modulus: int, public_generator: int, validate: bool = False):
        if validate:
            self._validate(public_modulus, public_generator)

        self.n = public_modulus
        self.g = public_generator

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
                "Invalid Paillier public key -- the public generator 'g' must be equal to: n + 1, where 'n' is the"
                " public modulus."
            )

    # noinspection DuplicatedCode
    @classmethod
    def from_base64_encoding(cls, encoded_public_key: str) -> PaillierPublicKey:
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

    def __str__(self) -> str:
        """
        Returns a base64-based encoding of this Paillier public key, which uses the following format:
            `{public_modulus_base64}:{public_generator_base64}`
        """
        return self.encode_to_base64()

    def __repr__(self) -> str:
        """
        Returns a string representation of the Paillier public key (base64-encoded), in the format:
            `PaillierPublicKey(n, g)='{public_modulus_base64}:{public_generator_base64}'`
        """
        return (
            f"PaillierPublicKey(n, g)='{self.encode_to_base64()}'"
        )

    @property
    def n2(self) -> int:
        # Lazily compute n^2 and cache the result, on first access.
        if self._n2 is None:
            self._n2 = self.n ** 2

        return self._n2

    def public_modulus(self) -> int:
        return self.n

    def public_generator(self) -> int:
        return self.g

    def public_modulus_squared(self) -> int:
        return self.n2

    def encode_to_base64(self) -> str:
        """
        Returns a base64-based encoding of this Paillier public key, which uses the following format:
            `{public_modulus_base64}:{public_generator_base64}`
        """
        public_modulus_base64: str = base64.b64encode(number.long_to_bytes(self.n)).decode('utf-8')
        public_generator_base64: str = base64.b64encode(number.long_to_bytes(self.g)).decode('utf-8')

        return f"{public_modulus_base64}:{public_generator_base64}"

    def encrypt(self, message: int) -> EncryptedUnsignedInteger:
        """
        Encrypts a non-negative integer message using the Paillier public key. Encryption of message `m` is performed
        as:
            Enc(pk=n, m): `c = g^m * r^n mod n^2`, where the base `r`, of the blinding factor `r^n`, is a random prime
        in `Z_{n}^*` (i.e., r ∈ [1, n) ).
        :param message: The non-negative integer message to be encrypted, which must lie in the range `[0, n)` to be a
               valid Paillier message.
        :return: The encrypted non-negative integer message, as a Paillier ciphertext, an integer `c` ∈ [1, n^2).
        :raises ValueError: If the message is out of range for encryption (i.e., if it lies outside of: `[0, n)` ).
        """
        # Ensure the message `m` is a non-negative integer in the range [0, n) (i.e., `m` ∈ `Z_{n}`, the (additive)
        # group of integers modulo `n`).
        if message < 0 or message >= self.n:
            raise ValueError("Message is out of range for encryption.")

        # Generate a random blinding factor (base) `r` in the range [1, n) (i.e., r ∈ `Z_{n}^*`, the multiplicative
        # group of integers modulo `n`).
        # Note: gcd(r, n) = 1 is required, however a random r ∈ `Z_{n}^*` meets this requirement unless r == p or
        #   r == q, where n := p*q (which is highly unlikely to occur).
        blinding_factor_base: int = utils.random_positive_integer(self.n)

        if self.g == self.n + 1:
            # Use optimization: `g^m ≡ (1 + n*m) mod n^2`, when `g == n + 1`.
            encrypted: int = (
                (1 + self.n * message) * pow(blinding_factor_base, self.n, self.n2)
            ) % self.n2
        else:
            encrypted: int = (
                pow(self.g, message, self.n2) * pow(blinding_factor_base, self.n, self.n2)
            ) % self.n2

        return EncryptedUnsignedInteger(encrypted, self)


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

        # Generate two large "safe" primes: `p` and `q`, of roughly equal size (half the key size in bits), which also
        # aren't "too close together" (i.e., `|p - q| >= nroot(n, 4)`), and their product: `n = p * q`.
        p, q, n = cls._generate_primes(prime_factor_size_bits)

        # Compute the private key: `λ(n) := lcm(p-1, q-1)` (i.e., the Carmichael function of n).
        private_lambda: int = cls._calc_private_lambda(p, q)

        # Choose `g = n + 1`, a known generator `g ∈ B` of the set of n-th residues modulo n^2, where `B` := the set of
        # elements of Z_{n^2}^* with order `n * 𝜶`, for 𝜶 ∈ [1, λ(n)].
        g = n + 1

        priv_key = PaillierPrivateKey(private_lambda, n)
        pub_key = PaillierPublicKey(n, g)

        return cls(pub_key, priv_key)

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
    def _generate_primes(size_bits: int) -> (int, int, int):
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

    def export_private_key(self, passphrase: str | bytearray) -> str:
        return self.private_key.export_private_key(passphrase)

    def encode_public_key(self) -> str:
        return self.public_key.encode_to_base64()


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
            f" public_key='{self.public_key.encode_to_base64()}')"
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

        # Generate a random re-blinding factor base `r` in `Z_{n}^*` (i.e., approx. r ∈ [1, n) ).
        blinding_factor_base: int = utils.random_positive_integer(self.public_key.n)

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

        # Generate a random re-blinding factor base `r` in `Z_{n}^*` (i.e., approx. r ∈ [1, n) ).
        blinding_factor_base: int = utils.random_positive_integer(self.public_key.n)

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
        """
        # Ensure that the scalar is a non-negative integer, as Paillier encryption only natively supports non-negative
        # integer plaintexts.
        if scalar < 0:
            raise ValueError(
                "The 'scalar' multiplier used in Paillier homomorphic scalar multiplication must be a non-negative"
                " integer."
            )

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

        # Generate a random blinding factor base `r` in `Z_{n}^*` (i.e., approx. r ∈ [1, n) ).
        blinding_factor_base: int = utils.random_positive_integer(self.public_key.n)

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
        random blinding factor (`r^n`, where `r` ∈ [1, n) ), which doesn't affect the encrypted plaintext due to its
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
        # Generate a random blinding factor base `r` in `Z_{n}^*` (i.e., approx. r ∈ [1, n) ).
        blinding_factor_base: int = utils.random_positive_integer(self.public_key.n)

        # Obfuscate the ciphertext by multiplying it by a blinding factor `r^n` (i.e., `c' = c * r^n mod n^2`).
        return EncryptedUnsignedInteger(
            self.encrypted * pow(blinding_factor_base, self.public_key.n, self.public_key.n2) % self.public_key.n2,
            self.public_key
        )
