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

import libnum

from scriptless_zkp import utils

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
        self.mu = libnum.invmod(private_lambda, public_modulus)

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
        p, q, n = cls._generate_safer_primes(prime_factor_size_bits)

        # Compute the private key: `λ(n) := lcm(p-1, q-1)` (i.e., the Carmichael function of n).
        private_lambda: int = cls._calc_private_lambda(p, q, safe_primes=True)

        # Choose `g = n + 1`, a known generator `g ∈ B` of the set of n-th residues modulo n^2, where `B` := the set of
        # elements of Z_{n^2}^* with order `n * 𝜶`, for 𝜶 ∈ [1, λ(n)].
        g = n + 1

        priv_key = PaillierPrivateKey(private_lambda, n)
        pub_key = PaillierPublicKey(n, g)

        return cls(pub_key, priv_key)

    @staticmethod
    def _calc_private_lambda(p: int, q: int, safe_primes: bool = False) -> int:
        """
        Computes the private key lambda: `λ(n) = lcm(p-1, q-1)` (i.e., Carmichael's function).

        If the provided primes are "safe" primes, then `gcd(p-1, q-1) = 2`, and the following formula is used to
        simplify the calculation: `lcm(a, b) = a*b/gcd(a, b)`, resulting in `λ(n) = (p-1)*(q-1)/2`.

        :param p: The first prime factor `p` of the public modulus `n = p * q`.
        :param q: The second prime factor `q` of the public modulus `n = p * q`.
        :param safe_primes: Whether the primes `p` and `q` are "safe" primes (i.e., `(p-1)/2` and `(q-1)/2` are also
               prime).
        :return: The private key lambda: `λ(n) = lcm(p-1, q-1)`.
        """
        if safe_primes:
            return (p - 1) * (q - 1) // 2  # lcm(p-1, q-1) = (p-1)*(q-1)/2, since gcd(p-1, q-1) = 2 for "safe" primes
        else:
            return libnum.lcm(p - 1, q - 1)

    @staticmethod
    def _generate_safer_primes(size_bits: int) -> (int, int, int):
        """
        Generates two "safe" primes (i.e., primes `p`, `q` such that `(p-1)/2` and `(q-1)/2` are also prime), using the
        specified bit-size for each prime. (Each prime will lie in the range: `[2^(size_bits-1) + 1, 2^size_bits - 1]`).

        Using "safe" primes also guarantees that gcd(p-1, q-1) = 2, ensuring gcd(λ(p), λ(q)) is small (i.e., 2 in this
        case), since λ(p) = p-1 and λ(q) = q-1 for primes p and q, respectively. That these are "safe" primes also
        ensures `p-1` and `q-1` have a large prime factor. Together, these properties provide protection against
        sophisticated factoring algorithms like Pollard's p-1 method.

        (This also simplifies the calculation of the private key lambda: `λ(n) = lcm(p-1, q-1)`, using the formula:
        `lcm(a*b) = a*b / gcd(a, b)` => `lcm(p-1, q-1) = (p-1)*(q-1)/gcd(p-1, q-1) = (p-1)*(q-1)/2` ).

        Additionally, this method ensures the absolute difference of the two primes are greater or equal to the 4th root
        of `n` (i.e., `|p - q| >= nroot(n, 4)`), which is a recommended security measure for Paillier key (and RSA key)
        generation. (This ensures the two primes are "not too close together", in order to thwart brute-force attacks
        seeking to factor the public modulus `n` via Fermat’s difference of squares method.)

        :param size_bits: The bit-size to use for each of the two "safe" primes to be generated.
        :return: A tuple of two "safe" prime numbers: `p` and `q`, generated using the specified bit-size, along with
                 their product (i.e., the public modulus `n = p * q`).
        """
        while True:
            p: int = utils.random_safe_prime(size_bits)
            q: int = utils.random_safe_prime(size_bits)
            n: int = p * q  # candidate public modulus: `n = p * q`

            abs_diff: int = abs(p - q)
            # Compute the (truncated) 4th root of the public modulus `n = p * q`.
            fourth_root_n: int = libnum.nroot(n, 4)

            if abs_diff >= fourth_root_n:
                return p, q, n   # return "safe" primes `p` and `q`, and public modulus `n`

    def validate_key_pair(self) -> None:
        """
        Verifies whether a Paillier key-pair is valid, raising a `ValueError` if not. Validations of the public key's
        modulus and generator are performed, in addition to two sophisticated tests of the private key's validity,
        which involve modular congruence identities due to Carmichael's theorem.

        These validations are especially useful for verifying a Paillier key-pair's validity following deserialization.

        :raises ValueError: If this Paillier key-pair is invalid.
        """
        self._validate(self.public_key, self.private_key)

    def encode_private_key(self) -> str:
        return self.private_key.encode_to_base64()

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
