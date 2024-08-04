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
import secrets

from dataclasses import dataclass

from Cryptodome.Util import number

import libnum


MIN_KEY_SIZE: int = 2048      # Note: Min. key-size for use in Y. Lindell's 2-Party ECDSA protocol w/ 256-bit ECC keys.
DEFAULT_KEY_SIZE: int = 3072  # Default based on NIST recommended min. RSA key size of 3072 bits.


@dataclass
class PaillierPrivateKey:
    λ: int                # private key lambda: `λ(n) = lcm(p-1, q-1)` -- The Carmichael function of public modulus n
    n: int                  # public modulus: `n = p * q`, for private p, q prime
    mu: int                 # modular inverse of private key lambda: `λ(n)^-1 mod n`
    _n2: int | None = None  # cached square `n^2` of the public modulus `n`

    def __init__(self, private_lambda: int, public_modulus: int):
        self.λ = private_lambda
        self.n = public_modulus
        # Calculate the modular inverse of the private key lambda: `λ(n)^-1 mod n`
        self.mu = libnum.invmod(private_lambda, public_modulus)

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
            private_lambda: int = number.bytes_to_long(base64.b64decode(private_lambda_base64))
            public_modulus: int = number.bytes_to_long(base64.b64decode(public_modulus_base64))
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
        private_lambda_base64: str = base64.b64encode(number.long_to_bytes(self.λ)).decode('utf-8')
        public_modulus_base64: str = base64.b64encode(number.long_to_bytes(self.n)).decode('utf-8')

        return f"{private_lambda_base64}:{public_modulus_base64}"

    def decrypt(self, ciphertext: EncryptedUnsignedInteger) -> int:
        """
        Decrypts an encrypted non-negative integer using the Paillier private key. Decryption of ciphertext `c` is
        performed as:
            Dec(sk=lam, c): `m = L(c^λ mod n^2) * μ mod n`, where `L(u) = (u - 1) / n` and `μ ≡ λ^-1 mod n`.

        The decryption function is only defined for ciphertexts in the range `[1, n^2)`.

        Note:
        :param ciphertext: The encrypted integer value to decrypt.
        :return: The decrypted integer value.
        """
        if ciphertext.encrypted < 0 or ciphertext.encrypted >= self.n2:
            raise ValueError("Ciphertext is out of range for decryption.")

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
        """
        # Ensure u ∈ Z_{n^2}^* (i.e., u is a non-zero element of the multiplicative group of integers modulo n^2).
        assert 0 < u < n ** 2, "u must be in the range [1, n^2)."
        # Ensure that L(u, n) is well-defined (i.e., u = 1 mod n).
        assert u % n == 1, "u must be congruent to 1 modulo n."

        return (u - 1) // n


@dataclass
class PaillierPublicKey:
    n: int                  # public modulus: `n = p * q`, for private p, q prime
    g: int                  # public generator `g ∈ B` of the set of n-th residues modulo n^2 (CR[n])
    _n2: int | None = None

    def __init__(self, public_modulus: int, public_generator: int):
        self.n = public_modulus
        self.g = public_generator

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
            public_modulus: int = number.bytes_to_long(base64.b64decode(public_modulus_base64))
            public_generator: int = number.bytes_to_long(base64.b64decode(public_generator_base64))
        except binascii.Error as b64ex:
            raise ValueError(f"Invalid base64 encoding for Paillier public key -- exception: {b64ex}")
        else:
            return cls(public_modulus, public_generator)

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
        public_modulus_base64: str = base64.b64encode(number.long_to_bytes(self.n)).decode('utf-8')
        public_generator_base64: str = base64.b64encode(number.long_to_bytes(self.g)).decode('utf-8')

        return f"{public_modulus_base64}:{public_generator_base64}"

    def encrypt(self, message: int) -> EncryptedUnsignedInteger:
        """
        Encrypts a non-negative integer message using the Paillier public key. Encryption of message `m` is performed
        as:
            Enc(pk=n, m): `c = g^m * r^n mod n^2`, where the blinding factor `r` is a random prime in `Z_{n}^*`.
        """
        if message < 0 or message >= self.n2:
            raise ValueError("Message is out of range for encryption.")

        # Generate a random blinding factor r in `Z_{n}^*` (i.e., r ∈ [1, n) ).
        # Note: gcd(r, n) = 1 is required, however a random r ∈ `Z_{n}^*` meets this requirement unless r == p or
        #   r == q (which is highly unlikely to occur).
        while (r := secrets.randbelow(self.n)) == 0:
            pass

        if self.g == self.n + 1:
            # Apply optimization: `g^m == (1 + n*m) mod n^2`, when `g == n + 1`.
            encrypted: int = (
                (1 + self.n * message) * pow(r, self.n, self.n2)
            ) % self.n2
        else:
            encrypted: int = (
                pow(self.g, message, self.n2) * pow(r, self.n, self.n2)
            ) % self.n2

        return EncryptedUnsignedInteger(encrypted, self)


@dataclass
class PaillierKeyPair:
    public_key: PaillierPublicKey
    private_key: PaillierPrivateKey

    def __init__(self, public_key: PaillierPublicKey, private_key: PaillierPrivateKey):
        self.public_key = public_key
        self.private_key = private_key

    @classmethod
    def generate(cls, key_size_bits: int = DEFAULT_KEY_SIZE) -> PaillierKeyPair:
        if key_size_bits < MIN_KEY_SIZE:
            raise ValueError(f"Paillier key-size must be at least [{MIN_KEY_SIZE}] bits.")

        prime_factor_size_bits: int = key_size_bits // 2

        # Generate two large prime numbers, p and q, of roughly equal size.
        p: int = number.getPrime(prime_factor_size_bits)
        q: int = number.getPrime(prime_factor_size_bits)

        # Compute the public modulus: `n = p * q`
        n = p * q

        # Compute the private key: `λ(n) := lcm(p-1, q-1)` (i.e., the Carmichael function of n).
        lam: int = libnum.lcm(p - 1, q - 1)

        # Choose `g = n + 1`, a known generator ∈ B of the set of n-th residues modulo n^2, where B := the disjoint
        # union of subsets B_𝜶 of Z_{n^2}^*, where B_𝜶 := the set of elements of Z_{n^2}^* with order `n * 𝜶`.
        g = n + 1

        priv_key = PaillierPrivateKey(lam, n)
        pub_key = PaillierPublicKey(n, g)

        return PaillierKeyPair(pub_key, priv_key)


@dataclass
class EncryptedUnsignedInteger:
    """
    EncryptedUnsignedInteger represents an unsigned integer value encrypted using the Paillier cryptosystem.
    """
    encrypted: int
    public_key: PaillierPublicKey

    def __init__(self, encrypted: int, public_key: PaillierPublicKey):
        self.encrypted = encrypted
        self.public_key = public_key

    def __add__(self, other_encrypted: EncryptedUnsignedInteger) -> EncryptedUnsignedInteger:
        if self.public_key != other_encrypted.public_key:
            raise ValueError("Homomorphic addition operands must have the same public key.")

        return EncryptedUnsignedInteger(
            (self.encrypted * other_encrypted.encrypted) % self.public_key.n2,
            self.public_key
        )

    def __mul__(self, scalar: int) -> EncryptedUnsignedInteger:
        return EncryptedUnsignedInteger(
            pow(self.encrypted, scalar, self.public_key.n2),
            self.public_key
        )

    def decrypt(self, private_key: PaillierPrivateKey) -> int:
        return private_key.decrypt(self)
