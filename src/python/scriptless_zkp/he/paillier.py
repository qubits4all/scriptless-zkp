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

from dataclasses import dataclass

from Cryptodome.Util import number

import libnum


MIN_KEY_SIZE: int = 2048      # Note: Min. key-size for use in Y. Lindell's 2-Party ECDSA protocol w/ 256-bit ECC keys.
DEFAULT_KEY_SIZE: int = 3072  # Default based on NIST recommended min. RSA key size of 3072 bits.


@dataclass
class PaillierPrivateKey:
    lam: int                # λ(n) = lcm(p-1, q-1) -- The Carmichael function of n.
    mu: int                 # λ(n)^-1 mod n -- The modular multiplicative inverse of λ(n) modulo n.
    n: int                  # The public modulus n = p * q, for p, q prime.
    _n2: int | None = None

    def __init__(self, lam: int, n: int):
        self.lam = lam
        self.n = n
        self.mu = libnum.invmod(lam, n)

    @property
    def n_squared(self) -> int:
        # Lazily compute n^2 and cache the result, on first access.
        if self._n2 is None:
            self._n2 = self.n ** 2

        return self._n2

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
        if ciphertext.encrypted < 0 or ciphertext.encrypted >= self.n_squared:
            raise ValueError("Ciphertext is out of range for decryption.")

        # Dec(sk=lam, c): `m = L(c^λ mod n^2) * μ mod n`, where `L(u) = (u - 1) / n` and `μ ≡ λ^-1 mod n`
        return self._L(
            pow(ciphertext.encrypted, self.lam, self.n_squared),
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
    n: int
    g: int
    _n2: int | None = None

    @property
    def n_squared(self) -> int:
        # Lazily compute n^2 and cache the result, on first access.
        if self._n2 is None:
            self._n2 = self.n ** 2

        return self._n2

    def encrypt(self, message: int) -> EncryptedUnsignedInteger:
        """
        Encrypts a non-negative integer message using the Paillier public key. Encryption of message `m` is performed
        as:
            Enc(pk=n, m): `c = g^m * r^n mod n^2`, where the blinding factor `r` is a random prime in `Z_{n}^*`.
        """
        if message < 0 or message >= self.n_squared:
            raise ValueError("Message is out of range for encryption.")

        # Generate a random prime r in `Z_{n}^*`, to be used as a blinding factor.
        # Note: gcd(r, n) = 1 as required since r is prime, unless r = p or r = q (i.e., where n = p * q).
        while (r := number.getPrime(self.n.bit_length())) >= self.n:
            pass

        encrypted: int = (
            pow(self.g, message, self.n_squared) * pow(r, self.n, self.n_squared)
        ) % self.n_squared

        return EncryptedUnsignedInteger(encrypted, self)


# TODO: Add support for key-pair serialization/deserialization.
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

        # Choose `g = n + 1`, a known generator ∈ B of the set of n-th residues modulo n^2, where B := the disjoint union
        # of subsets B_𝜶 of Z_{n^2}^*, where B_𝜶 := the set of elements of Z_{n^2}^* with order `n * 𝜶`.
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
            (self.encrypted * other_encrypted.encrypted) % self.public_key.n_squared,
            self.public_key
        )

    def __mul__(self, scalar: int) -> EncryptedUnsignedInteger:
        return EncryptedUnsignedInteger(
            pow(self.encrypted, scalar, self.public_key.n_squared),
            self.public_key
        )

    def decrypt(self, private_key: PaillierPrivateKey) -> int:
        return private_key.decrypt(self)
