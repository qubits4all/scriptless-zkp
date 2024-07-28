###############################################################################
# (c) 2022, 2023, 2024 W. Spann Systems Consulting
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

"""
Modified cryptographic hashing for use with prime-order fields.
"""
from __future__ import annotations

import hashlib
import math

from abc import ABC, abstractmethod
from typing import Optional, Any

from Cryptodome.Util import number

from scriptless_zkp.exceptions import InvalidHasherStateException


class ReducedRangeHasher(ABC):
    """
    Provides a common interface for cryptographic hash functions that produce a hash output within a reduced range, such
    as to members of the prime-order field `F_q` for `q` prime, or to a range with the bit-length of a specified prime.

    Note: This interface is inspired by the hashlib.Hash interface, but with additional methods for producing hash
    outputs within a reduced range, such as for use in zero-knowledge proof protocols.

    The provided `update(message: bytes)` method is used to update the hash state with additional message data, and is
    designed to be chainable, returning the hasher instance itself. This allows for a more fluent, functional-style
    programming approach when using the hasher on input values that would otherwise have to be concatenated as byte
    strings first.

    Methods are provided for producing the final hash output as an integer, bytes, or hexadecimal string representation,
    as well as for hashing a message directly to any of these hash output formats in a single step.
    """

    @abstractmethod
    def update(self, message: bytes) -> ReducedRangeHasher:
        pass

    @abstractmethod
    def digest(self) -> bytes:
        pass

    @abstractmethod
    def intdigest(self) -> int:
        pass

    @abstractmethod
    def hexdigest(self) -> str:
        pass

    @abstractmethod
    def reset(self) -> ReducedRangeHasher:
        pass

    @abstractmethod
    def is_reset(self) -> bool:
        pass

    @abstractmethod
    def hash_to_int(self, message: bytes) -> int:
        pass

    @abstractmethod
    def hash(self, message: bytes) -> bytes:
        pass

    @abstractmethod
    def hash_to_hex(self, message: bytes) -> str:
        pass


class UniversalPrimeLengthHasher(ReducedRangeHasher):
    """
    Provides a universal hash function for producing a cryptographic hash of a given message, which maps onto a
    prime-order field for a specified prime `q`, ensuring the hash output is within the range `[0, q-1]`.

    This class uses the Carter-Wegman universal hash construction, which utilizes a universal hash function family that
    maps onto a target prime-order field `F_q`, ensuring the hash output is within the desired range `[0, q-1]`, for the
    configured prime `q`, while avoiding introducing bias in the hash output.

    Note: By default this class uses the randomized Carter-Wegman universal hash construction, making multiple calls to
    hash the same message produce different hash outputs. However, deterministic hash outputs can be produced by setting
    the `deterministic` flag to `True`, which causes this universal hash construction's coefficients to be derived
    deterministically from the message hash using the SHAKE-256 XOF hash function, thereby producing reproducible hashes
    for the same message.

    Note: This class is not thread-safe. (Use a thread-local for a hasher instance per thread, if needed in a
      multithreading context.)
    """
    DEFAULT_HASH_ALGO: str = hashlib.sha3_256().name

    q: int
    p: int
    hash_algo: str
    xof_hash_length: int | None
    domain_separator: Optional[str]
    deterministic: bool
    _hasher: Optional[Any] = None  # cryptographic hasher as obtained via hashlib.new(hash_algo)

    def __init__(
            self,
            target_field_order: int,
            larger_prime_p: int,
            hash_algorithm: str = DEFAULT_HASH_ALGO,
            xof_hash_digest_length: int | None = None,
            domain_separation_tag: Optional[str] = None,
            deterministic: bool = False
    ):
        """
        Constructs a universal hash function for producing cryptographic hashes that map onto a prime-order field for a
        specified prime `q`, ensuring the hash output is within the range `[0, q-1]`.
        :param target_field_order: the order of the prime-order field `F_q` (i.e., the prime integer `q`) onto which the
               constructed universal hash function will map the configured cryptographic hash's output.
        :param larger_prime_p: a prime integer that must be greater than the maximum integer value that can be produced
               by the configured cryptographic hash algorithm (i.e., when considered as an unsigned integer), used in
               the Carter-Wegman universal hash construction (e.g., `p > 2^256 - 1` for SHA-256 or SHA3-256).
        :param hash_algorithm: cryptographic hash algorithm to be used for producing the message input to a
               Carter-Wegman universal hash function.
        :param xof_hash_digest_length: optional length of the XOF (eXtendable Output Function) hash output, in bytes, to
               be used for the Carter-Wegman universal hash construction, when the hash algorithm is an XOF
               (e.g., SHAKE-256). If provided, the hash output will be exactly this length.
        :param domain_separation_tag: optional domain separation tag to be used for ensuring distinct hashes from other
               uses of the configured cryptographic hash algorithm.
        :param deterministic: flag indicating whether to use coefficients derived deterministically, from the message
               hash, for the Carter-Wegman universal hash construction, resulting in reproducible hashes for the same
               message if set to `True`.
        :raises ValueError: if the provided cryptographic hash algorithm is not supported by the `hashlib` library; or
                if a domain separation tag is provided that's equal to the empty string (or only whitespace).
        """
        if hash_algorithm not in hashlib.algorithms_available:
            raise ValueError(f"Unsupported cryptographic hash algorithm: {hash_algorithm}")
        elif domain_separation_tag is not None and domain_separation_tag.strip() == "":
            raise ValueError("Domain separation tag (if provided) must not be an empty-string or only whitespace.")

        if xof_hash_digest_length is None:
            hash_digest_bit_len: int = hashlib.new(hash_algorithm).digest_size * 8
        else:
            hash_digest_bit_len: int = xof_hash_digest_length * 8

        if target_field_order.bit_length() > hash_digest_bit_len:
            raise ValueError(
                f"Unable to construct universal hash function for prime-order field, as its bit-length: "
                f"({target_field_order.bit_length()} bits) exceeds the bit-length: ({hash_digest_bit_len} bits) of the "
                f"specified '{hash_algorithm}' hash algorithm's output size."
            )
        elif xof_hash_digest_length is not None and hash_algorithm != hashlib.shake_256().name:
            raise ValueError(
                f"Unable to construct universal hash function with XOF hash length: ({xof_hash_digest_length * 8} bits)"
                f" for non-SHAKE-256 hash algorithm: {hash_algorithm}"
            )

        self.q = target_field_order
        self.p = larger_prime_p
        self.hash_algo = hash_algorithm
        self.xof_hash_length = xof_hash_digest_length
        self.domain_separator = domain_separation_tag
        self.deterministic = deterministic

    @classmethod
    def for_field_order(
            cls,
            target_field_order: int,
            domain_separation_tag: str | None = None,
            deterministic: bool = False
    ) -> UniversalPrimeLengthHasher:
        field_order_bit_length: int = target_field_order.bit_length()

        match field_order_bit_length:
            case bits if bits <= 256:
                large_prime_p: int = number.getPrime(384)  # generate the large prime `p` with 256 * 1.5 bits
                hash_algo: str = hashlib.sha3_256().name
            case bits if 256 < bits <= 384:
                large_prime_p: int = number.getPrime(576)  # generate the large prime `p` with 384 * 1.5 bits
                hash_algo: str = hashlib.sha3_384().name
            case bits if 384 < bits <= 512:
                large_prime_p: int = number.getPrime(768)  # generate the large prime `p` with 512 * 1.5 bits
                hash_algo: str = hashlib.sha3_512().name
            case bits:  # bits > 512 (e.g., 521 bits for the NIST P-521 curve)
                large_prime_size_bits: int = math.ceil(bits * 1.5)
                large_prime_p: int = number.getPrime(large_prime_size_bits)
                hash_algo: str = hashlib.shake_256().name
                xof_hash_len: int = (bits + 7) // 8  # equiv.: `ceil(bits / 8)` (e.g., 521 bits -> 66 bytes or 528 bits)

                return cls(
                    target_field_order,
                    large_prime_p,
                    hash_algorithm=hash_algo,
                    xof_hash_digest_length=xof_hash_len,
                    domain_separation_tag=domain_separation_tag,
                    deterministic=deterministic
                )

        # For field orders with bit-length <= 512, use a cryptographic hash w/ a fixed-size hash output.
        return cls(
            target_field_order,
            large_prime_p,
            hash_algorithm=hash_algo,
            domain_separation_tag=domain_separation_tag,
            deterministic=deterministic
        )

    def reset(self) -> UniversalPrimeLengthHasher:
        self._hasher = None
        return self

    def is_reset(self) -> bool:
        return self._hasher is None

    def update(self, message: bytes) -> UniversalPrimeLengthHasher:
        # Lazily initialize hasher, to simplify invalid state detection re: digest(), intdigest() & hexdigest() methods.
        if self._hasher is None and self.xof_hash_length is None:
            self._hasher = hashlib.new(self.hash_algo)

            # Initialize hasher state with hash of a domain separation tag, if one was provided.
            if self.domain_separator:
                self._hasher.update(self.domain_separator.encode('utf-8'))
        elif self._hasher is None and self.xof_hash_length is not None:
            self._hasher = hashlib.shake_256()

            # Initialize hasher state with hash of a domain separation tag, if one was provided.
            if self.domain_separator:
                self._hasher.update(self.domain_separator.encode('utf-8'))

        self._hasher.update(message)

        return self

    def intdigest(self) -> int:
        if self._hasher is None:
            raise InvalidHasherStateException(
                f"Unable to produce {type(self).__name__} digest -- update(bytes) must be called at least once prior "
                f"to calling digest()."
            )

        if self.xof_hash_length is not None:
            full_hash_bytes: bytes = self._hasher.digest(self.xof_hash_length)
        else:
            full_hash_bytes: bytes = self._hasher.digest()

        self._hasher = None  # Reset hasher state after digesting.

        return UniversalPrimeLengthHasher._carter_wegman_hash(full_hash_bytes, self.q, self.p, self.deterministic)

    def digest(self) -> bytes:
        return number.long_to_bytes(self.intdigest())

    def hexdigest(self) -> str:
        return self.digest().hex()

    def hash_to_int(self, message: bytes) -> int:
        full_hash_bytes: bytes = self._hash_to_full_bytes(message)

        return UniversalPrimeLengthHasher._carter_wegman_hash(full_hash_bytes, self.q, self.p, self.deterministic)

    def hash(self, message: bytes) -> bytes:
        return number.long_to_bytes(self.hash_to_int(message))

    def hash_to_hex(self, message: bytes) -> str:
        return self.hash(message).hex()

    def _hash_to_full_bytes(self, message: bytes) -> bytes:
        # Initialize hasher or XOF state by hashing a domain separation tag, if one was provided.
        if self.domain_separator:
            if self.xof_hash_length is not None:
                xof = hashlib.shake_256(self.domain_separator.encode('utf-8') + message)
                full_hash_bytes: bytes = xof.digest(self.xof_hash_length)
            else:
                hasher = hashlib.new(self.hash_algo)
                hasher.update(self.domain_separator.encode('utf-8'))
                hasher.update(message)
                full_hash_bytes: bytes = hasher.digest()
        else:  # Otherwise, calculate hash in one shot.
            if self.xof_hash_length is not None:
                full_hash_bytes: bytes = hashlib.shake_256(message).digest(self.xof_hash_length)
            else:
                full_hash_bytes: bytes = hashlib.new(self.hash_algo, message).digest()

        return full_hash_bytes

    @staticmethod
    def _carter_wegman_hash(message_hash: bytes, q: int, p: int, deterministic: bool = False) -> int:
        """
        Produces a universal hash of the given message, which maps onto a prime-order field for a specified prime `q`,
        given an associated prime `p` greater than the size of the hash output of the configured cryptographic hash
        function, but with a recommended size for `p` being `ceil(1.5 * log2(q))` (e.g., `p ~ 2^384` for SHA3-256).

        This algorithm produces a value in the range `[0, q-1]` for the specified prime `q`, using the following
        formula: `H_q(H(x), p) = ((a * x + b) mod p) mod q`, where `a` and `b` are random integers in the range
        `[1, p-1]` if `deterministic=False`, and `x` is the message being hashed and H(x) is the output of the
        configured cryptographic hash with range [0, 2^n - 1] for an n-bit hash (e.g., [0, 2^256 - 1] for SHA3-256).
        If `deterministic=True`, the coefficients `a` and `b` are derived deterministically from the message hash,
        using the SHAKE-256 XOF hash function.

        :param message_hash: the cryptographic hash of the message being hashed to the target prime-order field.
        :param q: the order of the target field to which this universal hash output should map, which should be a prime
               number smaller than the size of the configured cryptographic hash algorithm's output.
        :param p: a prime number greater than the size of the configured cryptographic hash algorithm's output.
        :param deterministic: flag indicating whether to use coefficients derived deterministically, from the
               `message_hash` (i.e., using the SHAKE-256 XOF hash), for the Carter-Wegman universal hash construction.
        :return: a universal hash value, mapping onto the target prime-order field `F_q` (i.e., an integer in the range
                 `[0, q-1]`).
        """
        if deterministic:
            # Derive deterministic coefficients for reproducible hashes for the same message.
            coeff_a, coeff_b = UniversalPrimeLengthHasher._generate_coefficients_for_message_hash(message_hash, p)
        else:
            coeff_a: int = number.getRandomRange(1, p)  # generate random coefficient `a` in range [1, p-1]
            coeff_b: int = number.getRandomRange(1, p)  # generate random coefficient `b` in range [1, p-1]

        full_hash: int = number.bytes_to_long(message_hash)

        # Calculate the universal hash value, mapping onto the prime-order field `F_q`.
        return ((coeff_a * full_hash + coeff_b) % p) % q

    @staticmethod
    def _generate_coefficients_for_message_hash(message_hash: bytes, inner_modulus: int) -> tuple[int, int]:
        """
        Generates the coefficients `a` and `b` for the Carter-Wegman universal hash construction, using the provided
        message hash as a seed for deterministic generation with the SHAKE-256 XOF hash function.

        :param message_hash: the cryptographic hash of the message being hashed to the target prime-order field.
        :return: a tuple containing the random coefficients `a` and `b` for the Carter-Wegman universal hash construction.
        """
        inner_mod_size_bits: int = inner_modulus.bit_length()
        xof = hashlib.shake_256(message_hash)
        match inner_mod_size_bits:
            case bits if bits <= 256:
                xof_bytes: bytes = xof.digest(64)  # consume 32 + 32 = 64 bytes of XOF hash output
                coeff_a: int = number.bytes_to_long(xof_bytes[:32])
                coeff_b: int = number.bytes_to_long(xof_bytes[32:])
            case bits if 256 < bits <= 384:
                xof_bytes: bytes = xof.digest(96)  # consume 48 + 48 = 96 bytes of XOF hash output
                coeff_a: int = number.bytes_to_long(xof_bytes[:48])
                coeff_b: int = number.bytes_to_long(xof_bytes[48:])
            case bits if bits <= 512:
                xof_bytes: bytes = xof.digest(128)  # consume 64 + 64 = 128 bytes of XOF hash output
                coeff_a: int = number.bytes_to_long(xof_bytes[:64])
                coeff_b: int = number.bytes_to_long(xof_bytes[64:])
            case bits:
                inner_mod_size_bytes: int = (bits + 7) // 8  # equiv. to `ceil(bits / 8)`, but more efficient
                xof_bytes: bytes = xof.digest(inner_mod_size_bytes * 2)
                coeff_a: int = number.bytes_to_long(xof_bytes[:inner_mod_size_bytes])
                coeff_b: int = number.bytes_to_long(xof_bytes[inner_mod_size_bytes:])

        return coeff_a, coeff_b


class PrimeBasedTruncatedHasher(ReducedRangeHasher):
    """
    Hasher that produces a truncated cryptographic hash matching the bit-length of a specified prime, such as the prime
    corresponding to a prime-order field. Only the most-significant N bits are retained, where N is the bit-length of
    the given prime.

    Note: This technique is used by the ECDSA standard (NIST FIPS-186.5) for elliptic curve digital signatures,
    for example.

    Note: However, alternative techniques that map to the full range of a target prime-order field should be preferred,
    when compatibility with other cryptographic libraries implementing the aforementioned FIPS standard is not a
    requirement, in order to avoid the bias introduced by this truncation-based technique.

    This class supports the use of an optional domain separation tag, for ensuring hashing the same message in one
    domain produces a distinct hash when hashed in a different domain (e.g., a digital signature scheme vs. a
    zero-knowledge proof protocol).

    Note: This class is not thread-safe. (Use a thread-local for a hasher instance per thread, if needed in a
    multithreading context.)
    """
    DEFAULT_HASH_ALGO: str = hashlib.sha256().name

    hash_algo: str
    bit_length: int
    nontruncated_bit_length: int
    domain_separator: Optional[str]
    _hasher: Optional[Any] = None  # hasher as obtained via hashlib.new(hash_algo)

    def __init__(
            self,
            prime_for_length: int,
            hash_algorithm: str = DEFAULT_HASH_ALGO,
            domain_separation_tag: Optional[str] = None
    ):
        """
        Constructs a truncated hasher, based on the specified cryptographic hash algorithm and prime.

        :param prime_for_length: prime for determining the bit-length to be used for the truncated hashes produced,
               which must be less or equal in bit-length to the chosen hash algorithm's digest length in bits.
        :param hash_algorithm: cryptographic hash algorithm to be used for the truncated hashes produced.
        :param domain_separation_tag: domain separation tag to be used for ensuring distinct hashes from other uses of
               the configured cryptographic hash algorithm.
        :raises ValueError: if the provided cryptographic hash algorithm is not supported by the `hashlib` library; or
                if the provided prime has a bit-length larger than the chosen hash algorithm's digest size in bits; or
                if a domain separation tag is provided that's equal to the empty string (or only whitespace).
        """
        if hash_algorithm not in hashlib.algorithms_available:
            raise ValueError(f"Unsupported cryptographic hash algorithm: {hash_algorithm}")
        elif domain_separation_tag is not None and domain_separation_tag.strip() == "":
            raise ValueError("Domain separation tag (if provided) must not be an empty-string or only whitespace.")

        self.hash_algo: str = hash_algorithm
        self.domain_separator = domain_separation_tag

        self.bit_length: int = prime_for_length.bit_length()  # e.g., 17 is 5 bits in length

        full_hash_len_bytes: int = hashlib.new(self.hash_algo).digest_size
        self.nontruncated_bit_length: int = full_hash_len_bytes * 8

        # Disallow use of a prime w/ bit-length larger than the chosen hash algorithm.
        if self.bit_length > self.nontruncated_bit_length:
            raise ValueError(
                f"Unable to construct truncated hasher for prime with bit-length: {self.bit_length}, which is larger "
                f"than the specified '{self.hash_algo}' hash algorithm's digest size (bits): "
                f"{self.nontruncated_bit_length}"
            )

    def reset(self) -> PrimeBasedTruncatedHasher:
        self._hasher = None
        return self

    def is_reset(self) -> bool:
        return self._hasher is None

    def update(self, message: bytes) -> PrimeBasedTruncatedHasher:
        # Lazily initialize hasher, to simplify invalid state detection re: digest(), intdigest() & hexdigest() methods.
        if self._hasher is None:
            self._hasher = hashlib.new(self.hash_algo)

            # Initialize hasher state with hash of a domain separation tag, if one was provided.
            if self.domain_separator:
                self._hasher.update(self.domain_separator.encode('utf-8'))

        self._hasher.update(message)

        return self

    def intdigest(self) -> int:
        if self._hasher is None:
            raise InvalidHasherStateException(
                f"Unable to produce {type(self).__name__} integer digest -- update(bytes) must be called at least once "
                f"prior to calling intdigest()."
            )

        full_hash_bytes: bytes = self._hasher.digest()

        try:
            full_hash: int = number.bytes_to_long(full_hash_bytes)

            if self.bit_length < self.nontruncated_bit_length:
                # Truncate hash to bit-length (N) of configured prime, keeping most-significant N bits.
                return full_hash >> (self.nontruncated_bit_length - self.bit_length)
            else:
                return full_hash
        finally:
            self._hasher = None  # Reset hasher state after digesting.

    def digest(self) -> bytes:
        if self._hasher is None:
            raise InvalidHasherStateException(
                f"Unable to produce {type(self).__name__} digest -- update(bytes) must be called at least once prior "
                f"to calling digest()."
            )

        full_hash_bytes: bytes = self._hasher.digest()

        try:
            full_hash: int = number.bytes_to_long(full_hash_bytes)

            if self.bit_length < self.nontruncated_bit_length:
                # Truncate hash to bit-length of configured prime.
                truncated_hash: int = full_hash >> (self.nontruncated_bit_length - self.bit_length)
                return number.long_to_bytes(truncated_hash)
            else:
                return full_hash_bytes
        finally:
            self._hasher = None  # Reset hasher state after digesting.

    def hexdigest(self) -> str:
        return self.digest().hex()

    def hash_to_int(self, message: bytes) -> int:
        """
        Produces a cryptographic hash of the given message, which has been truncated to the bit-length (`N`) of a
        configured prime, by keeping the most-significant `N` bits via a right-shift operation, returning the truncated
        hash as an integer.

        :param message: a message to be hashed.
        :return: a truncated cryptographic hash with the bit-length of a configured prime, returned as an integer.
        """
        full_hash_bytes: bytes = self._hash_to_bytes_pretruncate(message)
        full_hash: int = number.bytes_to_long(full_hash_bytes)

        if self.bit_length < self.nontruncated_bit_length:
            # Truncate hash to bit-length (N) of configured prime, keeping most-significant N bits.
            return full_hash >> (self.nontruncated_bit_length - self.bit_length)
        else:
            return full_hash

    def hash(self, message: bytes) -> bytes:
        """
        Produces a cryptographic hash of the given message, which has been truncated to the bit-length (`N`) of a
        configured prime, by keeping the most-significant `N` bits via a right-shift operation.
        :param message: a message to be hashed.
        :return: a truncated cryptographic hash with the bit-length of a configured prime.
        """
        full_hash_bytes: bytes = self._hash_to_bytes_pretruncate(message)
        full_hash: int = number.bytes_to_long(full_hash_bytes)

        if self.bit_length < self.nontruncated_bit_length:
            # Truncate hash to bit-length of configured prime.
            truncated_hash: int = full_hash >> (self.nontruncated_bit_length - self.bit_length)
            return number.long_to_bytes(truncated_hash)
        else:
            return full_hash_bytes

    def hash_to_hex(self, message: bytes) -> str:
        return self.hash(message).hex()

    def _hash_to_bytes_pretruncate(self, message: bytes) -> bytes:
        # Initialize hasher state with hash of a domain separation tag, if one was provided.
        if self.domain_separator:
            hasher = hashlib.new(self.hash_algo)
            hasher.update(self.domain_separator.encode('utf-8'))
            hasher.update(message)
            full_hash_bytes: bytes = hasher.digest()
        else:
            # Otherwise, calculate hash in one shot.
            full_hash_bytes: bytes = hashlib.new(self.hash_algo, message).digest()

        return full_hash_bytes
