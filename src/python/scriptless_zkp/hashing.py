"""
Modified cryptographic hashing for use with prime-order fields.
"""
from __future__ import annotations

import hashlib

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

    Note: As the Carter-Wegman universal hash construction uses random coefficients `a` and `b` for producing a
    universal hash function, the cryptographic hashes produced by this class are non-deterministic. So, if repeatable,
    deterministic hash outputs are needed (i.e., for the same message), such as for the deterministic ECDSA digital
    signatures variant, then a different approach should be used.

    Note: This class is not thread-safe. (Use a thread-local for a hasher instance per thread, if needed in a
    multithreading context.)
    """
    DEFAULT_HASH_ALGO: str = hashlib.sha3_256().name

    q: int
    p: int
    hash_algo: str
    domain_separator: Optional[str]
    _hasher: Optional[Any] = None  # cryptographic hasher as obtained via hashlib.new(hash_algo)

    def __init__(
            self,
            target_field_order: int,
            larger_prime_p: int,
            hash_algorithm: str = DEFAULT_HASH_ALGO,
            domain_separation_tag: Optional[str] = None
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
        :param domain_separation_tag: optional domain separation tag to be used for ensuring distinct hashes from other
               uses of the configured cryptographic hash algorithm.
        :raises ValueError: if the provided cryptographic hash algorithm is not supported by the `hashlib` library; or
                if a domain separation tag is provided that's equal to the empty string (or only whitespace).
        """
        if hash_algorithm not in hashlib.algorithms_available:
            raise ValueError(f"Unsupported cryptographic hash algorithm: {hash_algorithm}")
        elif domain_separation_tag is not None and domain_separation_tag.strip() == "":
            raise ValueError("Domain separation tag (if provided) must not be an empty-string or only whitespace.")

        self.q = target_field_order
        self.p = larger_prime_p
        self.hash_algo = hash_algorithm
        self.domain_separator = domain_separation_tag

    def update(self, message: bytes) -> UniversalPrimeLengthHasher:
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
                f"Unable to produce {type(self).__name__} digest -- update(bytes) must be called at least once prior "
                f"to calling digest()."
            )

        full_hash_bytes: bytes = self._hasher.digest()
        self._hasher = None  # Reset hasher state after digesting.

        return self._carter_wegman_hash(full_hash_bytes, self.q, self.p)

    def digest(self) -> bytes:
        return number.long_to_bytes(self.intdigest())

    def hexdigest(self) -> str:
        return self.digest().hex()

    def hash_to_int(self, message: bytes) -> int:
        full_hash_bytes: bytes = self._hash_to_full_bytes(message)

        return self._carter_wegman_hash(full_hash_bytes, self.q, self.p)

    def hash(self, message: bytes) -> bytes:
        return number.long_to_bytes(self.hash_to_int(message))

    def hash_to_hex(self, message: bytes) -> str:
        return self.hash(message).hex()

    def _hash_to_full_bytes(self, message: bytes) -> bytes:
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

    def _carter_wegman_hash(self, message_hash: bytes, q: int, p: int) -> int:
        """
        Produces a universal hash of the given message, which maps onto a prime-order field for a specified prime `q`,
        given an associated prime `p` greater than the size of the hash output of the configured cryptographic hash
        function (e.g., `p > 2^256` for SHA-256 or SHA3-256).

        This algorithm produces a value in the range `[0, q-1]` for the specified prime `q`, using the following
        formula: `H_q(H(x), p) = ((a * x + b) mod p) mod q`, where `a` and `b` are random integers in the range
        `[1, p-1]`, and `x` is the message being hashed and H(x) is the output of the configured cryptographic hash
        with range [0, 2^n - 1] for some n (e.g., [0, 2^256 - 1] for SHA-256 or SHA3-256).

        :param message_hash: the cryptographic hash of the message being hashed to the target prime-order field.
        :param q: the order of the target field to which this universal hash output should map, which should be a prime
               number smaller than the size of the configured cryptographic hash algorithm's output.
        :param p: a prime number greater than the size of the configured cryptographic hash algorithm's output.
        :return: a universal hash value, mapping onto the target prime-order field `F_q` (i.e., an integer in the range
                 `[0, q-1]`).
        """
        full_hash: int = number.bytes_to_long(message_hash)
        coeff_a: int = number.getRandomRange(1, p)  # generate random coefficient `a` in range [1, p-1]
        coeff_b: int = number.getRandomRange(1, p)  # generate random coefficient `b` in range [1, p-1]

        # Calculate the universal hash value, mapping onto the prime-order field `q`.
        return ((coeff_a * full_hash + coeff_b) % p) % q


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
