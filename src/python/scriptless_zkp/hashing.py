"""
Modified cryptographic hashing for use with prime-order fields.
"""
from __future__ import annotations

import hashlib

from typing import Optional, Any

from Cryptodome.Util import number

from scriptless_zkp.exceptions import InvalidHasherStateException


class PrimeLengthTruncatedHasher:
    """
    Hasher that produces a truncated cryptographic hash matching the bit-length of a specified prime, such as the prime
    corresponding to a prime-order field. Only the most-significant N bits are retained, where N is the bit-length of
    the given prime.

    Note: This technique is used by the ECDSA standard (NIST FIPS-186.5) for elliptic curve digital signatures,
    for example.

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
        :raises ValueError: if the provided hash algorithm is not supported by hashlib; or the provided prime has a
                bit-length larger than the chosen hash algorithm's digest size in bits.
        """
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

    def update(self, message: bytes) -> PrimeLengthTruncatedHasher:
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
        full_hash: int = number.bytes_to_long(full_hash_bytes)

        if self.bit_length < self.nontruncated_bit_length:
            # Truncate hash to bit-length (N) of configured prime, keeping most-significant N bits.
            return full_hash >> (self.nontruncated_bit_length - self.bit_length)
        else:
            return full_hash

    def digest(self) -> bytes:
        if self._hasher is None:
            raise InvalidHasherStateException(
                f"Unable to produce {type(self).__name__} digest -- update(bytes) must be called at least once prior "
                f"to calling digest()."
            )

        full_hash_bytes: bytes = self._hasher.digest()
        full_hash: int = number.bytes_to_long(full_hash_bytes)

        if self.bit_length < self.nontruncated_bit_length:
            # Truncate hash to bit-length of configured prime.
            truncated_hash: int = full_hash >> (self.nontruncated_bit_length - self.bit_length)
            return number.long_to_bytes(truncated_hash)
        else:
            return full_hash_bytes

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
