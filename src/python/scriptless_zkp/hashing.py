"""
Modified cryptographic hashing for use with prime-order fields.
"""
from __future__ import annotations

import hashlib

from Cryptodome.Util import number

from scriptless_zkp.exceptions import InvalidHasherStateException


class PrimeLengthTruncatedHasher:
    """
    Hasher that produces a truncated cryptographic hash matching the bit-length of a specified prime, such as the prime
    corresponding to a prime-order field. Only the most-significant N bits are retained, where N is the bit-length of
    the given prime.
    Note: This class is not thread-safe.
    """
    DEFAULT_HASH_ALGO: str = hashlib.sha256().name

    def __init__(self, prime_for_length: int, hash_algorithm: str = DEFAULT_HASH_ALGO):
        """
        Constructs a truncated hasher, based on the specified cryptographic hash algorithm and prime.

        :param prime_for_length: prime for determining the bit-length to be used for the truncated hashes produced,
               which must be less or equal in bit-length to the chosen hash algorithm's digest length in bits.
        :param hash_algorithm: cryptographic hash algorithm to be used for the truncated hashes produced.
        :raises ValueError: if the provided hash algorithm is not supported by hashlib; or the provided prime has a
                bit-length larger than the chosen hash algorithm's digest size in bits.
        """
        self.hash_algo: str = hash_algorithm

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

        self._hasher = None

    def update(self, message: bytes) -> PrimeLengthTruncatedHasher:
        if self._hasher is None:
            self._hasher = hashlib.new(self.hash_algo)

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
        full_hash_bytes: bytes = hashlib.new(self.hash_algo, message).digest()
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
        full_hash_bytes: bytes = hashlib.new(self.hash_algo, message).digest()
        full_hash: int = number.bytes_to_long(full_hash_bytes)

        if self.bit_length < self.nontruncated_bit_length:
            # Truncate hash to bit-length of configured prime.
            truncated_hash: int = full_hash >> (self.nontruncated_bit_length - self.bit_length)
            return number.long_to_bytes(truncated_hash)
        else:
            return full_hash_bytes

    def hash_to_hex(self, message: bytes) -> str:
        return self.hash(message).hex()
