"""
Tools for producing, revealing & verifying keyed hash-based cryptographic commitments, including HMAC-based and
Blake2b keyed hash-based commitments.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac

from typing import Union, NewType

import attrs

from Cryptodome import Random

from scriptless_zkp import STRING_ENCODING_FIELD_DELIMITER

"""
Efficient type for binary commitments that will auto-cast to `bytes`, but not from `bytes`, providing type safety in
function & method calls.
"""
BinaryCommitment = NewType('BinaryCommitment', bytes)


class KeyedHashCommitmentUtils:
    DEFAULT_HASH_ALGORITHM: str = "sha3_256"
    DEFAULT_BLAKE2B_LENGTH: int = 32
    STRING_ENCODING_DELIMITER: str = STRING_ENCODING_FIELD_DELIMITER

    def __init__(self, hash_algorithm: str = DEFAULT_HASH_ALGORITHM):
        self.hash_algo = hash_algorithm

    def commit(
            self,
            secret_message: Union[bytes, bytearray]
    ) -> (KeyedHashCommitment, RevealedKeyedHashCommitment):
        """
        Produces a keyed hash-based commitment for the given secret message, using a random ephemeral key.
        :param secret_message: secret message to which to commit.
        :return: a keyed hash-based commitment for the given secret message, along with the associated revealed
                 commitment.
        """
        commitment_mac: BinaryCommitment
        ephemeral_key: bytearray
        # Create a commitment to the provided secret message as a keyed hash.
        commitment_mac, ephemeral_key = self._generate_keyed_hash(secret_message)

        return (
            KeyedHashCommitment(commitment_mac, self.hash_algo),
            RevealedKeyedHashCommitment(secret_message, ephemeral_key, self.hash_algo)
        )

    def reveal(
            self,
            secret_message: Union[bytes, bytearray],
            ephemeral_key: bytearray
    ) -> RevealedKeyedHashCommitment:
        """
        Produces a revealed commitment, given the original secret message and a commitment's random ephemeral key.
        :param secret_message: the original secret message to which the commitment is made.
        :param ephemeral_key: the random ephemeral key that was used to produce the commitment.
        :return: a revealed commitment, which includes the committed to secret message, the commitment's associated
                 random ephemeral key, and the commitment itself (recalculated from this message & key).
        """
        return RevealedKeyedHashCommitment(secret_message, ephemeral_key, self.hash_algo)

    def verify_revealed(
            self,
            commitment: BinaryCommitment,
            secret_message: Union[bytes, bytearray],
            ephemeral_key: bytearray
    ) -> bool:
        """
        Verifies that the provided commitment is valid, given the revealed original secret message and the commitment's
        random ephemeral key.
        :param commitment: keyed hash-based commitment to verify.
        :param secret_message: the revealed original secret message to which the provided commitment was made.
        :param ephemeral_key: the revealed random ephemeral key that was used to produce the provided keyed-hash
               commitment.
        :return: whether the provided keyed-hash commitment is valid, given the revealed original secret message and
                 ephemeral key.
        """
        expected_commitment: BinaryCommitment = self._create_keyed_hash(secret_message, ephemeral_key)

        return hmac.compare_digest(commitment, expected_commitment)

    def _generate_keyed_hash(self, secret_message: Union[bytes, bytearray]) -> (BinaryCommitment, bytearray):
        """
        <p>
        Generates a random ephemeral key equal to the configured hash algorithm's digest size, and produces a
        keyed hash for the provided secret message using this ephemeral key, returning this keyed hash & ephemeral
        key.</p><p>
        If Blake2b was specified, then its built-in support for keyed hashes is used, which is inherently
        invulnerable to length extension attacks. Otherwise, HMAC is used for other cryptographic hash algorithms
        (e.g., SHA-256 or SHA3-256), which is invulnerable to length extension attacks regardless of the choice of
        cryptographic hash used.</p>
        :param secret_message: secret message for which to produce a keyed hash.
        :return: a keyed hash of the provided secret message and the random ephemeral key that was used.
        """
        if self.hash_algo == hashlib.blake2b.name:
            ephemeral_key: bytearray = bytearray(Random.get_random_bytes(self.DEFAULT_BLAKE2B_LENGTH))
            # Use Blake2b's built-in support for secure keyed hashes.
            hasher = hashlib.blake2b(key=ephemeral_key, digest_size=self.DEFAULT_BLAKE2B_LENGTH)
            hasher.update(secret_message)

            return BinaryCommitment(hasher.digest()), ephemeral_key
        else:
            hash_digest_size: int = hashlib.new(self.hash_algo).digest_size
            ephemeral_key: bytearray = bytearray(Random.get_random_bytes(hash_digest_size))
            # Create a secure keyed hash using HMAC.
            hmac_hasher: hmac.HMAC = hmac.new(key=ephemeral_key, msg=secret_message, digestmod=self.hash_algo)

            return BinaryCommitment(hmac_hasher.digest()), ephemeral_key

    def _create_keyed_hash(self, secret_message: Union[bytes, bytearray], ephemeral_key: bytearray) -> BinaryCommitment:
        """
        Creates a keyed hash for the given secret message & ephemeral key. Uses either Blake2b's built-in support
        for secure keyed hashes, or HMAC for other cryptographic hash algorithms.
        :param secret_message: secret message for which to produce a keyed hash.
        :param ephemeral_key: random ephemeral key used to produce the keyed-hash (i.e., commitment).
        :raises ValueError if the configured hash algorithm is unsupported.
        """
        if self.hash_algo == hashlib.blake2b.name:
            # Use Blake2b's built-in support for secure keyed hashes.
            hasher = hashlib.blake2b(key=ephemeral_key, digest_size=self.DEFAULT_BLAKE2B_LENGTH)
            hasher.update(secret_message)

            return BinaryCommitment(hasher.digest())
        else:
            # Create a secure keyed hash using HMAC.
            hmac_hasher: hmac.HMAC = hmac.new(key=ephemeral_key, msg=secret_message, digestmod=self.hash_algo)

            return BinaryCommitment(hmac_hasher.digest())


@attrs.define(slots=True, frozen=True)
class KeyedHashCommitment:
    commitment: BinaryCommitment
    hash_algorithm: str = KeyedHashCommitmentUtils.DEFAULT_HASH_ALGORITHM

    def reveal(
            self,
            secret_message: Union[bytes, bytearray],
            ephemeral_key: bytearray
    ) -> RevealedKeyedHashCommitment:
        return KeyedHashCommitmentUtils(self.hash_algorithm).reveal(
            secret_message, ephemeral_key
        )

    @classmethod
    def from_string_encoding(cls, string_encoding: str) -> KeyedHashCommitment:
        """
        Creates a `KeyedHashCommitment` constructed from the provided string encoding.
        :param string_encoding: string encoding of the `KeyedHashCommitment`.
        :return: a KeyedHashCommitment constructed from the provided string encoding.
        """
        # noinspection PyPep8Naming
        EXPECTED_FIELDS_COUNT: int = 2

        commitment_fields: list[str] = string_encoding.split(KeyedHashCommitmentUtils.STRING_ENCODING_DELIMITER)
        if len(commitment_fields) != EXPECTED_FIELDS_COUNT:
            raise ValueError(
                f"Invalid string encoding of keyed-hash commitment -- expected [{EXPECTED_FIELDS_COUNT}] fields, but "
                f"found [{len(commitment_fields)}]."
            )

        try:
            commitment_bytes: bytes = base64.b64decode(commitment_fields[0], validate=True)
        except binascii.Error as bae:
            raise ValueError(
                f"Invalid string encoding of keyed-hash commitment -- failed to decode the base64-encoded commitment: "
                f"{bae}"
            ) from bae

        return KeyedHashCommitment(
            BinaryCommitment(commitment_bytes),
            commitment_fields[1]
        )

    def encode_as_string(self) -> str:
        """
        Encodes this `KeyedHashCommitment` as a string (e.g., for storage or transmission), using base64-encoding for
        the binary commitment.
        :return: this `KeyedHashCommitment` encoded as a string.
        """
        return KeyedHashCommitmentUtils.STRING_ENCODING_DELIMITER.join([
            base64.b64encode(self.commitment).decode('utf-8'),
            self.hash_algorithm
        ])


@attrs.define(slots=True)
class RevealedKeyedHashCommitment:
    secret_message: Union[bytes, bytearray]
    verification_key: bytearray  # ephemeral commitment key
    hash_algorithm: str = KeyedHashCommitmentUtils.DEFAULT_HASH_ALGORITHM
    _destroyed: bool = False

    def verify(self, commitment: BinaryCommitment) -> bool:
        return KeyedHashCommitmentUtils(self.hash_algorithm).verify_revealed(
            commitment, self.secret_message, self.verification_key
        )

    def destroy(self) -> None:
        """Clears (i.e., zeroes out) the secret message & ephemeral key in memory."""
        self.verification_key.zfill(len(self.verification_key))
        if self.secret_message is bytearray:
            self.secret_message.zfill(len(self.secret_message))
        self._destroyed = True

    def is_destroyed(self) -> bool:
        return self._destroyed
