"""
Classes providing support for ECC Schnorr digital signatures.
"""
from __future__ import annotations

import base64
import binascii
import hashlib

from typing import Optional

from Cryptodome.PublicKey import ECC
from Cryptodome.Util import number

from scriptless_zkp import STRING_ENCODING_FIELD_DELIMITER
from scriptless_zkp.ecc import (
    OWASP_PBKDF2_SHA1_ITERATIONS, DEFAULT_ECC_PRIVATE_KEY_PKCS8_KDF,
    PKCS8_ECC_KDF_PBKDF2_SHA1_AES128_CBC, PKCS8_ECC_KDF_PBKDF2_SHA1_AES192_CBC, PKCS8_ECC_KDF_PBKDF2_SHA1_AES256_CBC,
    DEFAULT_ECC_PRIVATE_KEY_ENCODING_METHOD, DEFAULT_PKCS8_HMAC_SHA1_SALT_BYTES, MIN_PKCS8_PASSPHRASE_LENGTH,
    DEFAULT_ECC_POINT_ENCODING_METHOD
)
from scriptless_zkp.ecc.ecc_utils import WeierstrassEllipticCurveConfig
from scriptless_zkp.ecc.ecc_exceptions import InvalidECCPublicKeyException, IncorrectECCSchnorrSignatureCurveException
from scriptless_zkp.hashing import PrimeLengthTruncatedHasher


class SchnorrContext:
    """
    Configuration parameters for ECC Schnorr digital signatures, including ECC parameters and message hash algorithm.
    """
    DEFAULT_HASH_ALGO: str = hashlib.sha256().name  # Note: 256-bit hash req'd for 256-bit ECC curves.

    ecc_curve_config: WeierstrassEllipticCurveConfig
    q: int
    message_hash_algo: str
    message_hash_length: int

    def __init__(
            self,
            ecc_curve_config: WeierstrassEllipticCurveConfig,
            message_hash_algorithm: str = DEFAULT_HASH_ALGO
    ):
        self.ecc_curve_config: WeierstrassEllipticCurveConfig = ecc_curve_config
        self.q: int = self.ecc_curve_config.order
        self.message_hash_algo: str = message_hash_algorithm
        self.message_hash_length: int = hashlib.new(self.message_hash_algo).digest_size

    @staticmethod
    def encode_public_key(public_key: ECC.EccKey) -> bytes:
        if public_key.has_private():
            return public_key.public_key().export_key(format='SEC1')
        else:
            return public_key.export_key(format='SEC1')

    def encode_ecc_point(self, ecc_point: ECC.EccPoint) -> bytes:
        return self.ecc_point_to_pubkey(ecc_point).export_key(format='SEC1')

    def ecc_point_to_pubkey(self, ecc_point: ECC.EccPoint) -> ECC.EccKey:
        return ECC.construct(curve=self.ecc_curve_config.curve, point_x=ecc_point.x, point_y=ecc_point.y)

    def generate_key_pair(self) -> ECC.EccKey:
        return ECC.generate(curve=self.ecc_curve_config.curve)


class SchnorrKeyPair:
    ecc_key_pair: ECC.EccKey
    context: SchnorrContext

    def __init__(self, context: SchnorrContext, ecc_key_pair: ECC.EccKey):
        # Checks for arguments' validity:
        if not context.ecc_curve_config.has_curve_name(ecc_key_pair.curve):
            raise ValueError(
                f"The ECC Schnorr public key's elliptic curve: '{ecc_key_pair.curve}' must match that of the provided "
                f"ECC Schnorr context: '{context.ecc_curve_config.curve}'"
            )
        if not ecc_key_pair.has_private():
            raise ValueError("No ECC Schnorr private key was provided.")
        if ecc_key_pair.pointQ.is_point_at_infinity():
            raise ValueError(
                f"The provided ECC Schnorr public key is invalid, as it equals the configured elliptic curve's "
                f"Point-at-Infinity [ecc_curve='{context.ecc_curve_config.curve}']"
            )

        self.context = context
        self.ecc_key_pair = ecc_key_pair

    @classmethod
    def generate(cls, context: SchnorrContext) -> SchnorrKeyPair:
        ecc_key_pair: ECC.EccKey = context.generate_key_pair()

        return SchnorrKeyPair(context, ecc_key_pair)

    @classmethod
    def import_private_key(
            cls,
            context: SchnorrContext,
            encoded_ecc_private_key: bytes,
            encryption_passphrase: bytes | str | None
    ) -> SchnorrKeyPair:
        """
        Returns an ECC Schnorr key-pair constructed from an ECC private key, imported from a PKCS#8-wrapped DER-encoded
        byte string, which has been decrypted using the provided passphrase and a password-based key derivation function
        (KDF), indicated in the DER encoding of the ECC private key.
        :param context: Schnorr signature parameters including ECC curve configuration.
        :param encoded_ecc_private_key: a PKCS#8-wrapped DER-encoded encrypted ECC private key.
        :param encryption_passphrase: an encryption passphrase to use for PKCS#8 key-wrap encryption of the key-pair's
               ECC private key (provided as a string, byte string or byte-array).
        :return: an ECC Schnorr key-pair imported from a PKCS#8-wrapped DER-encoded byte string encoding of an ECC
                 private key, which has been decrypted using the provided passphrase.
        """
        if encryption_passphrase is str:
            passphrase: bytes = encryption_passphrase.encode(encoding='utf-8')
        else:
            passphrase: Optional[bytes] = encryption_passphrase

        ecc_key_pair: ECC.EccKey = ECC.import_key(
            encoded=encoded_ecc_private_key,
            passphrase=passphrase  # Allowed types: bytes | str | None
        )
        return SchnorrKeyPair(context, ecc_key_pair)

    @property
    def public_key(self) -> SchnorrPublicKey:
        return SchnorrPublicKey(self.context, self.ecc_key_pair.public_key())

    def export_private_key(
            self,
            encryption_passphrase: bytes | str,
            encryption_method: str = DEFAULT_ECC_PRIVATE_KEY_PKCS8_KDF
    ) -> bytes:
        """
        Returns a PKCS#8-wrapped private key as a DER-encoded byte string, which has been encrypted using the provided
        passphrase & the indicated password-based key-derivation function (PBKDF2 w/ HMAC-SHA1/AES-128-CBC by default).
        :param encryption_passphrase: an encryption passphrase to use for PKCS#8 key-wrap encryption of the key-pair's
               ECC private key (provided as a string, byte string or byte-array). Must be at least 8 characters/bytes
               in length.
        :param encryption_method: PKCS#8 key-wrap encryption method (PBKDF2 w/ HMAC-SHA1/AES-128-CBC by default).
        :return: a PKCS#8-wrapped private key as a DER-encoded byte string, encrypted using a key derived from the
                 provided passphrase, using the indicated password-based KDF (PBKDF2 by default).
        """
        supported_PBKDF2_key_wrap_variants: list[str] = [
            PKCS8_ECC_KDF_PBKDF2_SHA1_AES128_CBC,
            PKCS8_ECC_KDF_PBKDF2_SHA1_AES192_CBC,
            PKCS8_ECC_KDF_PBKDF2_SHA1_AES256_CBC
        ]

        if encryption_passphrase is str:
            passphrase: bytes = encryption_passphrase.encode(encoding='utf-8')
        else:
            passphrase: bytes = encryption_passphrase

        if len(passphrase) < MIN_PKCS8_PASSPHRASE_LENGTH:
            raise ValueError(
                f"Encryption passphrase for export of ECC Schnorr private key must be at least "
                f"[{MIN_PKCS8_PASSPHRASE_LENGTH}] bytes in length [passphrase_length={len(passphrase)}]"
            )

        if encryption_method in supported_PBKDF2_key_wrap_variants:
            # PBKDF2 parameters used for PKCS#8-based key-wrap encryption.
            pbkdf2_params: dict[str, int] = {
                'iteration_count': OWASP_PBKDF2_SHA1_ITERATIONS,  # KDF iterations for PKCS#8 key-wrap encryption
                'salt_size': DEFAULT_PKCS8_HMAC_SHA1_SALT_BYTES   # size of random salt for use by KDF
            }

            # noinspection PyTypeChecker
            return self.ecc_key_pair.export_key(
                format=DEFAULT_ECC_PRIVATE_KEY_ENCODING_METHOD,  # 'DER'
                compress=True,
                passphrase=passphrase,         # passphrase for PKCS#8 key-wrap encryption of private key
                protection=encryption_method,  # password-based KDF & variant for PKCS#8 key-wrap encryption
                use_pkcs8=True,                # wrap private key in PKCS#8 envelope
                # PKCS#8 parameters (passed to Crypto.IO.PKCS8.wrap(...):
                prot_params=pbkdf2_params  # PKCS#8 parameters, passed to Crypto.IO.PKCS8.wrap(...)
            )
        # TODO: Add support for using the scrypt KDF variants for PKCS#8 key-wrap encryption (supported by
        #   PyCryptodome), which are more resistant to dedicated hardware & GPU-based attacks.
        else:
            raise ValueError(
                f"Unsupported ECC Schnorr private key encryption KDF provided for export: '{encryption_method}' "
                f"-- Supported KDFs are PBKDF2 with HMAC/SHA-1 variants "
                f"[supported_KDFs={supported_PBKDF2_key_wrap_variants}]"
            )

    def sign(self, message: bytes) -> SchnorrSignature:
        """
        Returns a Schnorr signature for the provided message, constructed using the key-pair's private key.
        <p>
        Using a random nonce `r` & associated nonce point `R`, the ECC Schnorr signature over message `m` is calculated
        for public/private key-pair `(Q, x)` and ECC group `<G>` (i.e., the group generated by ECC "base" point `G`)
        order `q` as:
            `s := r + H(Q || R || m)*x mod q`,

        where `H(...)` is a cryptographic hash function truncated to the bit-length of ECC group order `q`, and `||`
        indicates byte-string concatenation.
        <p>
        The complete ECC Schnorr signature is then the tuple: `(R, s)`
        :param message: a message to sign, provided as a byte string.
        :return: a Schnorr signature for the provided message, constructed using the key-pair's private key.
        """
        while True:  # do-while construct
            random_nonce_pair: ECC.EccKey = ECC.generate(curve=self.context.ecc_curve_config.curve)
            if not random_nonce_pair.pointQ.is_point_at_infinity():
                break

        random_nonce: int = int(random_nonce_pair.d)                 # random nonce: `r`
        random_nonce_point: ECC.EccPoint = random_nonce_pair.pointQ  # nonce point: `R := r*G`

        hasher = PrimeLengthTruncatedHasher(self.context.q, self.context.message_hash_algo)
        hash_e: int = hasher.update(                           # hash: `e := H(Q || R || m)`
            self.context.encode_public_key(self.ecc_key_pair)  # public key point `Q := x*G` encoded ('SEC1')
        ).update(
            self.context.encode_ecc_point(random_nonce_point)  # nonce point `R` encoded ('SEC1')
        ).update(message).intdigest()

        signature: int = (random_nonce + hash_e * int(self.ecc_key_pair.d)) % self.context.q

        return SchnorrSignature(self.context, random_nonce_point, signature)


class SchnorrPublicKey:
    public_ecc_key: ECC.EccKey
    context: SchnorrContext

    def __init__(self, context: SchnorrContext, public_ecc_key: ECC.EccKey):
        # Checks for arguments' validity:
        if not context.ecc_curve_config.has_curve_name(public_ecc_key.curve):
            raise ValueError(
                f"The ECC Schnorr public key's elliptic curve: '{public_ecc_key.curve}' must match that of the provided"
                f" ECC Schnorr context: '{context.ecc_curve_config.curve}'"
            )
        if public_ecc_key.has_private():
            raise ValueError(
                "An ECC Schnorr private key should not be provided, when constructing an ECC Schnorr public key."
            )
        if public_ecc_key.pointQ.is_point_at_infinity():
            raise ValueError(
                f"The provided ECC Schnorr public key is invalid, as it equals the configured elliptic curve's "
                f"Point-at-Infinity [ecc_curve='{context.ecc_curve_config.curve}']"
            )

        self.context = context
        self.public_ecc_key = public_ecc_key

    @classmethod
    def import_key(cls, context: SchnorrContext, encoded_ecc_public_key: bytes) -> SchnorrPublicKey:
        try:
            public_ecc_key: ECC.EccKey = ECC.import_key(
                encoded_ecc_public_key,
                curve_name=context.ecc_curve_config.curve
            )
        except ValueError as ve:
            raise InvalidECCPublicKeyException(
                f"Unable to decode ECC Schnorr public key from encoded ECC point -- Invalid ECC point encoding or point"
                f" not on expected elliptic curve [curve={context.ecc_curve_config.curve}, "
                f"expected_encoding={DEFAULT_ECC_POINT_ENCODING_METHOD}]"
            ) from ve

        if not public_ecc_key.pointQ.is_point_at_infinity():
            return SchnorrPublicKey(context, public_ecc_key)
        else:
            raise InvalidECCPublicKeyException(
                f"Decoded ECC Schnorr public key is invalid -- ECC point equals the Point-at-Infinity "
                f"[curve={context.ecc_curve_config.curve}]"
            )

    def export_key(self, compress_pubkey_point: bool = True) -> bytes:
        return self.public_ecc_key.export_key(format=DEFAULT_ECC_POINT_ENCODING_METHOD, compress=compress_pubkey_point)

    def verify_signature(self, schnorr_signature: SchnorrSignature, message: bytes) -> bool:
        # Ensure ECC Schnorr signature was constructed on the same ECC curve as the provided joint public key.
        if schnorr_signature.context.ecc_curve_config != self.context.ecc_curve_config:
            raise IncorrectECCSchnorrSignatureCurveException(
                schnorr_signature.context.ecc_curve_config.curve,
                self.context.ecc_curve_config.curve,
                "ECC Schnorr signature was constructed on a different ECC curve than the joint public key provided for"
                " verification"
            )

        # Calculate the ECC point associated with the signature (integer) value (i.e., "s*G"), using the base point (G).
        signature_point: ECC.EccPoint = self.context.ecc_curve_config.base_point * schnorr_signature.signature

        # Encode the public key, using SEC1 encoding.
        pubkey_bytes: bytes = self.context.encode_public_key(self.public_ecc_key)
        # Encode the signature's nonce point, using SEC1 encoding.
        signature_nonce_point_bytes: bytes = self.context.encode_ecc_point(schnorr_signature.public_nonce)

        # Calculate the truncated hash "e := H(Q || R || m)" of the public key, the signature's public nonce point &
        # the message associated with the Schnorr signature (truncated to the ECC curve's bit-length).
        truncated_hasher = PrimeLengthTruncatedHasher(
            self.context.ecc_curve_config.order,
            self.context.message_hash_algo
        )
        pubkey_nonce_message_hash: int = truncated_hasher.hash_to_int(
            pubkey_bytes + signature_nonce_point_bytes + message  # concatenate bytes ("Q || R || m")
        )

        # Calculate the full verification point "R + e*Q", where R is the signature's public nonce point, e is the hash
        # calculated above, and Q is the public key (ECC point).
        verification_point: ECC.EccPoint = schnorr_signature.public_nonce + (
                self.public_ecc_key.pointQ * pubkey_nonce_message_hash
        )

        return signature_point == verification_point


class SchnorrSignature:
    """
    Represents an ECC Schnorr digital signature. Supports encoding/decoding to/from a base64-based string encoding of
    an ECC Schnorr digital signature's (R,s) tuple (i.e., random nonce ECC point & signature value).
    """
    context: SchnorrContext
    public_nonce: ECC.EccPoint
    signature: int

    def __init__(self, context: SchnorrContext, nonce_point: ECC.EccPoint, signature: int):
        self.context = context
        self.public_nonce = nonce_point
        self.signature = signature

    @classmethod
    def from_string_encoding(
            cls,
            encoded_schnorr_signature: str,
            context: SchnorrContext
    ) -> SchnorrSignature:
        """
        Reconstructs an ECC Schnorr digital signature from its string encoding ("nonce_point_SEC1_base64:sig_base64").
        :param context: Schnorr signature parameters including ECC curve configuration.
        :param encoded_schnorr_signature: string encoded Schnorr digital signature.
        :return: an ECC Schnorr digital signature reconstructed from its string encoding.
        """
        EXPECTED_FIELDS_COUNT = 2

        encoded_signature_fields: list[str] = encoded_schnorr_signature.split(STRING_ENCODING_FIELD_DELIMITER)
        if len(encoded_signature_fields) != EXPECTED_FIELDS_COUNT:
            raise ValueError(
                f"Unexpected number of fields [{len(encoded_signature_fields)}] in string encoding of {cls.__name__} "
                f"[expected_fields_count={EXPECTED_FIELDS_COUNT}]"
            )

        try:
            public_nonce: ECC.EccPoint = ECC.import_key(
                base64.b64decode(encoded_signature_fields[0], validate=True),
                curve_name=context.ecc_curve_config.curve
            ).pointQ
        except binascii.Error as bae:
            raise ValueError(
                f"Invalid base64-encoded Schnorr signature public nonce ECC point in string encoding of {cls.__name__} "
                f"-- caused by: {bae}"
            ) from bae  # include base64 decoding exception cause
        except ValueError as ve:
            raise ValueError(
                f"Invalid 'SEC1' public key-encoded Schnorr signature public nonce ECC point, in string encoding of "
                f"{cls.__name__} -- caused by: {ve}"
            ) from ve  # include 'SEC1' public key decoding exception cause

        try:
            signature_bytes: bytes = base64.b64decode(encoded_signature_fields[1], validate=True)
            signature: int = number.bytes_to_long(signature_bytes)
        except binascii.Error as bae:
            raise ValueError(
                f"Invalid base64-encoded Schnorr signature value in string encoding of {cls.__name__}"
                f" -- caused by: {bae}"
            ) from bae  # include base64 decoding exception cause

        return SchnorrSignature(context, public_nonce, signature)

    def encode_as_string(self) -> str:
        """
        Encodes this ECC Schnorr digital signature's (R,s) tuple, using SEC1 encoding for the random nonce ECC point (R)
        followed by base64 encoding, and base64 encoding for its (integer) signature value (s), separated by a colon
        delimiter.
        :return: a string encoding of this ECC Schnorr digital signature, which uses colon-delimited base64-encoded
                 fields.
        """
        nonce_point_SEC1_bytes: bytes = self.context.encode_ecc_point(self.public_nonce)
        nonce_point_base64: str = base64.b64encode(nonce_point_SEC1_bytes).decode('utf-8')

        signature_bytes: bytes = number.long_to_bytes(self.signature)
        signature_base64: str = base64.b64encode(signature_bytes).decode('utf-8')

        return STRING_ENCODING_FIELD_DELIMITER.join([nonce_point_base64, signature_base64])  # (R:s)
