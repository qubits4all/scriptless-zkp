"""
Provides a noninteractive zero-knowledge (NIZK) proof of knowledge of discrete logarithm,
over a prime-order elliptic curve group (e.g., NIST P-256).
"""
from __future__ import annotations

import base64
import binascii

from hashlib import sha512
from typing import Optional, NewType

from Cryptodome.PublicKey import ECC
from Cryptodome.Util import number

from scriptless_zkp import STRING_ENCODING_FIELD_DELIMITER
from scriptless_zkp.ecc.ecc_utils import WeierstrassEllipticCurveConfig


class NIZKDiscreteLogCommon:
    """
    This noninteractive protocol, for proving & verifying knowledge of a discrete logarithm, is based on Schnorr's
    identification/authentication protocol, which has been transformed via the Fiat-Shamir transform.
    """

    def __init__(self, curve_config: WeierstrassEllipticCurveConfig):
        self.curve_config: WeierstrassEllipticCurveConfig = curve_config
        self.curve: str = self.curve_config.curve
        self.order: int = self.curve_config.order
        self.G: ECC.EccPoint = self.curve_config.base_point  # curve's generator

    def calc_public_hash(
            self,
            dlog_reference_point: ECC.EccPoint,
            ephemeral_public_key: ECC.EccKey,
            dlog_base: Optional[ECC.EccPoint] = None
    ) -> int:
        """
        Calculates a public hash (SHA-512) of the provided discrete log base, elliptic curve reference point & random
        ephemeral public key (i.e., all public parameters). This hash replaces the verifier-provided random challenge,
        of the base interactive zero-knowledge proof (sigma) protocol, in the noninteractive zero-knowledge (NIZK)
        proof of knowledge of discrete logarithm.
        """
        dlog_base_as_pubkey: ECC.EccKey = ECC.construct(
            curve=self.curve, point_x=self.G.x, point_y=self.G.y
        ) if dlog_base is None else ECC.construct(
            curve=self.curve, point_x=dlog_base.x, point_y=dlog_base.y
        )

        dlog_ref_point_as_pubkey: ECC.EccKey = ECC.construct(
            curve=self.curve, point_x=dlog_reference_point.x, point_y=dlog_reference_point.y
        )

        md = sha512()
        md.update(dlog_ref_point_as_pubkey.export_key(format='SEC1'))
        md.update(dlog_base_as_pubkey.export_key(format='SEC1'))
        md.update(ephemeral_public_key.export_key(format='SEC1'))
        public_hash_bytes: bytes = md.digest()

        return number.bytes_to_long(public_hash_bytes)


class NIZKDiscreteLogParameters:
    curve_config: WeierstrassEllipticCurveConfig
    dlog_ref_point: ECC.EccPoint  # EC point = dlog * dlog_base
    dlog_base: ECC.EccPoint

    def __init__(
            self,
            curve_config: WeierstrassEllipticCurveConfig,
            dlog_reference_point: ECC.EccPoint,
            dlog_base: Optional[ECC.EccPoint] = None
    ):
        self.curve_config = curve_config
        self.dlog_ref_point = dlog_reference_point
        self.dlog_base = self.curve_config.base_point if dlog_base is None else dlog_base

    @classmethod
    def from_string_encoding(cls, encoded_dlog_proof_params: str) -> NIZKDiscreteLogParameters:
        """
        Factory function that constructs an NIZK proof of knowledge of discrete logarithm's associated parameters
        (`NIZKDiscreteLogParameters`), including the elliptic curve's canonical name, discrete log (reference) point,
        and discrete log base, via parsing of its string encoding:
            `<elliptic-curve-name>:<dlog_ref_point_base64>:<dlog_base_base64>`
        :param encoded_dlog_proof_params: a string-encoded `NIZKDiscreteLogParameters`, which uses base64-encoding for
               binary fields and a colon field delimiter.
        :return: an NIZK proof of knowledge of discrete logarithm's associated parameters via parsing of its string
                 encoding.
        """
        EXPECTED_FIELDS_COUNT = 3

        dlog_param_fields: list[str] = encoded_dlog_proof_params.split(STRING_ENCODING_FIELD_DELIMITER)
        if len(dlog_param_fields) != EXPECTED_FIELDS_COUNT:
            raise ValueError(
                f"Unexpected number of fields [{len(dlog_param_fields)}] in string encoding of "
                f"NIZKDiscreteLogParameters [expected_fields_count={EXPECTED_FIELDS_COUNT}]"
            )

        curve_name: str = dlog_param_fields[0]
        curve_config: WeierstrassEllipticCurveConfig
        match curve_name:
            case str(curve) if WeierstrassEllipticCurveConfig.secp256r1().has_curve_name(curve):
                curve_config = WeierstrassEllipticCurveConfig.secp256r1()
            case unsupported:
                raise ValueError(
                    f"Unsupported ECC curve name in string encoding of {cls.__name__}: {unsupported!s}"
                )

        try:
            dlog_ref_point: ECC.EccPoint = ECC.import_key(
                base64.b64decode(dlog_param_fields[1], validate=True),
                curve_name=curve_name
            ).pointQ
        except binascii.Error as bae:
            raise ValueError(
                f"Invalid base64-encoded ECC discrete log (reference) point in string encoding of {cls.__name__} "
                f"-- caused by: {bae}"
            ) from bae  # include base64 decoding exception cause
        except ValueError as ve:
            raise ValueError(
                f"Invalid 'SEC1' public key-encoded ECC discrete log (reference) point, in string encoding of "
                f"{cls.__name__} -- caused by: {ve}"
            ) from ve  # include 'SEC1' public key decoding exception cause

        try:
            dlog_base: ECC.EccPoint = ECC.import_key(
                base64.b64decode(dlog_param_fields[2], validate=True),
                curve_name=curve_name
            ).pointQ
        except binascii.Error as bae:
            raise ValueError(
                f"Invalid base64-encoded ECC discrete log base point in string encoding of {cls.__name__} "
                f"-- caused by: {bae}"
            ) from bae  # include base64 decoding exception cause
        except ValueError as ve:
            raise ValueError(
                f"Invalid 'SEC1' public key-encoded ECC discrete log base point, in string encoding of "
                f"{cls.__name__} -- caused by: {ve}"
            ) from ve  # include 'SEC1' public key decoding exception cause

        return cls(curve_config, dlog_ref_point, dlog_base)

    def encode_parameters(self) -> bytes:
        # Convert EC reference point (ECC.EccPoint) to public key (ECC.EccKey), then encode as bytes in 'SEC1' encoding.
        dlog_ref_point_encoded: bytes = ECC.construct(
            curve=self.curve_config.curve,
            point_x=self.dlog_ref_point.x,
            point_y=self.dlog_ref_point.y
        ).export_key(format='SEC1')

        # Convert EC dlog base point (ECC.EccPoint) to public key (ECC.EccKey), then encode as bytes in 'SEC1' encoding.
        dlog_base_encoded: bytes = ECC.construct(
            curve=self.curve_config.curve,
            point_x=self.dlog_base.x,
            point_y=self.dlog_base.y
        ).export_key(format='SEC1')

        # Return the concatenation of the 'SEC1'-encoded EC ref. point & dlog base point.
        return dlog_ref_point_encoded + dlog_base_encoded

    def encode_as_string(self) -> str:
        """
        Returns a string encoding of this NIZK proof's associated parameters, including the elliptic curve's canonical
        name, discrete log (reference) point & discrete log base.
        The encoding uses base64 for binary values and is colon-delimited as follows:
            `<elliptic-curve-name>:<dlog_ref_point_base64>:<dlog_base_base64>`
        :return: a string encoding of this NIZK proof's associated parameters, which uses base64-encoding for binary
                 fields and colon delimited fields.
        """
        # Convert EC reference point (ECC.EccPoint) to public key (ECC.EccKey), then encode as bytes in 'SEC1' encoding.
        dlog_ref_point_encoded: bytes = ECC.construct(
            curve=self.curve_config.curve,
            point_x=self.dlog_ref_point.x,
            point_y=self.dlog_ref_point.y
        ).export_key(format='SEC1')
        dlog_ref_point_base64: str = base64.b64encode(dlog_ref_point_encoded).decode('utf-8')

        # Convert EC dlog base point (ECC.EccPoint) to public key (ECC.EccKey), then encode as bytes in 'SEC1' encoding.
        dlog_base_encoded: bytes = ECC.construct(
            curve=self.curve_config.curve,
            point_x=self.dlog_base.x,
            point_y=self.dlog_base.y
        ).export_key(format='SEC1')
        dlog_base_base64: str = base64.b64encode(dlog_base_encoded).decode('utf-8')

        return ':'.join([self.curve_config.curve, dlog_ref_point_base64, dlog_base_base64])


"""
Efficient type for an NIZK proof of knowledge of discrete log's signature that auto-casts to an `int`, but not from
an `int`, providing type safety in function & method calls.
"""
DiscreteLogProofSignature = NewType('NIZKDiscreteLogProofSignature', int)


class NIZKDiscreteLogProof:
    discrete_log_params: NIZKDiscreteLogParameters
    ephemeral_public_key: ECC.EccKey
    proof_signature: DiscreteLogProofSignature

    def __init__(
            self,
            discrete_log_params: NIZKDiscreteLogParameters,
            ephemeral_public_key: ECC.EccKey,
            proof_signature: DiscreteLogProofSignature
    ):
        self.curve_config = discrete_log_params.curve_config
        self.discrete_log_params = discrete_log_params
        self.ephemeral_public_key = ephemeral_public_key
        self.proof_signature = proof_signature

    @classmethod
    def from_string_encoding(cls, encoded_dlog_proof: str) -> NIZKDiscreteLogProof:
        """
        Factory function that constructs an `NIZKDiscreteLogProof` via parsing of its string encoding as follows:
            `<elliptic-curve-name>:<dlog_ref_point_base64>:<dlog_base_base64>:<proof_signature_base64>
                :<proof_verification_key_base64>`
        :param encoded_dlog_proof: a string-encoded `NIZKDiscreteLogProof`, which uses base64-encoding for binary
               fields and a colon field delimiter.
        :return: an `NIZKDiscreteLogProof` via parsing of its string encoding.
        """
        EXPECTED_FIELDS_COUNT = 5

        dlog_proof_fields: list[str] = encoded_dlog_proof.split(STRING_ENCODING_FIELD_DELIMITER)
        if len(dlog_proof_fields) != EXPECTED_FIELDS_COUNT:
            raise ValueError(
                f"Unexpected number of fields [{len(dlog_proof_fields)}] in string encoding of {cls.__name__} "
                f"[expected_fields_count={EXPECTED_FIELDS_COUNT}]"
            )

        try:
            encoded_dlog_params: str = ':'.join(dlog_proof_fields[0:3])
            discrete_log_params: NIZKDiscreteLogParameters = NIZKDiscreteLogParameters.from_string_encoding(
                encoded_dlog_params  # fields #0-2 comprise the NIZK proof's assoc. parameters
            )
        except ValueError as ve:
            raise ValueError(
                f"Missing or invalid NIZK discrete log proof parameters in string encoding of {cls.__name__} "
                f"-- caused by: {ve}"
            ) from ve

        try:
            proof_signature: DiscreteLogProofSignature = DiscreteLogProofSignature(number.bytes_to_long(
                base64.b64decode(dlog_proof_fields[3], validate=True)
            ))
        except binascii.Error as bae:
            raise ValueError(
                f"Invalid base64-encoded NIZK discrete log proof signature in string encoding of {cls.__name__} "
                f"-- caused by: {bae}"
            ) from bae  # include base64 decoding exception cause
        except ValueError as ve:
            raise ValueError(
                f"Invalid NIZK discrete log proof signature in string encoding of {cls.__name__} -- caused by: {ve}"
            ) from ve  # include bytes-to-long decoding exception cause

        try:
            proof_verification_key: ECC.EccKey = ECC.import_key(
                base64.b64decode(dlog_proof_fields[4], validate=True),
                curve_name=discrete_log_params.curve_config.curve
            )
        except binascii.Error as bae:
            raise ValueError(
                f"Invalid base64-encoded proof verification key in string encoding of {cls.__name__} "
                f"-- caused by: {bae}"
            ) from bae  # include base64 decoding exception cause
        except ValueError as ve:
            raise ValueError(
                f"Invalid 'SEC1'-encoded proof verification ECC public key in string encoding of {cls.__name__} "
                f"-- caused by: {ve}"
            ) from ve  # include 'SEC1' public key decoding exception cause

        return cls(
            discrete_log_params,
            proof_verification_key,
            proof_signature
        )

    @property
    def dlog_reference_point(self) -> ECC.EccPoint:
        """
        Returns the elliptic curve (reference) point `Q` (i.e., `Q = dlog * dlog_base`), for which knowledge of its
        discrete logarithm `dlog` w.r.t. base `dlog_base` is being proven.
        :return: the elliptic curve (reference) point, for which knowledge of its discrete logarithm is being proven.
        """
        return self.discrete_log_params.dlog_ref_point

    @property
    def dlog_base_point(self) -> ECC.EccPoint:
        """
        Returns the base `dlog_base` of the discrete logarithm, for which knowledge is being proven (i.e., where `dlog`
        is the discrete logarithm of `Q` in: `Q = dlog * dlog_base`).
        :return: the base of the discrete logarithm, for which knowledge is being proven.
        """
        return self.discrete_log_params.dlog_base

    def encode_for_commitment(self) -> bytes:
        """
        Binary encodes & concatenates this NIZK proof of knowledge of discrete logarithm, along with its associated
        discrete log parameters, and proof verification key, as follows:
            `<dlog_ref_point><dlog_base><proof_signature><proof_verification_key>`
        Elliptic curve points are 'SEC1'-encoded.
        :return: this NIZK proof of knowledge of discrete logarithm, along with its associated discrete log parameters,
                 and proof verification key, binary encoded & concatenated, where 'SEC1' encoding is used for elliptic
                 curve points.
        """
        # Encode values that will be committed to:
        encoded_dlog_params: bytes = self.discrete_log_params.encode_parameters()
        encoded_proof_verification_key: bytes = self.ephemeral_public_key.export_key(format='SEC1')
        encoded_dlog_proof_signature: bytes = number.long_to_bytes(self.proof_signature)

        # Concatenate encoded commitment values.
        return encoded_dlog_params + encoded_proof_verification_key + encoded_dlog_proof_signature

    def encode_as_string(self) -> str:
        """
        Encodes this NIZK proof of knowledge of discrete logarithm, along with its associated discrete log parameters,
        and proof verification key, as a colon-delimited string of base64-encoded values, as follows:
            `<elliptic-curve-name>:<dlog_ref_point_base64>:<dlog_base_base64>:<proof_signature_base64>
                :<proof_verification_key_base64>`
        where `dlog_ref_point = dlog_base * dlog` and `dlog_base` and `dlog_ref_point` are both elliptic curve points.
        Elliptic curve points are 'SEC1'-encoded prior to base64 encoding.
        :return: this NIZK proof of knowledge of discrete logarithm, along with its associated discrete log parameters,
                 and proof verification key, encoded as a colon-delimited string of base64-encoded values.
        """
        # Encode values that will be committed to:
        encoded_dlog_params: str = self.discrete_log_params.encode_as_string()

        encoded_dlog_proof_signature: bytes = number.long_to_bytes(self.proof_signature)
        dlog_proof_signature_base64: str = base64.b64encode(encoded_dlog_proof_signature).decode('utf-8')

        encoded_proof_verification_key: bytes = self.ephemeral_public_key.export_key(format='SEC1')
        proof_verification_key_base64: str = base64.b64encode(encoded_proof_verification_key).decode('utf-8')

        return ':'.join([encoded_dlog_params, dlog_proof_signature_base64, proof_verification_key_base64])


class NIZKDiscreteLogProver:
    """Supports constructing NIZK proofs of knowledge of discrete logarithm, for points on the given elliptic curve."""

    def __init__(self, curve_config: WeierstrassEllipticCurveConfig):
        self.curve_config = curve_config
        self.curve = self.curve_config.curve
        self.order = self.curve_config.order
        self.G: ECC.EccPoint = self.curve_config.base_point  # curve's generator
        self.common = NIZKDiscreteLogCommon(self.curve_config)

    def calc_proof(
            self,
            discrete_log: int,
            dlog_reference_point: Optional[ECC.EccPoint] = None,
            discrete_log_base: Optional[ECC.EccPoint] = None
    ) -> NIZKDiscreteLogProof:
        """
        Calculates a noninteractive zero-knowledge (NIZK) proof of knowledge of discrete logarithm, for the given
        ECC discrete logarithm and associated discrete log base.
        :param discrete_log: ECC discrete logarithm for which to produce an NIZK proof of knowledge.
        :param dlog_reference_point: ECC point for which knowledge of its discrete log is being proven for the given
               base point (i.e., "dlog_ref_pt = dlog * dlog_base").
        :param discrete_log_base: ECC discrete logarithm base corresponding to the provided discrete log, for which an
               NIZK proof of knowledge is to be produced.
        :return: a proof of knowledge of ECC discrete logarithm to the provided discrete log base, as a tuple:
                 (ephemeral_pub_key, signature).
        """
        # Generate a random ephemeral ECC key-pair.
        ephemeral_keypair: ECC.EccKey = self._generate_ephemeral_keypair()
        ephemeral_private_key: int = int(ephemeral_keypair.d)
        ephemeral_public_key: ECC.EccKey = ephemeral_keypair.public_key()

        if dlog_reference_point is None:
            # Produce the EC reference point, for which its discrete logarithm is being proven, if not provided.
            dlog_ref_point: ECC.EccPoint = self._calc_dlog_reference_point(discrete_log, discrete_log_base)
        else:
            dlog_ref_point: ECC.EccPoint = dlog_reference_point

        # Calc. public hash (SHA-512) of the dlog_ref_point, ephemeral pub. key & dlog_base, which replaces an
        # interactive ZKP's verifier-provided random challenge.
        public_hash: int = self.common.calc_public_hash(dlog_ref_point, ephemeral_public_key, discrete_log_base)

        # Calculate proof signature: sig := ephemeral_priv - pub_hash*dlog (mod o(G))
        proof_signature: int = (ephemeral_private_key - public_hash * discrete_log) % self.order

        return NIZKDiscreteLogProof(
            NIZKDiscreteLogParameters(self.curve_config, dlog_ref_point, discrete_log_base),
            ephemeral_public_key,
            DiscreteLogProofSignature(proof_signature)
        )

    def _generate_ephemeral_keypair(self) -> ECC.EccKey:
        """Generates a random ephemeral ECC key-pair."""
        return ECC.generate(curve=self.curve)

    def _calc_dlog_reference_point(
            self,
            discrete_log: int,
            discrete_log_base: Optional[ECC.EccPoint] = None
    ) -> ECC.EccPoint:
        """
        Calculates the elliptic curve (reference) point, for which knowledge of the provided discrete logarithm to the
        given base will be proven by this `NIZKDiscreteLogProver`.
        :param discrete_log discrete logarithm from which to produce the elliptic curve (reference) point `Q`
               (i.e., as `Q = dlog * dlog_base`).
        :param discrete_log_base discrete logarithm base corresponding to the provided discrete log, for which the
               elliptic curve (reference) point is being produced; defaulting to the elliptic curve's base point if not
               provided.
        :return the public elliptic curve (reference) point, for which knowledge of the provided discrete logarithm to
                the given base will be proven.
        """
        # Default to the curve's base point as discrete logarithm base, if not provided.
        if discrete_log_base is None:
            return self.G * discrete_log
        else:
            return discrete_log_base * discrete_log


class NIZKDiscreteLogVerifier:
    """Supports verifying NIZK proofs of knowledge of discrete logarithm, for points on the given elliptic curve."""

    def __init__(self, curve_config: WeierstrassEllipticCurveConfig):
        self.curve_config = curve_config
        self.common = NIZKDiscreteLogCommon(self.curve_config)

    def verify_proof(self, discrete_log_proof: NIZKDiscreteLogProof) -> bool:
        """
        Verifies a noninteractive zero-knowledge (NIZK) proof of knowledge of discrete logarithm.
        :param discrete_log_proof: NIZK proof of knowledge of discrete logarithm to be verified.
        :return: whether the provided NIZK proof of knowledge of discrete logarithm is valid.
        """
        dlog_base: ECC.EccPoint = discrete_log_proof.dlog_base_point
        dlog_ref_point: ECC.EccPoint = discrete_log_proof.dlog_reference_point

        # Calc. public hash (SHA-512) of the dlog_ref_point, ephemeral pub. key & dlog_base
        public_hash: int = self.common.calc_public_hash(
            dlog_ref_point,
            discrete_log_proof.ephemeral_public_key,
            dlog_base
        )
        # Recalculate the proof's ephemeral public key via the proof's signature & public hash, and its associated
        # discrete log reference point (incl. the discrete log base):
        #     `verification_key ?= (dlog_base * proof_sig) + (ref_point * pub_hash)`
        ephemeral_verification: ECC.EccPoint = (
            dlog_base * discrete_log_proof.proof_signature
        ) + (dlog_ref_point * public_hash)

        # Proof is valid if the recalculated ephemeral public key matches the proof's provided ephemeral public key.
        return ephemeral_verification == discrete_log_proof.ephemeral_public_key.pointQ
