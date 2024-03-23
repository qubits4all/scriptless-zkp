"""
Provides provers & verifiers for non-interactive zero-knowledge (NIZK) proofs of knowledge
of discrete logarithms, along with cryptographic commitments to associated parameters, such
as the discrete logarithm's base and the value (e.g., elliptic curve point) for which
knowledge of its discrete log is being proven.
"""
from __future__ import annotations

import base64
import binascii
import uuid

from typing import Literal, Optional

from scriptless_zkp import PartyId, STRING_ENCODING_FIELD_DELIMITER
from scriptless_zkp.commitments.hmac_commitments import (
    KeyedHashCommitment, KeyedHashCommitmentUtils, RevealedKeyedHashCommitment
)
from scriptless_zkp.ecc.ecc_utils import WeierstrassEllipticCurveConfig
from scriptless_zkp.ecc.zkp.nizk_dlog_proof import (
    NIZKDiscreteLogProof, NIZKDiscreteLogProver, NIZKDiscreteLogVerifier, NIZKDiscreteLogParameters
)


class SealedDiscreteLogProofCommitment:
    session_id: uuid.UUID    # globally-unique ID for a protocol session
    party_id: PartyId  # proving/committing party's ID (i.e., either #1: initiator or #2: responder)
    commitment: KeyedHashCommitment

    def __init__(
            self,
            party_id: int,
            commitment: KeyedHashCommitment,
            session_id: Optional[uuid.UUID] = None
    ):
        self.session_id = session_id if session_id is not None else uuid.uuid4()  # generate random UUID if not provided
        self.party_id = type(self)._validate_party_id(party_id)
        self.commitment = commitment

    @classmethod
    def for_dlog_proof(
            cls,
            party_id: PartyId,
            dlog_proof: NIZKDiscreteLogProof,
            hash_algorithm: str = KeyedHashCommitmentUtils.DEFAULT_HASH_ALGORITHM
    ) -> (SealedDiscreteLogProofCommitment, bytearray):
        """
        Constructs a sealed commitment to the provided discrete logarithm proof and associated discrete log parameters,
        including the discrete log reference point, discrete log base, proof signature & proof verification key.
        The sealed commitment is returned, as well as the commitment verification key (to be revealed later).
        :param party_id: prover/committer party's ID (i.e., either #1: initiator or #2: responder).
        :param dlog_proof: noninteractive zero-knowledge (NIZK) proof of knowledge of discrete logarithm, to which to
               commit.
        :param hash_algorithm: cryptographic hash algorithm to be used for the keyed-hash commitment.
        :return: a sealed commitment to the provided discrete logarithm proof and associated discrete log parameters,
                 in addition to the commitment verification key (to be revealed later).
        """
        # Encode & concatenate the dlog parameters, dlog proof & verification key, to which we're committing.
        encoded_commitment_values: bytes = dlog_proof.encode_for_commitment()

        sealed_commitment: KeyedHashCommitment
        revealed_commitment: RevealedKeyedHashCommitment
        sealed_commitment, revealed_commitment = KeyedHashCommitmentUtils(
            hash_algorithm
        ).commit(encoded_commitment_values)

        return cls(party_id, sealed_commitment), revealed_commitment.verification_key

    @classmethod
    def from_string_encoding(cls, encoded_sealed_commitment: str) -> SealedDiscreteLogProofCommitment:
        """
        Constructs a `SealedDiscreteLogProofCommitment` by parsing the provided string encoding (e.g., received via a
        network transmission).
        :param encoded_sealed_commitment: string encoding of a sealed discrete log proof commitment.
        :return: a `SealedDiscreteLogProofCommitment` constructed from the provided string encoding.
        """
        EXPECTED_FIELDS_COUNT: int = 4
        sealed_commitment_fields: list[str] = encoded_sealed_commitment.split(STRING_ENCODING_FIELD_DELIMITER)
        if len(sealed_commitment_fields) != EXPECTED_FIELDS_COUNT:
            raise ValueError(
                f"Expected [{EXPECTED_FIELDS_COUNT}] fields in sealed discrete log proof commitment's string encoding, "
                f"but found [{len(sealed_commitment_fields)}] fields."
            )

        try:
            session_id: uuid.UUID = uuid.UUID(sealed_commitment_fields[0])
        except ValueError as ve:
            raise ValueError(
                f"Failed to parse (UUID) session ID from string encoding of sealed discrete log proof commitment: "
                f"{ve}"
            ) from ve

        try:
            party_id: PartyId = cls._validate_party_id(
                int(sealed_commitment_fields[1])
            )
        except ValueError as ve:
            raise ValueError(
                f"Failed to parse (int) party ID from string encoding of sealed discrete log proof commitment: {ve}"
            ) from ve

        try:
            commitment: KeyedHashCommitment = KeyedHashCommitment.from_string_encoding(
                STRING_ENCODING_FIELD_DELIMITER.join(sealed_commitment_fields[2:])
            )
        except ValueError as ve:
            raise ValueError(
                f"Failed to parse keyed-hash commitment from string encoding of sealed discrete log proof commitment: "
                f"{ve}"
            ) from ve

        return cls(party_id, commitment, session_id)

    def encode_as_string(self) -> str:
        """
        Encodes this sealed discrete log proof commitment as a string (e.g., for network transmission).
        :return: string encoding of this sealed discrete log proof commitment.
        """
        return STRING_ENCODING_FIELD_DELIMITER.join([
            str(self.session_id),
            str(self.party_id),
            self.commitment.encode_as_string()
        ])

    def reveal(
            self,
            dlog_proof: NIZKDiscreteLogProof,
            commitment_verification_key: bytearray  # ephemeral commitment key
    ) -> RevealedDiscreteLogProofCommitment:
        return RevealedDiscreteLogProofCommitment.for_committed_proof(
            self,
            dlog_proof,
            commitment_verification_key
        )

    @classmethod
    def _validate_party_id(cls, party_id: int) -> PartyId:
        match party_id:
            case 1: return 1
            case 2: return 2
            case invalid:
                raise ValueError(
                    f"Invalid party ID provided when constructing a {cls.__name__}: {invalid}"
                )


class RevealedDiscreteLogProofCommitment:
    session_id: uuid.UUID    # globally-unique ID for a protocol session
    party_id: Literal[1, 2]  # prover/committer party's ID (i.e., either #1: initiator or #2: responder)
    committed_dlog_proof: NIZKDiscreteLogProof
    commitment_verification_key: bytearray
    hash_algo: str

    def __init__(
            self,
            session_id: uuid.UUID,
            party_id: int,
            discrete_log_proof: NIZKDiscreteLogProof,
            commitment_verification_key: bytearray,
            commitment_hash_algorithm: str
    ):
        self.party_id = type(self)._validate_party_id(party_id)
        self.session_id = session_id
        self.committed_dlog_proof = discrete_log_proof
        self.commitment_verification_key = commitment_verification_key
        self.hash_algo = commitment_hash_algorithm

    @classmethod
    def for_committed_proof(
            cls,
            sealed_proof_commitment: SealedDiscreteLogProofCommitment,
            dlog_proof: NIZKDiscreteLogProof,
            ephemeral_commitment_key: bytearray
    ) -> RevealedDiscreteLogProofCommitment:
        return cls(
            sealed_proof_commitment.session_id,
            sealed_proof_commitment.party_id,
            dlog_proof,
            ephemeral_commitment_key,
            sealed_proof_commitment.commitment.hash_algorithm
        )

    @classmethod
    def from_string_encoding(cls, encoded_revealed_commitment: str) -> RevealedDiscreteLogProofCommitment:
        """
        Factory function that parses the string encoding of a `RevealedDiscreteLogProofCommitment` (e.g., received via
        network transmission).
        :param encoded_revealed_commitment: string encoding of a `RevealedDiscreteLogProofCommitment` to be parsed.
        :return: a new `RevealedDiscreteLogProofCommitment` constructed via parsing of its string encoding.
        """
        # noinspection PyPep8Naming
        EXPECTED_FIELDS_COUNT = 9

        revealed_commitment_fields: list[str] = encoded_revealed_commitment.split(STRING_ENCODING_FIELD_DELIMITER)
        if len(revealed_commitment_fields) != EXPECTED_FIELDS_COUNT:
            raise ValueError(
                f"Unexpected number of fields [{len(revealed_commitment_fields)}] in string encoding of "
                f"RevealedDiscreteLogProofCommitment [expected_fields_count={EXPECTED_FIELDS_COUNT}]"
            )

        try:
            session_id: uuid.UUID = uuid.UUID(revealed_commitment_fields[0])
        except ValueError as ve:
            raise ValueError(
                f"Invalid UUID session ID found in string encoding of {cls.__name__} -- caused by: {ve}"
            ) from ve  # include UUID parsing exception cause

        try:
            party_id: int = int(revealed_commitment_fields[1])
        except ValueError as ve:
            raise ValueError(
                f"Invalid party ID found in string encoding of {cls.__name__} -- caused by: {ve}"
            ) from ve  # include integer parsing exception cause
        else:
            party_id: PartyId = cls._validate_party_id(party_id)

        # Parse the embedded string-encoded NIZK proof of knowledge of discrete logarithm.
        dlog_proof: NIZKDiscreteLogProof = NIZKDiscreteLogProof.from_string_encoding(
            ':'.join(revealed_commitment_fields[2:7])  # fields #2-6 comprise the NIZK proof object
        )

        try:
            commitment_key: bytearray = bytearray(base64.b64decode(revealed_commitment_fields[7], validate=True))
        except binascii.Error as bae:
            raise ValueError(
                f"Invalid base64-encoded commitment verification key in string encoding of {cls.__name__} "
                f"-- caused by: {bae}"
            ) from bae  # include base64 decoding exception cause

        # The commitment's cryptographic hash algorithm (i.e., used in its MAC or HMAC).
        hash_algo: str = revealed_commitment_fields[8]

        return cls(session_id, party_id, dlog_proof, commitment_key, hash_algo)

    def encode_as_string(self) -> str:
        """
        Returns a string encoding of this revealed discrete log proof commitment, including the zero-knowledge proof
        and associated parameters, proof verification key, commitment & commitment verification key, along with the
        unique session ID, the party ID (i.e., #1: initiator or #2: responder) & the commitment's cryptographic hash
        algorithm (e.g., SHA-256).
        The encoding uses base64 for binary values and is colon-delimited as follows:
            `<session_id>:<party_id>:<dlog_ref_point_base64>:<dlog_base_base64>:<proof_signature_base64>
                :<proof_verification_key_base64>:<commitment_verification_key_base64>:<hash_algorithm>`
        :return: a string encoding of this revealed discrete log proof commitment, using base64-encoding for binary
                 values & a colon field delimiter.
        """
        encoded_proof: str = self.committed_dlog_proof.encode_as_string()
        commitment_verification_key: str = base64.b64encode(self.commitment_verification_key).decode('utf-8')

        return f"{self.session_id!s}:{self.party_id}:{encoded_proof}:{commitment_verification_key}:{self.hash_algo}"

    def verify(self, keyed_hash_commitment: KeyedHashCommitment) -> bool:
        return RevealedKeyedHashCommitment(
            self.committed_dlog_proof.encode_for_commitment(),
            self.commitment_verification_key,
            self.hash_algo
        ).verify(keyed_hash_commitment.commitment)

    @classmethod
    def _validate_party_id(cls, party_id: int) -> PartyId:
        match party_id:
            case 1: return 1
            case 2: return 2
            case invalid:
                raise ValueError(
                    f"Invalid party ID provided when constructing a {cls.__name__}: {invalid}"
                )


class DiscreteLogProofCommitmentUtils:
    curve_config: WeierstrassEllipticCurveConfig
    dlog_prover: NIZKDiscreteLogProver
    dlog_verifier: NIZKDiscreteLogVerifier
    commitment_utils: KeyedHashCommitmentUtils

    def __init__(
            self,
            curve_config: WeierstrassEllipticCurveConfig,
            commitment_hash_algorithm: str = KeyedHashCommitmentUtils.DEFAULT_HASH_ALGORITHM
    ):
        self.curve_config = curve_config
        self.dlog_prover = NIZKDiscreteLogProver(self.curve_config)
        self.dlog_verifier = NIZKDiscreteLogVerifier(self.curve_config)
        self.commitment_utils = KeyedHashCommitmentUtils(commitment_hash_algorithm)

    @property
    def hash_algorithm(self) -> str:
        return self.commitment_utils.hash_algo

    def commit_prove(
            self,
            party_id: Literal[1, 2],
            dlog_parameters: NIZKDiscreteLogParameters,
            discrete_log: int
    ) -> (SealedDiscreteLogProofCommitment, NIZKDiscreteLogProof, bytearray):
        dlog_proof: NIZKDiscreteLogProof = self.dlog_prover.calc_proof(
            discrete_log=discrete_log,
            dlog_reference_point=dlog_parameters.dlog_ref_point,
            discrete_log_base=dlog_parameters.dlog_base
        )

        sealed_commitment: SealedDiscreteLogProofCommitment
        commitment_verification_key: bytearray
        sealed_commitment, commitment_verification_key = SealedDiscreteLogProofCommitment.for_dlog_proof(
            party_id,
            dlog_proof,
            self.hash_algorithm
        )

        return sealed_commitment, dlog_proof, commitment_verification_key
