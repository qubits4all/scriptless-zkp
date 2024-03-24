"""
Provides an interactive signing protocol supporting two-party Schnorr signatures, a supporting distributed key
generation protocol for collaboratively generating private key-shares and a joint public key, and a signature verifier
for verifying such two-party Schnorr signatures using the joint public key.

- Featuring 2/2 multi-signatures indistinguishable from single-party ECC Schnorr signatures, and non-interactive
  verification via a joint public key.
- Including distributed multi-party computation of a hardened joint public key & hardened public/private key-shares,
  with protection against public key-share subtraction attacks.
- Both protocols feature detection of deviations from correct protocol operation by either party with abort, via ZKPs
  with commitments.
"""
from __future__ import annotations

import hashlib
import uuid

from typing import Optional

import attrs

from Cryptodome.PublicKey import ECC

from scriptless_zkp import PartyId
from scriptless_zkp.ecc.ecc_exceptions import (
    InvalidECCPublicKeyException, IncorrectECCCurveException, IncorrectECCSchnorrSignatureCurveException,
    InvalidECCPointException
)
from scriptless_zkp.ecc.ecc_utils import WeierstrassEllipticCurveConfig
from scriptless_zkp.ecc.signatures.schnorr import SchnorrContext, SchnorrSignature
from scriptless_zkp.ecc.zkp.nizk_dlog_proof import (
    NIZKDiscreteLogParameters, NIZKDiscreteLogProver, NIZKDiscreteLogProof, NIZKDiscreteLogVerifier
)
from scriptless_zkp.ecc.zkp.nizk_dlog_proof_commitments import (
    DiscreteLogProofCommitmentUtils, SealedDiscreteLogProofCommitment, RevealedDiscreteLogProofCommitment
)
from scriptless_zkp.hashing import PrimeLengthTruncatedHasher


class TwoPartySchnorrContext:
    """
    Configuration parameters for two-party ECC Schnorr digital signatures, including ECC parameters, and message & key
    hash algorithms.
    """
    DEFAULT_HASH_ALGO: str = hashlib.sha256().name  # Note: 256-bit hash req'd for 256-bit ECC curves.
    INITIATING_PARTY: PartyId = 1
    RESPONDING_PARTY: PartyId = 2

    ecc_curve_config: WeierstrassEllipticCurveConfig
    q: int
    key_hash_algo: str
    key_hash_length: int
    message_hash_algo: str
    message_hash_length: int

    def __init__(
            self,
            ecc_curve_config: WeierstrassEllipticCurveConfig,
            key_hash_algorithm: str = DEFAULT_HASH_ALGO,
            message_hash_algorithm: str = DEFAULT_HASH_ALGO
    ):
        self.ecc_curve_config: WeierstrassEllipticCurveConfig = ecc_curve_config
        self.q: int = self.ecc_curve_config.order
        self.key_hash_algo: str = key_hash_algorithm
        self.key_hash_length: int = hashlib.new(self.key_hash_algo).digest_size
        self.message_hash_algo: str = message_hash_algorithm
        self.message_hash_length: int = hashlib.new(self.message_hash_algo).digest_size

    @property
    def curve_base_point(self) -> ECC.EccPoint:
        """Returns the configured ECC curve's base point `G`."""
        return self.ecc_curve_config.base_point

    @property
    def curve_order(self) -> int:
        """Returns the configured ECC curve group's (``<G>``) order `q`."""
        return self.ecc_curve_config.order

    def generate_unhardened_key_share(self) -> ECC.EccKey:
        """
        Generates an unhardened public/private key-share pair, which requires hardening via the 2-party key generation
        sub-protocol's public keys-mixing hardening algorithm, prior to generation of the (hardened) 2-party joint
        public key or use in the 2-party signing sub-protocol.
        """
        return ECC.generate(curve=self.ecc_curve_config.curve)

    def as_schnorr_context(self) -> SchnorrContext:
        """
        Returns this two-party ECC Schnorr context converted to a single-party ECC Schnorr context.
        <p>
        This is useful for construction of ``SchnorrSignature`` instances, which are agnostic re: whether they were
        constructed via the single-party signing algorithm or two-party signing protocol. </p>
        """
        return SchnorrContext(self.ecc_curve_config, message_hash_algorithm=self.message_hash_algo)

    @staticmethod
    def encode_public_key(public_key: ECC.EccKey) -> bytes:
        """Encodes an ECC public-key's curve point, using the 'SEC1' binary point encoding without compression."""
        return public_key.export_key(format='SEC1')

    def encode_ecc_point(self, ecc_point: ECC.EccPoint) -> bytes:
        """Encodes an ECC point, using the 'SEC1' binary point encoding without compression."""
        return self.ecc_point_to_pubkey(ecc_point).export_key(format='SEC1')

    def ecc_point_to_pubkey(self, ecc_point: ECC.EccPoint) -> ECC.EccKey:
        """Converts an ECC point to an ECC public-key ``EccKey`` object."""
        return ECC.construct(curve=self.ecc_curve_config.curve, point_x=ecc_point.x, point_y=ecc_point.y)

    def verify_ecc_point(self, ecc_point: ECC.EccPoint) -> bool:
        """Returns whether the provided ECC point is on the configured elliptic curve."""
        try:
            self.ecc_point_to_pubkey(ecc_point)
        except ValueError:
            return False
        else:
            return True


class TwoPartySchnorrSigner:
    context: TwoPartySchnorrContext
    session_id: uuid.UUID               # globally-unique ID for a protocol session
    party_id: PartyId                   # party's ID (i.e., either #1: initiator or #2: responder)
    key_share: TwoPartySchnorrKeyShare  # hardened 2-party ECC Schnorr key-share (incl. counterparty's public key-share)
    joint_pubkey: JointSchnorrPublicKey

    def __init__(
            self,
            schnorr_context: TwoPartySchnorrContext,
            party_id: PartyId,
            hardened_key_share: TwoPartySchnorrKeyShare,
            joint_public_key: JointSchnorrPublicKey,
            session_id: Optional[uuid.UUID] = None
    ):
        self.context = schnorr_context
        self.session_id = session_id if session_id is not None else uuid.uuid4()  # generate random UUID if not provided
        self.party_id = party_id
        self.key_share = hardened_key_share
        self.joint_pubkey = joint_public_key

    @classmethod
    def from_existing_key_share(
            cls,
            schnorr_context: TwoPartySchnorrContext,
            party_id: PartyId,
            hardened_key_share: TwoPartySchnorrKeyShare,
            session_id: Optional[uuid.UUID] = None
    ) -> TwoPartySchnorrSigner:
        joint_public_key = JointSchnorrPublicKey.from_hardened_key_shares(
            schnorr_context,
            hardened_key_share.private_ecc_keypair,
            hardened_key_share.counterparty_ecc_pubkey
        )
        return TwoPartySchnorrSigner(schnorr_context, party_id, hardened_key_share, joint_public_key, session_id)

    @classmethod
    def for_initiating_party(
            cls,
            schnorr_context: TwoPartySchnorrContext,
            private_unhardened_key_share: ECC.EccKey,
            counterparty_public_unhardened_key_share: ECC.EccKey
    ) -> TwoPartySchnorrSigner:
        hardened_key_share = TwoPartySchnorrKeyShare.from_unhardened_key_shares(
            schnorr_context,
            TwoPartySchnorrContext.INITIATING_PARTY,
            private_unhardened_key_share,
            counterparty_public_unhardened_key_share
        )
        return TwoPartySchnorrSigner.from_existing_key_share(
            schnorr_context,
            TwoPartySchnorrContext.INITIATING_PARTY,
            hardened_key_share
        )

    @classmethod
    def for_responding_party(
            cls,
            schnorr_context: TwoPartySchnorrContext,
            private_unhardened_key_share: ECC.EccKey,
            counterparty_public_unhardened_key_share: ECC.EccKey
    ) -> TwoPartySchnorrSigner:
        hardened_key_share = TwoPartySchnorrKeyShare.from_unhardened_key_shares(
            schnorr_context,
            TwoPartySchnorrContext.RESPONDING_PARTY,
            private_unhardened_key_share,
            counterparty_public_unhardened_key_share
        )
        return TwoPartySchnorrSigner.from_existing_key_share(
            schnorr_context,
            TwoPartySchnorrContext.RESPONDING_PARTY,
            hardened_key_share
        )

    def init_signing(self) -> TwoPartySchnorrInitiatorSigningSession | TwoPartySchnorrResponderSigningSession:
        """
        As initiating or responding party, performs the first phase of the 2-party ECC Schnorr signing sub-protocol,
        returning a signing party-specific signing session.
        """
        nonce_pair: ECC.EccKey = ECC.generate(curve=self.context.ecc_curve_config.curve)
        dlog_parameters = NIZKDiscreteLogParameters(
            curve_config=self.context.ecc_curve_config,
            dlog_reference_point=nonce_pair.pointQ,
            dlog_base=self.context.ecc_curve_config.base_point
        )
        match self.party_id:
            case TwoPartySchnorrContext.INITIATING_PARTY:
                dlog_prover = NIZKDiscreteLogProver(self.context.ecc_curve_config)
                dlog_proof: NIZKDiscreteLogProof = dlog_prover.calc_proof(
                    discrete_log=int(nonce_pair.d),
                    dlog_reference_point=nonce_pair.pointQ
                )
                # NOTE: Send nonce dlog proof & public nonce to Responder, after receiving nonce dlog proof commitment.
                return TwoPartySchnorrInitiatorSigningSession(
                    schnorr_context=self.context,
                    session_id=self.session_id,
                    nonce_share_pair=nonce_pair,
                    nonce_nizk_dlog_proof=dlog_proof
                )
            case TwoPartySchnorrContext.RESPONDING_PARTY:
                proof_commitment_utils = DiscreteLogProofCommitmentUtils(self.context.ecc_curve_config)
                dlog_proof_commitment, dlog_proof, proof_commitment_verify_key = proof_commitment_utils.commit_prove(
                    party_id=self.party_id,
                    dlog_parameters=dlog_parameters,
                    discrete_log=int(nonce_pair.d)
                )
                # NOTE: Send sealed dlog proof commitment for nonce to Initiator.
                return TwoPartySchnorrResponderSigningSession(
                    schnorr_context=self.context,
                    session_id=self.session_id,
                    nonce_share_pair=nonce_pair,
                    nonce_nizk_dlog_proof=dlog_proof,
                    sealed_nonce_dlog_proof_commitment=dlog_proof_commitment,
                    nonce_dlog_proof_commitment_verification_key=proof_commitment_verify_key
                )
            case _:
                raise ValueError(f"Invalid PartyId configured for two-party ECC Schnorr signer: {self.party_id}")

    def calc_full_signature(
            self,
            signing_session: TwoPartySchnorrInitiatorSigningSession,
            responder_nonce_dlog_proof_commitment: SealedDiscreteLogProofCommitment,
            revealed_responder_nonce_dlog_proof_commitment: RevealedDiscreteLogProofCommitment,
            responder_public_nonce: ECC.EccPoint,
            responder_signature_share: int,
            message: bytes
    ) -> SchnorrSignature:
        """
        As the initiating party, calculates the full 2-party ECC Schnorr signature, given the responding party's
        signature share, and their commitment-revealed public nonce-share and zero-knowledge proof of knowledge (ZKPoK)
        of discrete logarithm for this nonce-share.
        """
        # Verify the Responder's revealed keyed-hash commitment, to their public nonce-share & ZKPoK of discrete log.
        TwoPartySchnorrSigner._verify_nonce_proof_commitment(
            responder_nonce_dlog_proof_commitment,
            revealed_responder_nonce_dlog_proof_commitment
        )

        # Verify the Responder's NIZK proof of knowledge (PoK) of discrete log for their nonce-share.
        self._verify_nonce_share_proof(
            revealed_responder_nonce_dlog_proof_commitment.committed_dlog_proof
        )

        # Verify the validity of the Responder-provided public nonce-share.
        self._verify_public_nonce_share(responder_public_nonce)

        # Construct a bit-length LSB(s)-truncated hasher w/ same bit-length as the ECC curve group's (<G>) order (q).
        truncated_hasher = PrimeLengthTruncatedHasher(
            self.context.ecc_curve_config.order,
            self.context.message_hash_algo
        )
        joint_nonce: ECC.EccPoint = responder_public_nonce + signing_session.public_nonce

        # Calc. hash of joint public key, joint public nonce & message, truncated to the bit-length of the ECC curve
        # group's (<G>) order (q): ("H'(Q_AB || R_A + R_B || m)").
        joint_hash_e: int = truncated_hasher.update(
            self.context.encode_public_key(          # joint public key "Q_AB := P_A' + P_B'" (SEC1-encoded)
                self.joint_pubkey.joint_ecc_pubkey
            )
        ).update(
            self.context.encode_ecc_point(           # joint public nonce "R := R_A + R_B" (SEC1-encoded)
                joint_nonce
            )
        ).update(message).intdigest()

        # Verify the Responder-provided signature share is valid.
        if not self._verify_responder_signature_share(
            responder_signature_share=responder_signature_share,
            responder_public_nonce=responder_public_nonce,
            joint_sig_hash=joint_hash_e
        ):
            # TODO: Use a custom exception type here, instead of ValueError.
            raise ValueError(
                "Invalid 2-party ECC Schnorr signature share received from responding party."
            )

        # Calculate full 2-party signature's scalar: "(s_B + r_A + H'(Q_AB || R_A + R_B || m) * x_A') mod q"
        full_signature_scalar: int = (
            responder_signature_share + signing_session.private_nonce + (
                self.key_share.private_key_scalar * joint_hash_e
            )
        ) % self.context.curve_order

        # NOTE: Send full 2-party ECC Schnorr signature to signing protocol's Responding party, who will verify its
        #   validity via the joint public key & joint public nonce.
        return SchnorrSignature(
            self.context.as_schnorr_context(),
            joint_nonce,
            full_signature_scalar
        )

    @staticmethod
    def _verify_nonce_proof_commitment(
            sealed_nonce_dlog_proof_commitment: SealedDiscreteLogProofCommitment,
            revealed_nonce_dlog_proof_commitment: RevealedDiscreteLogProofCommitment
    ) -> None:
        """
        Verifies a keyed-hash commitment to the provided nonce-share & associated zero-knowledge proof of knowledge
        (ZKPoK), given the original sealed commitment and its associated revealed commitment, which includes the
        commitment verification key.

        :raises ValueError: if the provided keyed-hash commitment is invalid, given its revealed commitment and
                included commitment verification key.
        """
        # Verify the Responder's keyed-hash commitment to their public nonce-share & assoc. ZKPoK of discrete log.
        if not revealed_nonce_dlog_proof_commitment.verify(sealed_nonce_dlog_proof_commitment.commitment):
            # TODO: Use a custom exception here, instead of ValueError (e.g., perhaps called
            #   InvalidNonceShareCommitmentException).
            raise ValueError(
                "Invalid keyed-hash commitment from 2-party ECC Schnorr signing sub-protocol's responding party,"
                " received for their nonce-share & associated zero-knowledge proof of knowledge (ZKPoK)."
            )

    def _verify_responder_signature_share(
        self,
        responder_signature_share: int,
        responder_public_nonce: ECC.EccPoint,
        joint_sig_hash: int
    ) -> bool:
        """
        Verifies whether the 2-party ECC Schnorr signing sub-protocol's responding party's provided signature share is
        valid, given their public nonce-share and the joint hash ("H'(Q_AB || R_A + R_B || m)").
        """
        # Verify the Responder's signature share:
        # Calc. ECC point corresponding to responder's provided signature share ("s_B * G").
        signature_share_point: ECC.EccPoint = self.context.ecc_curve_config.base_point * responder_signature_share

        # Calc. responder's public key-share from joint public key & initiator's public key-share ("P_B' = Q_AB - P_A'")
        responder_pubkey_point: ECC.EccPoint = self.joint_pubkey.public_key_point + (-self.key_share.public_key_point)

        # Calc. expected equivalent ECC point, based on responder's signature share, responder's public key-share, and
        # responder's public nonce ("R_B + H'(Q_AB || R_A + R_B || m) * (Q_AB - P_A').
        expected_sig_share_point: ECC.EccPoint = responder_public_nonce + (responder_pubkey_point * joint_sig_hash)

        return signature_share_point == expected_sig_share_point

    def calc_responder_signature_share(
            self,
            signing_session: TwoPartySchnorrResponderSigningSession,
            initiator_public_nonce: ECC.EccPoint,
            initiator_nonce_dlog_proof: NIZKDiscreteLogProof,
            message: bytes
    ) -> TwoPartySchnorrResponderSigningSession:
        """
        As responding party, calculates their signature share for the provided message, given the initiating party's
        public nonce, nonce dlog proof, and responding party's signing session.

        :raises InvalidECCPointException: if the received signing initiator's public nonce point is invalid due to it
                not lying on the configured elliptic curve.
        :raises InvalidECCPublicKeyException: if the received signing initiator's public nonce point in invalid due to
                it being the Point-at-Infinity.
        """
        # Verify the Initiator's NIZK proof of knowledge (PoK) of discrete log for their nonce-share.
        self._verify_nonce_share_proof(initiator_nonce_dlog_proof)

        # Verify the validity of the Initiator-provided public nonce-share.
        self._verify_public_nonce_share(initiator_public_nonce)

        # Construct a bit-length LSB(s)-truncated hasher w/ same bit-length as the ECC curve group's (<G>) order (q).
        truncated_hasher = PrimeLengthTruncatedHasher(
            self.context.ecc_curve_config.order,
            self.context.message_hash_algo
        )

        # Calculate the 2-party signing joint nonce ECC point ("R := R_A + R_B").
        joint_nonce: ECC.EccPoint = initiator_public_nonce + signing_session.public_nonce

        # Calc. hash of joint public key, joint public nonce & message, truncated to the bit-length of the ECC curve
        # group's (<G>) order (q): ("H'(Q_AB || R_A + R_B || m)").
        joint_hash_e: int = truncated_hasher.update(
            self.context.encode_public_key(          # joint public key "Q_AB := P_A' + P_B'" (SEC1-encoded)
                self.joint_pubkey.joint_ecc_pubkey
            )
        ).update(
            self.context.encode_ecc_point(           # joint public nonce "R := R_A + R_B" (SEC1-encoded)
                joint_nonce
            )
        ).update(message).intdigest()

        # Calc. signature share for signing protocol's Responding party B ("s_B := r_B + e * x_B' mod q").
        signature_share: int = (
            signing_session.private_nonce + joint_hash_e * self.key_share.private_key_scalar
        ) % self.context.curve_order

        signing_session.joint_nonce = joint_nonce
        signing_session.joint_hash_e = joint_hash_e
        signing_session.signature_share = signature_share

        # NOTE: Send nonce dlog proof commitment reveal & sig. share ('s_B') to signing protocol's Initiating party.
        return signing_session

    def verify_joint_signature_scalar(
            self,
            signing_session: TwoPartySchnorrResponderSigningSession,
            joint_signature_s: int
    ) -> bool:
        """
        As responding party, verifies the joint signature (scalar) produced by the signing protocol's initiating party.
        <p>
        Specifically, the joint signature's scalar is converted to an ECC point, and then compared to the joint public
        nonce added to the point formed by multiplying the joint public key by the joint hash
        ("s * G == R_A + R_B + H'(Q_AB || R_A + R_B || m) * Q_AB"). </p>
        """
        # Calc. ECC point corresponding to the signature scalar ("s * G").
        signature_ecc_point: ECC.EccPoint = self.context.ecc_curve_config.base_point * joint_signature_s

        # Calc. expected equivalent ECC point, based on the signature scalar, joint public key ("Q_AB := P_A' + P_B'"),
        # and joint public nonce ("R := R_A + R_B"). (Expected ECC point: "R + H'(Q_AB || R || m) * Q_AB")
        expected_ecc_point: ECC.EccPoint = signing_session.joint_nonce + (
            self.joint_pubkey.public_key_point * signing_session.joint_hash_e
        )
        return signature_ecc_point == expected_ecc_point

    def _verify_nonce_share_proof(self, nonce_dlog_proof: NIZKDiscreteLogProof) -> None:
        """
        Verifies the provided NIZK proof of knowledge (PoK) of discrete log for a nonce-share (i.e., proof of knowledge
        of the associated private nonce).

        :raises ValueError: if the provided zero-knowledge proof of knowledge (ZKPoK) of discrete logarithm is invalid.
        """
        dlog_proof_verifier = NIZKDiscreteLogVerifier(self.context.ecc_curve_config)
        if not dlog_proof_verifier.verify_proof(nonce_dlog_proof):
            party_str: str = "initiator" if self.party_id == self.context.INITIATING_PARTY else "responder"

            # TODO: Use a custom exception here, instead of ValueError (perhaps called InvalidNonceShareProofException).
            raise ValueError(
                f"Invalid NIZK proof of knowledge (PoK) of discrete logarithm received for 2-party ECC Schnorr signing"
                f" {party_str}'s nonce-share."
            )

    def _verify_public_nonce_share(self, public_nonce_share: ECC.EccPoint) -> None:
        """
        Verifies the provided public nonce-share ECC point lies on the configured elliptic curve and is not the
        Point-at-Infinity.
        """
        party_str: str = "initiating party" if self.party_id == self.context.INITIATING_PARTY else "responding party"

        # Ensure the Initiator-provided public nonce-share's ECC point is on the configured elliptic curve.
        if not self.context.verify_ecc_point(public_nonce_share):
            raise InvalidECCPointException(
                ecc_curve_config=self.context.ecc_curve_config,
                point_x=public_nonce_share.x,
                point_y=public_nonce_share.y,
                msg=f"Invalid public nonce-share received from 2-party ECC Schnorr signing sub-protocol's {party_str}"
            )
        # Ensure the Initiator-provided public nonce-share's ECC point is not the Point-at-Infinity.
        elif public_nonce_share.is_point_at_infinity():
            raise InvalidECCPublicKeyException(
                f"Invalid public nonce-share received from 2-party ECC Schnorr signing {party_str} -- Nonce ECC"
                f" point cannot be the Point-at-Infinity."
            )


class TwoPartySchnorrInitiatorSigningSession:
    context: TwoPartySchnorrContext
    session_id: uuid.UUID
    party_id: PartyId
    nonce_share: ECC.EccKey
    nonce_dlog_proof: NIZKDiscreteLogProof
    counterparty_nonce_proof_commitment: Optional[SealedDiscreteLogProofCommitment] = None

    def __init__(
            self,
            schnorr_context: TwoPartySchnorrContext,
            session_id: uuid.UUID,
            nonce_share_pair: ECC.EccKey,
            nonce_nizk_dlog_proof: NIZKDiscreteLogProof
    ):
        self.context = schnorr_context
        self.session_id = session_id
        self.party_id = TwoPartySchnorrContext.INITIATING_PARTY
        self.nonce_share = nonce_share_pair
        self.nonce_dlog_proof = nonce_nizk_dlog_proof

    @property
    def private_nonce(self) -> int:
        """Returns the 2-party ECC Schnorr signing sub-protocol's initiating party's private nonce-share."""
        return int(self.nonce_share.d)

    @property
    def public_nonce(self) -> ECC.EccPoint:
        """Returns the 2-party ECC Schnorr signing sub-protocol's initiating party's public nonce-share."""
        return self.nonce_share.pointQ


class TwoPartySchnorrResponderSigningSession:
    context: TwoPartySchnorrContext
    session_id: uuid.UUID
    party_id: PartyId
    nonce_share: ECC.EccKey
    nonce_dlog_proof: NIZKDiscreteLogProof
    nonce_dlog_proof_commitment: SealedDiscreteLogProofCommitment
    proof_commitment_verification_key: bytearray  # KeyedHashCommitment verification key
    signature_share: Optional[int] = None
    joint_nonce: Optional[ECC.EccPoint] = None
    joint_hash_e: Optional[int] = None

    def __init__(
            self,
            schnorr_context: TwoPartySchnorrContext,
            session_id: uuid.UUID,
            nonce_share_pair: ECC.EccKey,
            nonce_nizk_dlog_proof: NIZKDiscreteLogProof,
            sealed_nonce_dlog_proof_commitment: SealedDiscreteLogProofCommitment,
            nonce_dlog_proof_commitment_verification_key: bytearray
    ):
        self.context = schnorr_context
        self.session_id = session_id
        self.party_id = TwoPartySchnorrContext.RESPONDING_PARTY
        self.nonce_share = nonce_share_pair
        self.nonce_dlog_proof = nonce_nizk_dlog_proof
        self.nonce_dlog_proof_commitment = sealed_nonce_dlog_proof_commitment
        self.proof_commitment_verification_key = nonce_dlog_proof_commitment_verification_key

    @property
    def private_nonce(self) -> int:
        """Returns the 2-party ECC Schnorr signing sub-protocol's responding party's private nonce-share."""
        return int(self.nonce_share.d)

    @property
    def public_nonce(self) -> ECC.EccPoint:
        """Returns the 2-party ECC Schnorr signing sub-protocol's responding party's public nonce-share."""
        return self.nonce_share.pointQ


@attrs.define(slots=True)
class TwoPartySchnorrKeyShare:
    context: TwoPartySchnorrContext
    private_ecc_keypair: ECC.EccKey      # hardened public/private ECC key-share pair
    counterparty_ecc_pubkey: ECC.EccKey  # counterparty's hardened public ECC key-share

    @property
    def private_key_scalar(self) -> int:
        return int(self.private_ecc_keypair.d)

    @property
    def public_key_point(self) -> ECC.EccPoint:
        return self.private_ecc_keypair.pointQ

    @property
    def counterparty_pubkey_point(self) -> ECC.EccPoint:
        return self.counterparty_ecc_pubkey.pointQ

    @classmethod
    def from_unhardened_key_shares(
            cls,
            context: TwoPartySchnorrContext,
            party_id: PartyId,
            private_unhardened_key_share: ECC.EccKey,
            counterparty_public_unhardened_key_share: ECC.EccKey
    ) -> TwoPartySchnorrKeyShare:
        if not private_unhardened_key_share.has_private():
            raise ValueError("The 2-party ECC Schnorr (unhardened) private key-share must be a private key.")
        if private_unhardened_key_share.pointQ.is_point_at_infinity():
            raise InvalidECCPublicKeyException(
                "The 2-party ECC Schnorr (unhardened) public key-share must not be the Point-at-Infinity."
            )
        if counterparty_public_unhardened_key_share.has_private():
            raise InvalidECCPublicKeyException(
                "The counterparty's 2-party ECC Schnorr (unhardened) public key-share must be a public key."
            )
        if counterparty_public_unhardened_key_share.pointQ.is_point_at_infinity():
            raise InvalidECCPublicKeyException(
                "The counterparty's 2-party ECC Schnorr (unhardened) public key-share must not be the Point-at-"
                "Infinity."
            )

        hardened_key_share_pair, counterparty_hardened_pubkey = TwoPartySchnorrKeyShare._construct_hardened_key_shares(
            context,
            party_id,
            private_unhardened_key_share,
            counterparty_public_unhardened_key_share
        )

        return TwoPartySchnorrKeyShare(
            private_ecc_keypair=hardened_key_share_pair,
            counterparty_ecc_pubkey=counterparty_hardened_pubkey,
            context=context
        )

    @classmethod
    def _construct_hardened_key_shares(
            cls,
            context: TwoPartySchnorrContext,
            party_id: PartyId,
            private_unhardened_key_share: ECC.EccKey,
            counterparty_public_unhardened_key_share: ECC.EccKey
    ) -> (ECC.EccKey, ECC.EccKey):  # private ECC key-share, counterparty's ECC public key-share
        """
        Constructs a hardened ECC Schnorr public/private key-share pair and the counterparty's hardened ECC Schnorr
        public key-share, given the caller's unhardened ECC private key-share pair and the counterparty's unhardened
        ECC public key.
        :param context: two-party ECC Schnorr context containing shared parameters, including the ECC elliptic curve
               and chosen key & message hashing algorithms.
        :param party_id: PartyId indicating whether the caller is the two-party ECC Schnorr keys generation
               sub-protocol's Initiating or Responding party.
        :param private_unhardened_key_share: unhardened two-party ECC Schnorr private key-share.
        :param counterparty_public_unhardened_key_share: counterparty's unhardened two-party ECC Schnorr public
               key-share.
        :return: a tuple of ECC.EccKey containing the hardened ECC private key-share and the counterparty's hardened
                 ECC public key.
        """
        assert private_unhardened_key_share.has_private()
        assert not private_unhardened_key_share.pointQ.is_point_at_infinity()
        assert not counterparty_public_unhardened_key_share.has_private()
        assert not counterparty_public_unhardened_key_share.pointQ.is_point_at_infinity()

        keys_inner_hasher = hashlib.new(context.key_hash_algo)

        match party_id:
            case context.INITIATING_PARTY:  # caller is initiating party (P1)
                # Hash unhardened public key shares (exported SEC1-encoded) (i.e., "H(P1 || P2)").
                keys_inner_hasher.update(
                    context.encode_public_key(private_unhardened_key_share.public_key())
                )
                keys_inner_hasher.update(
                    context.encode_public_key(counterparty_public_unhardened_key_share)
                )
                unhardened_pubkeys_inner_hash: bytes = keys_inner_hasher.digest()

            case context.RESPONDING_PARTY:  # caller is responding party (P2)
                # Hash unhardened public key shares (exported SEC1-encoded) (i.e., "H(P1 || P2)").
                keys_inner_hasher.update(
                    context.encode_public_key(counterparty_public_unhardened_key_share)
                )
                keys_inner_hasher.update(
                    context.encode_public_key(private_unhardened_key_share.public_key())
                )
                unhardened_pubkeys_inner_hash: bytes = keys_inner_hasher.digest()

            case invalid:
                raise ValueError(
                    f"Invalid party ID provided constructing a {cls.__name__}: {invalid}"
                )

        # Construct a bit-length LSB(s)-truncated hasher w/ same bit-length as the ECC curve group's (<G>) order (q).
        truncated_hasher = PrimeLengthTruncatedHasher(context.ecc_curve_config.order, context.key_hash_algo)

        # Calculate outer hash of unhardened public keys: "h := H'(H(P1 || P2) || P1)" or "h := H'(H(P1 || P2) || P2)",
        # depending on whether Party #1 (initiator) or Party #2 (responder).
        outer_hash_int: int = truncated_hasher.update(
            unhardened_pubkeys_inner_hash  # H(P1 || P2)
        ).update(
            context.encode_public_key(
                private_unhardened_key_share.public_key()
            )
        ).intdigest()

        # Calculate hardened public key-share: "H'(H(P1 || P2) || P1)*P1" or "H'(H(P1 || P2) || P2)*P2", depending on
        # whether Party #1 (initiator) or Party #2 (responder).
        hardened_public_key_share: ECC.EccPoint = private_unhardened_key_share.pointQ * outer_hash_int

        # Ensure the calculated hardened public key-share's ECC point is not the Point-at-Infinity.
        if hardened_public_key_share.is_point_at_infinity():
            raise InvalidECCPublicKeyException(
                "The calculated 2-party ECC Schnorr (hardened) public key-share equals the Point-at-Infinity "
                "-- Key generation must be retried."
            )

        # Calculate hardened private key-share: "H'(H(P1 || P2) || P1)*x1 mod q" or "H'(H(P1 || P2)) || P2)*x2 mod q",
        # depending on whether Party #1 (initiator) or Party #2 (responder).
        hardened_private_key_share: int = (
                (outer_hash_int * int(private_unhardened_key_share.d)) % context.ecc_curve_config.order
        )

        hardened_key_share_pair: ECC.EccKey = ECC.construct(
            curve=context.ecc_curve_config.curve,
            d=hardened_private_key_share,
            point_x=hardened_public_key_share.x,
            point_y=hardened_public_key_share.y
        )

        # Calculate the counterparty's hardened public key-share.
        counterparty_public_key_share: ECC.EccKey = TwoPartySchnorrKeyShare._construct_counterparty_hardened_key_share(
            context,
            unhardened_pubkeys_inner_hash,
            counterparty_public_unhardened_key_share
        )

        return hardened_key_share_pair, counterparty_public_key_share

    @classmethod
    def _construct_counterparty_hardened_key_share(
            cls,
            context: TwoPartySchnorrContext,
            unhardened_pubkeys_inner_hash: bytes,
            counterparty_public_unhardened_key_share: ECC.EccKey
    ) -> ECC.EccKey:
        # Construct a bit-length LSB(s)-truncated hasher w/ same bit-length as the ECC curve group's (<G>) order (q).
        truncated_hasher = PrimeLengthTruncatedHasher(context.ecc_curve_config.order, context.key_hash_algo)

        # Calculate outer hash of unhardened public keys: "h := H'(H(P1 || P2) || P1)" or "h := H'(H(P1 || P2) || P2)",
        # depending on whether Party #1 (initiator) or Party #2 (responder).
        outer_hash_int: int = truncated_hasher.update(
            unhardened_pubkeys_inner_hash  # H(P1 || P2)
        ).update(
            context.encode_public_key(
                counterparty_public_unhardened_key_share
            )
        ).intdigest()

        # Calculate hardened public key-share: "H'(H(P1 || P2) || P1)*P1" or "H'(H(P1 || P2) || P2)*P2", depending on
        # whether Party #1 (initiator) or Party #2 (responder).
        hardened_public_key_share: ECC.EccPoint = counterparty_public_unhardened_key_share.pointQ * outer_hash_int

        # Ensure the calculated hardened public key-share's ECC point is not the Point-at-Infinity.
        if hardened_public_key_share.is_point_at_infinity():
            raise InvalidECCPublicKeyException(
                "The calculated 2-party ECC Schnorr (hardened) public key-share equals the Point-at-Infinity "
                "-- Key generation must be retried."
            )

        return context.ecc_point_to_pubkey(hardened_public_key_share)


class TwoPartySchnorrPublicKeyShare:
    context: TwoPartySchnorrContext
    public_ecc_key: ECC.EccKey

    def __init__(self, schnorr_context: TwoPartySchnorrContext, public_ecc_key_share: ECC.EccKey):
        self.context = schnorr_context
        self.public_ecc_key = public_ecc_key_share

    @classmethod
    def from_private_key_share(
            cls,
            schnorr_context: TwoPartySchnorrContext,
            private_key_share: TwoPartySchnorrKeyShare
    ) -> TwoPartySchnorrPublicKeyShare:
        public_key: ECC.EccKey = private_key_share.private_ecc_keypair.public_key()

        if public_key.pointQ.is_point_at_infinity():
            raise InvalidECCPublicKeyException(
                "Invalid 2-party ECC Schnorr private key-share -- Corresponding ECC public curve point must not be the"
                " Point-at-Infinity."
            )
        if not schnorr_context.ecc_curve_config.has_curve_name(public_key.curve):
            raise IncorrectECCCurveException(
                expected_ecc_curve=schnorr_context.ecc_curve_config.curve,
                provided_ecc_curve=public_key.curve,
                message="Invalid 2-party ECC Schnorr private key-share -- ECC key-pair's curve doesn't match provided "
                        "context"
            )

        return cls(schnorr_context, public_key)

    @classmethod
    def from_public_key_share(
            cls,
            schnorr_context: TwoPartySchnorrContext,
            public_ecc_key: ECC.EccKey
    ):
        if public_ecc_key.pointQ.is_point_at_infinity():
            raise InvalidECCPublicKeyException(
                "Invalid 2-party ECC Schnorr public key-share -- ECC public curve point must not be the"
                " Point-at-Infinity."
            )
        if not schnorr_context.ecc_curve_config.has_curve_name(public_ecc_key.curve):
            raise IncorrectECCCurveException(
                expected_ecc_curve=schnorr_context.ecc_curve_config.curve,
                provided_ecc_curve=public_ecc_key.curve,
                message="Invalid 2-party ECC Schnorr public key-share -- ECC key-pair's curve doesn't match provided"
                        " context"
            )

        return cls(schnorr_context, public_ecc_key)


@attrs.define(slots=True)
class JointSchnorrPublicKey:
    joint_ecc_pubkey: ECC.EccKey
    context: TwoPartySchnorrContext

    @property
    def public_key_point(self) -> ECC.EccPoint:
        return self.joint_ecc_pubkey.pointQ

    @classmethod
    def from_hardened_key_shares(
            cls,
            context: TwoPartySchnorrContext,
            private_key_share: ECC.EccKey,
            counterparty_public_key_share: ECC.EccKey
    ) -> JointSchnorrPublicKey:
        """
        Generate a joint Schnorr public key from a private hardened key-share and a counter-party's hardened public
        key share.
        :param context: cryptographic context including ECC shared parameters.
        :param private_key_share: the Schnorr private hardened key-share of the local party.
        :param counterparty_public_key_share: the Schnorr public hardened key-share of the counterparty.
        :return: a two-party Schnorr joint public key, constructed from a private hardened key-share and the
                 counterparty's public hardened key-share.
        """
        if not private_key_share.has_private():
            raise ValueError("The 2-party ECC Schnorr private key-share must be a private key.")
        if counterparty_public_key_share.has_private():
            raise ValueError("The counter-party's 2-party ECC Schnorr public key-share must be a public key.")
        # Verify both key-shares are on the same elliptic curve.
        # Note: The ECC.EccPoint class's constructor performs validation that a point is on the configured curve.
        if private_key_share.curve != counterparty_public_key_share.curve:
            raise ValueError("The 2-party ECC Schnorr key-shares must be on the same elliptic curve.")

        # Q := P1' + P2' = x1*G + P2' = P1' + x2*G
        joint_public_point: ECC.EccPoint = (
                private_key_share.pointQ + counterparty_public_key_share.pointQ
        )

        # Ensure the calculated (hardened) joint public key's ECC point is not the Point-at-Infinity.
        if joint_public_point.is_point_at_infinity():
            raise InvalidECCPublicKeyException(
                "The calculated 2-party ECC Schnorr (hardened) joint public key equals the Point-at-Infinity "
                "-- Key generation must be retried."
            )

        return JointSchnorrPublicKey(
            context.ecc_point_to_pubkey(joint_public_point),
            context=context
        )

    def verify_joint_signature(self, schnorr_signature: SchnorrSignature, message: bytes) -> bool:
        """
        Verifies a two-party ECC Schnorr digital signature for the given message and this two-party joint public key.
        <p>
        Calculates a signature verification ECC point ("R + H(Q || R || m)*Q"), where R is the signature's public nonce
        point, Q is the joint public key, and m is the message; and compares this ECC point to a point ("s*G")
        constructed from the signature's (integer) value (s) and the configured ECC curve's base point (G);
        returning True (valid) if these two calculated ECC points are equal, and False (invalid) if not. </p>
        
        :param schnorr_signature: two-party ECC Schnorr signature to be verified with this two-party joint public key.
        :param message: the message associated with the two-party ECC Schnorr signature being verified.
        :return: whether the provided two-party ECC Schnorr signature is a valid signature for the provided message
                 and this two-party joint public key.
        """
        # Ensure 2-party ECC Schnorr signature was constructed on the same ECC curve as the provided joint public key.
        if schnorr_signature.context.ecc_curve_config.curve != self.context.ecc_curve_config.curve:
            raise IncorrectECCSchnorrSignatureCurveException(
                schnorr_signature.context.ecc_curve_config.curve,
                self.context.ecc_curve_config.curve,
                "2-party ECC Schnorr signature was constructed on a different ECC curve than the joint public key "
                "provided for verification"
            )

        # Calculate the ECC point associated with the signature (integer) value (i.e., "s*G"), using the base point (G).
        signature_point: ECC.EccPoint = self.context.ecc_curve_config.base_point * schnorr_signature.signature

        # Encode the joint public key, using SEC1 encoding.
        joint_pubkey_bytes: bytes = self.context.encode_public_key(self.joint_ecc_pubkey)
        # Encode the signature's nonce point, using SEC1 encoding.
        signature_nonce_point_bytes: bytes = self.context.encode_ecc_point(schnorr_signature.public_nonce)

        # Calculate the truncated hash "e := H'(Q || R || m)" of the joint public key, the signature's public nonce
        # point & the message associated with the two-party Schnorr signature (truncated to the ECC curve's bit-length).
        truncated_hasher = PrimeLengthTruncatedHasher(self.context.ecc_curve_config.order, self.context.message_hash_algo)
        pubkey_nonce_message_hash: int = truncated_hasher.hash_to_int(
            joint_pubkey_bytes + signature_nonce_point_bytes + message  # concatenate bytes ("Q || R || m")
        )

        # Calculate the full verification point "R + e*Q", where R is the two-party signature's public nonce point,
        # e is the hash calculated above, and Q is the joint public key (ECC point).
        verification_point: ECC.EccPoint = schnorr_signature.public_nonce + (
                self.joint_ecc_pubkey.pointQ * pubkey_nonce_message_hash
        )

        return signature_point == verification_point
