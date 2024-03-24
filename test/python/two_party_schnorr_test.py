import unittest

from Cryptodome.PublicKey import ECC

from scriptless_zkp.ecc.ecc_utils import WeierstrassEllipticCurveConfig
from scriptless_zkp.ecc.zkp.nizk_dlog_proof_commitments import (
    SealedDiscreteLogProofCommitment, RevealedDiscreteLogProofCommitment
)
from scriptless_zkp.ecc.zkp.nizk_dlog_proof import NIZKDiscreteLogVerifier, NIZKDiscreteLogProof
from scriptless_zkp.ecc.signatures.schnorr import SchnorrSignature
from scriptless_zkp.ecc.signatures.two_party_schnorr import (
    JointSchnorrPublicKey, TwoPartySchnorrContext, TwoPartySchnorrSigner, TwoPartySchnorrKeyShare,
    TwoPartySchnorrInitiatorSigningSession, TwoPartySchnorrResponderSigningSession
)


class TwoPartyECCSchnorrTests(unittest.TestCase):
    """
    Integration tests for 2-party ECC Schnorr digital signatures, including the joint key generation and joint signing
    protocols.
    """
    context = TwoPartySchnorrContext(WeierstrassEllipticCurveConfig.secp256r1())
    test_message = "No one expects the Inquisition!"

    @property
    def encoded_test_message(self) -> bytes:
        return self.test_message.encode('utf-8')

    def test_two_party_Schnorr_key_shares_generation_initiator(self):
        """
        Integration test for generation of hardened key-shares in the joint key generation protocol, from the
        perspective of the protocol's initiating party.
        """
        initiator_unhardened_key_share: ECC.EccKey = self.context.generate_unhardened_key_share()
        # Protocol: Send initiator's public unhardened key-share to counterparty (responder).

        # Protocol: Simulate receipt of responder's public unhardened key-share.
        responder_public_unhardened_key_share: ECC.EccKey = self.context.generate_unhardened_key_share().public_key()

        # Calculate hardened key-share pair & counterparty's hardened public key-share, from unhardened key-share pair
        # and counterparty's unhardened public key-share.
        hardened_key_share = TwoPartySchnorrKeyShare.from_unhardened_key_shares(
            self.context,
            TwoPartySchnorrContext.INITIATING_PARTY,
            initiator_unhardened_key_share,
            responder_public_unhardened_key_share
        )

        self.assertEqual(hardened_key_share.context, self.context)

        self.assertTrue(hardened_key_share.private_ecc_keypair.has_private())
        self.assertFalse(hardened_key_share.private_ecc_keypair.pointQ.is_point_at_infinity())

        self.assertFalse(hardened_key_share.counterparty_ecc_pubkey.has_private())
        self.assertFalse(hardened_key_share.counterparty_ecc_pubkey.pointQ.is_point_at_infinity())

    def test_two_party_Schnorr_key_shares_generation_responder(self):
        """
        Integration test for generation of hardened key-shares in the joint key generation protocol, from the
        perspective of the protocol's responding party.
        """
        responder_unhardened_key_share: ECC.EccKey = self.context.generate_unhardened_key_share()
        # Protocol: Send responder's public unhardened key-share to counterparty (initiator).

        # Protocol: Simulate receipt of initiator's public unhardened key-share.
        initiator_public_unhardened_key_share: ECC.EccKey = self.context.generate_unhardened_key_share().public_key()

        hardened_key_share = TwoPartySchnorrKeyShare.from_unhardened_key_shares(
            self.context,
            TwoPartySchnorrContext.RESPONDING_PARTY,
            responder_unhardened_key_share,
            initiator_public_unhardened_key_share
        )

        self.assertEqual(hardened_key_share.context, self.context)

        self.assertTrue(hardened_key_share.private_ecc_keypair.has_private())
        self.assertFalse(hardened_key_share.private_ecc_keypair.pointQ.is_point_at_infinity())

        self.assertFalse(hardened_key_share.counterparty_ecc_pubkey.has_private())
        self.assertFalse(hardened_key_share.counterparty_ecc_pubkey.pointQ.is_point_at_infinity())

    def test_two_party_Schnorr_joint_pubkey_generation_initiator(self):
        """
        Integration test for generation of the joint public key in the joint key generation protocol, from the
        perspective of the protocol's initiating party.
        """
        initiator_unhardened_key_share: ECC.EccKey = self.context.generate_unhardened_key_share()
        # Protocol: Send initiator's public unhardened key-share to counterparty (responder).

        # Protocol: Simulate receipt of responder's public unhardened key-share.
        responder_public_unhardened_key_share: ECC.EccKey = self.context.generate_unhardened_key_share().public_key()

        # Calculate hardened key-share pair & counterparty's hardened public key-share, from unhardened key-share pair
        # and counterparty's unhardened public key-share.
        hardened_key_share = TwoPartySchnorrKeyShare.from_unhardened_key_shares(
            self.context,
            TwoPartySchnorrContext.INITIATING_PARTY,
            initiator_unhardened_key_share,
            responder_public_unhardened_key_share
        )

        joint_key: ECC.EccKey = JointSchnorrPublicKey.from_hardened_key_shares(
            self.context,
            hardened_key_share.private_ecc_keypair,
            hardened_key_share.counterparty_ecc_pubkey
        ).joint_ecc_pubkey

        self.assertFalse(joint_key.has_private())
        self.assertFalse(joint_key.pointQ.is_point_at_infinity())

    def test_two_party_Schnorr_joint_pubkey_generation_responder(self):
        """
        Integration test for generation of the joint public key in the joint key generation protocol, from the
        perspective of the protocol's responding party.
        """
        responder_unhardened_key_share: ECC.EccKey = self.context.generate_unhardened_key_share()
        # Protocol: Send responder's public unhardened key-share to counterparty (initiator).

        # Protocol: Simulate receipt of initiator's public unhardened key-share.
        initiator_public_unhardened_key_share: ECC.EccKey = self.context.generate_unhardened_key_share().public_key()

        hardened_key_share = TwoPartySchnorrKeyShare.from_unhardened_key_shares(
            self.context,
            TwoPartySchnorrContext.RESPONDING_PARTY,
            responder_unhardened_key_share,
            initiator_public_unhardened_key_share
        )

        joint_key: ECC.EccKey = JointSchnorrPublicKey.from_hardened_key_shares(
            self.context,
            hardened_key_share.private_ecc_keypair,
            hardened_key_share.counterparty_ecc_pubkey
        ).joint_ecc_pubkey

        self.assertFalse(joint_key.has_private())
        self.assertFalse(joint_key.pointQ.is_point_at_infinity())

    def test_two_party_Schnorr_initiator_and_responder_joint_pubkeys(self):
        """
        Integration test for generation of the joint public key in the joint key generation protocol, from the
        perspective of both the protocol's initiating and responding parties, which also verifies the joint public
        keys calculated by each party are equal.
        """
        initiator_unhardened_key_share: ECC.EccKey = self.context.generate_unhardened_key_share()
        responder_unhardened_key_share: ECC.EccKey = self.context.generate_unhardened_key_share()

        # Calculate hardened key-share pair & counterparty's hardened public key-share, from unhardened key-share pair
        # and counterparty's unhardened public key-share.
        initiator_hardened_key_share = TwoPartySchnorrKeyShare.from_unhardened_key_shares(
            self.context,
            TwoPartySchnorrContext.INITIATING_PARTY,
            initiator_unhardened_key_share,
            responder_unhardened_key_share.public_key()
        )

        # Calculate hardened key-share pair & counterparty's hardened public key-share, from unhardened key-share pair
        # and counterparty's unhardened public key-share.
        responder_hardened_key_share = TwoPartySchnorrKeyShare.from_unhardened_key_shares(
            self.context,
            TwoPartySchnorrContext.RESPONDING_PARTY,
            responder_unhardened_key_share,
            initiator_unhardened_key_share.public_key()
        )

        # Verify the Initiator's calculated public key-share for the Responder equals that calculated by the Responder.
        self.assertEqual(
            initiator_hardened_key_share.counterparty_pubkey_point,  # Initiator-calc. public key-share for Responder
            responder_hardened_key_share.public_key_point            # Responder's public key-share
        )
        # Verify the Responder's calculated public key-share for the Initiator equals that calculated by the Initiator.
        self.assertEqual(
            responder_hardened_key_share.counterparty_pubkey_point,  # Responder-calc. public key-share for Initiator
            initiator_hardened_key_share.public_key_point            # Initiator's public key-share
        )

        # Calculate joint public key as the collaborative key-generation protocol Initiator.
        initiator_joint_key: ECC.EccKey = JointSchnorrPublicKey.from_hardened_key_shares(
            self.context,
            initiator_hardened_key_share.private_ecc_keypair,
            initiator_hardened_key_share.counterparty_ecc_pubkey
        ).joint_ecc_pubkey

        self.assertFalse(initiator_joint_key.has_private())
        self.assertFalse(initiator_joint_key.pointQ.is_point_at_infinity())

        # Calculate joint public key as the collaborative key-generation protocol Responder.
        responder_joint_key: ECC.EccKey = JointSchnorrPublicKey.from_hardened_key_shares(
            self.context,
            responder_hardened_key_share.private_ecc_keypair,
            responder_hardened_key_share.counterparty_ecc_pubkey
        ).joint_ecc_pubkey

        self.assertFalse(responder_joint_key.has_private())
        self.assertFalse(responder_joint_key.pointQ.is_point_at_infinity())

        # Verify the joint public key calculated by the Initiator is equal to that calculated by the Responder.
        self.assertEqual(initiator_joint_key.pointQ, responder_joint_key.pointQ)

    def test_two_party_Schnorr_initiating_signer_init(self):
        """
        Integration test for initialization of the Initiator's signer in the joint signing protocol, from the
        perspective of the protocol's initiating party.
        """
        initiator_unhardened_key_share: ECC.EccKey = self.context.generate_unhardened_key_share()
        # Protocol: Send initiator's public unhardened key-share to counterparty (responder) over an authenticated
        #   channel.

        # Protocol: Simulate receipt of responder's public unhardened key-share over an authenticated channel.
        counterparty_public_unhardened_key_share: ECC.EccKey = self.context.generate_unhardened_key_share().public_key()

        initiating_signer = TwoPartySchnorrSigner.for_initiating_party(
            self.context,
            initiator_unhardened_key_share,
            counterparty_public_unhardened_key_share
        )

        self.assertEqual(initiating_signer.key_share.context, self.context)
        self.assertEqual(initiating_signer.party_id, TwoPartySchnorrContext.INITIATING_PARTY)

        self.assertTrue(initiating_signer.key_share.private_ecc_keypair.has_private())
        self.assertFalse(initiating_signer.key_share.private_ecc_keypair.pointQ.is_point_at_infinity())

        self.assertFalse(initiating_signer.key_share.counterparty_ecc_pubkey.has_private())
        self.assertFalse(initiating_signer.key_share.counterparty_ecc_pubkey.pointQ.is_point_at_infinity())

        self.assertEqual(initiating_signer.joint_pubkey.context, self.context)
        self.assertFalse(initiating_signer.joint_pubkey.joint_ecc_pubkey.has_private())
        self.assertFalse(initiating_signer.joint_pubkey.joint_ecc_pubkey.pointQ.is_point_at_infinity())

        signing_session = initiating_signer.init_signing()

        self.assertIsInstance(signing_session, TwoPartySchnorrInitiatorSigningSession)
        self.assertEqual(signing_session.party_id, TwoPartySchnorrContext.INITIATING_PARTY)
        self.assertTrue(signing_session.nonce_share.has_private())
        self.assertFalse(signing_session.nonce_share.pointQ.is_point_at_infinity())

        # Verify valid ZKPoK of discrete log for the signing session's Nonce dlog proof.
        dlog_proof_verifier = NIZKDiscreteLogVerifier(self.context.ecc_curve_config)
        self.assertTrue(dlog_proof_verifier.verify_proof(signing_session.nonce_dlog_proof))

    def test_two_party_Schnorr_responding_signer_init(self):
        """
        Integration test for initialization of the Responder's signer in the joint signing protocol, from the
        perspective of the protocol's responding party.
        """
        responder_unhardened_key_share: ECC.EccKey = self.context.generate_unhardened_key_share()
        # Protocol: Send responder's public unhardened key-share to counterparty (initiator) over an authenticated
        #   channel.

        # Protocol: Receive initiator's public unhardened key-share over an authenticated channel.
        counterparty_public_unhardened_key_share: ECC.EccKey = self.context.generate_unhardened_key_share().public_key()

        responding_signer = TwoPartySchnorrSigner.for_responding_party(
            self.context,
            responder_unhardened_key_share,
            counterparty_public_unhardened_key_share
        )

        self.assertEqual(responding_signer.key_share.context, self.context)
        self.assertEqual(responding_signer.party_id, TwoPartySchnorrContext.RESPONDING_PARTY)

        self.assertTrue(responding_signer.key_share.private_ecc_keypair.has_private())
        self.assertFalse(responding_signer.key_share.private_ecc_keypair.pointQ.is_point_at_infinity())

        self.assertFalse(responding_signer.key_share.counterparty_ecc_pubkey.has_private())
        self.assertFalse(responding_signer.key_share.counterparty_ecc_pubkey.pointQ.is_point_at_infinity())

        self.assertEqual(responding_signer.joint_pubkey.context, self.context)
        self.assertFalse(responding_signer.joint_pubkey.joint_ecc_pubkey.has_private())
        self.assertFalse(responding_signer.joint_pubkey.joint_ecc_pubkey.pointQ.is_point_at_infinity())

        signing_session = responding_signer.init_signing()

        self.assertIsInstance(signing_session, TwoPartySchnorrResponderSigningSession)
        self.assertEqual(signing_session.party_id, TwoPartySchnorrContext.RESPONDING_PARTY)
        self.assertTrue(signing_session.nonce_share.has_private())
        self.assertFalse(signing_session.nonce_share.pointQ.is_point_at_infinity())

        # Verify valid ZKPoK of discrete log for the signing session's Nonce dlog proof.
        dlog_proof_verifier = NIZKDiscreteLogVerifier(self.context.ecc_curve_config)
        self.assertTrue(dlog_proof_verifier.verify_proof(signing_session.nonce_dlog_proof))

    def test_two_party_Schnorr_initiating_signer_signature(self):
        """
        Integration test for calculation of the Initiator's 2-party ECC Schnorr signature in the joint signing protocol,
        from the perspective of the protocol's initiating party.
        """
        initiator_unhardened_key_share: ECC.EccKey = self.context.generate_unhardened_key_share()
        # Protocol: Send initiator's public unhardened key-share to counterparty (responder) over an authenticated
        #   channel.

        # Protocol: Simulate receipt of responder's public unhardened key-share over an authenticated channel.
        _counterparty_unhardened_key_share: ECC.EccKey = self.context.generate_unhardened_key_share()
        counterparty_public_unhardened_key_share: ECC.EccKey = _counterparty_unhardened_key_share.public_key()

        # Initialize initiator's two-party signer, incl. calculation of its hardened key-share pair & its counterparty's
        # (responder's) hardened public key-share.
        initiating_signer = TwoPartySchnorrSigner.for_initiating_party(
            self.context,
            initiator_unhardened_key_share,
            counterparty_public_unhardened_key_share.public_key()
        )

        # Initialize initiator's signing session, incl. calculation of its nonce-share & assoc. ZKPoK of dlog.
        signing_session = initiating_signer.init_signing()
        self.assertIsInstance(signing_session, TwoPartySchnorrInitiatorSigningSession)

        # Verify the signing session's nonce-share is the same as the dlog reference point for the nonce dlog proof.
        self.assertEqual(
            signing_session.public_nonce,
            signing_session.nonce_dlog_proof.dlog_reference_point
        )

        # Verify valid ZKPoK of discrete log for the signing session's Nonce dlog proof:
        dlog_proof_verifier = NIZKDiscreteLogVerifier(self.context.ecc_curve_config)
        self.assertIsInstance(dlog_proof_verifier, NIZKDiscreteLogVerifier)
        self.assertTrue(
            dlog_proof_verifier.verify_proof(signing_session.nonce_dlog_proof)
        )

        # Protocol: Simulate Responder's signer initialization & receipt of their public key-share (P_B'), over an
        #   authenticated channel.
        _responding_signer, _responder_signing_session = self._simulate_responder_signer_init(
            _counterparty_unhardened_key_share,
            initiator_unhardened_key_share.public_key()
        )
        responder_pub_keyshare: ECC.EccKey = _responding_signer.key_share.private_ecc_keypair.public_key()
        # DEBUG:
        print(f"Received Responder public key-share (P_B'): {responder_pub_keyshare!s}")

        # Protocol: Simulate receipt of string-encoded keyed-hash commitment to responder's public nonce-share & ZKPoK
        #   of dlog (re: their private nonce-share).
        encoded_responder_commitment: str = _responder_signing_session.nonce_dlog_proof_commitment.encode_as_string()
        # DEBUG
        print(f"Received Responder commitment to nonce-share & ZKPoK proof (encoded): {encoded_responder_commitment}")
        # Decode string-encoded keyed-hash commitment from responder.
        responder_commitment = SealedDiscreteLogProofCommitment.from_string_encoding(encoded_responder_commitment)
        self.assertIsInstance(responder_commitment, SealedDiscreteLogProofCommitment)

        # Protocol: Simulate sending of initiator's public nonce-share & ZKPoK of dlog for their private nonce-share to
        #   counterparty (responder), over an authenticated channel.
        encoded_initiator_nonce_proof: str = signing_session.nonce_dlog_proof.encode_as_string()
        # DEBUG
        print(f"Initiator nonce-share ZKPoK proof (encoded): {encoded_initiator_nonce_proof}")
        # Protocol:  Decode string-encoded initiator nonce proof.
        initiator_nonce_proof = NIZKDiscreteLogProof.from_string_encoding(encoded_initiator_nonce_proof)
        self.assertIsInstance(initiator_nonce_proof, NIZKDiscreteLogProof)

        # Protocol: Simulate receipt of responder's reveal of its keyed-hash commitment: incl. ZKPoK of dlog for their
        #   private nonce-share & commitment verification key, over an authenticated channel:
        encoded_revealed_responder_commitment: str = RevealedDiscreteLogProofCommitment.for_committed_proof(
            responder_commitment,
            _responder_signing_session.nonce_dlog_proof,
            _responder_signing_session.proof_commitment_verification_key
        ).encode_as_string()
        # DEBUG
        print(f"Responder revealed commitment (encoded): {encoded_revealed_responder_commitment}")
        # Decode string-encoded revealed ZKPoK commitment received from Responder.
        revealed_responder_commitment = RevealedDiscreteLogProofCommitment.from_string_encoding(
            encoded_revealed_responder_commitment
        )
        self.assertIsInstance(revealed_responder_commitment, RevealedDiscreteLogProofCommitment)

        responder_nonce_proof: NIZKDiscreteLogProof = revealed_responder_commitment.committed_dlog_proof
        # Obtain responder's public nonce-share from decoded revealed ZKPoK of dlog commitment.
        responder_public_nonce_share: ECC.EccPoint = responder_nonce_proof.dlog_reference_point
        # Verify the responder's public nonce-share equals the dlog reference point in their nonce-share ZKPoK proof
        # (as received via the revealed commitment).
        self.assertEqual(
            responder_public_nonce_share,
            _responder_signing_session.public_nonce
        )

        # Verify the Responder's revealed commitment is valid.
        #   - NOTE: This check is also performed by the Initiator's calc_full_signature() method call below.
        self.assertTrue(
            revealed_responder_commitment.verify(responder_commitment.commitment)
        )
        # Verify responder's ZKPoK proof re: its nonce-share is valid (raises exception on failure).
        #   - NOTE: This check is also performed by the Initiator's calc_full_signature() method call below.
        self.assertTrue(
            dlog_proof_verifier.verify_proof(responder_nonce_proof)
        )

        # Protocol: Simulate receipt of responder's 2-party ECC Schnorr signature-share, over an authenticated channel.
        responder_signature_share: int = _responding_signer.calc_responder_signature_share(
            _responder_signing_session,
            signing_session.public_nonce,
            signing_session.nonce_dlog_proof,
            self.encoded_test_message
        ).signature_share
        # DEBUG
        print(f"Received Responder signature-share (int): {responder_signature_share}")

        # Calculate 2-party ECC Schnorr (full) signature, incl. verification of the responder's signature-share.
        joint_schnorr_sig: SchnorrSignature = initiating_signer.calc_full_signature(
            signing_session,
            responder_commitment,
            revealed_responder_commitment,
            responder_public_nonce_share,
            responder_signature_share,
            self.encoded_test_message
        )
        self.assertIsInstance(joint_schnorr_sig, SchnorrSignature)

        # Verify the calculated 2-party ECC Schnorr (full) signature is valid for the given test message.
        self.assertTrue(
            initiating_signer.joint_pubkey.verify_joint_signature(joint_schnorr_sig, self.encoded_test_message)
        )

    # TODO: Implement the additional protocol logic demonstrated in this protocol test in a 2-party ECC Schnorr joint
    #   signing protocol client, including message sending & receipt, and associated received message verifications
    #   (incl. tracking & verification of a protocol instance's session ID and received messages' expected Party ID).
    # TODO: An associated joint key-generation protocol client will also be needed (but should perhaps be part of the
    #   same network-enabled client).
    # NOTE: Network communication can be simulated via two shared Python (message) queues, which could be used to
    #   implement a simulated network backend for these protocol clients, facilitating testing of the protocol logic in
    #   a more realistic end-to-end configuration (and/or use of these protocols via a CLI).
    #
    # NOTE: This integration test is verifying (& simulating) several aspects of the 2-party ECC Schnorr signing
    #   protocol, including:
    #   - Joint key generation via the 2-party key generation protocol, including Responder's signer initialization.
    #   - Responder's signing session initialization, incl. calculation of its nonce-share & ZKPoK of dlog for its
    #     nonce-share, and a keyed-hash commitment to its public nonce-share & assoc. ZKPoK proof.
    #   - Sending of this commitment to the signing protocol Initiator.
    #   - Receipt and verification of the Initiator's public nonce-share & ZKPoK of dlog for its nonce-share.
    #   - Sending of the revealed keyed-hash commitment to the Initiator, incl. the responder's public nonce-share &
    #     ZKPoK of its dlog.
    #   - Sending of the Responder's 2-party ECC Schnorr signature-share to the Initiator.
    #   - Receipt and verification of the Initiator's calculated full joint signature.
    def test_two_party_Schnorr_responding_signer_signature(self):
        """
        Integration test for calculation of the Responder's 2-party ECC Schnorr signature-share in the joint signing
        protocol, from the perspective of the protocol's responding party, in addition to verification of the
        Initiator's calculated full joint signature.
        """
        responder_unhardened_key_share: ECC.EccKey = self.context.generate_unhardened_key_share()
        # Protocol: Send responder's public unhardened key-share to counterparty (initiator) over an authenticated
        #   channel.

        # Protocol: Simulate receipt of initiator's public unhardened key-share, over an authenticated channel.
        _counterparty_unhardened_key_share: ECC.EccKey = self.context.generate_unhardened_key_share()
        counterparty_public_unhardened_key_share: ECC.EccKey = _counterparty_unhardened_key_share.public_key()

        # Initialize responder's two-party signer, incl. calculation of its hardened key-share pair & its counterparty's
        # (initiator's) hardened public key-share.
        responding_signer = TwoPartySchnorrSigner.for_responding_party(
            self.context,
            responder_unhardened_key_share,
            counterparty_public_unhardened_key_share.public_key()
        )

        # Initialize responder's signing session, incl. calculation of its nonce-share & assoc. ZKPoK of dlog.
        signing_session: TwoPartySchnorrResponderSigningSession = responding_signer.init_signing()
        self.assertIsInstance(signing_session, TwoPartySchnorrResponderSigningSession)

        # Verify the signing session's nonce-share is the same as the dlog reference point for the nonce dlog proof.
        self.assertEqual(
            signing_session.public_nonce,
            signing_session.nonce_dlog_proof.dlog_reference_point
        )
        # Verify valid ZKPoK of discrete log for the signing session's nonce dlog proof:
        dlog_proof_verifier = NIZKDiscreteLogVerifier(self.context.ecc_curve_config)
        self.assertIsInstance(dlog_proof_verifier, NIZKDiscreteLogVerifier)
        self.assertTrue(
            dlog_proof_verifier.verify_proof(signing_session.nonce_dlog_proof)
        )
        # Verify the keyed-hash commitment is valid (i.e., prior to simulating its sending to the Initiator):
        revealed_commitment: RevealedDiscreteLogProofCommitment = signing_session.nonce_dlog_proof_commitment.reveal(
            signing_session.nonce_dlog_proof,
            signing_session.proof_commitment_verification_key
        )
        self.assertTrue(
            revealed_commitment.verify(signing_session.nonce_dlog_proof_commitment.commitment)
        )

        # Protocol: Simulate sending responder's keyed-hash commitment to its public nonce-share & assoc. ZKPoK of
        #   its dlog (i.e., their private nonce-share), to the signing protocol initiator over an authenticated channel.
        encoded_responder_commitment: str = signing_session.nonce_dlog_proof_commitment.encode_as_string()
        # DEBUG
        print(f"Responder commitment (encoded): {encoded_responder_commitment}")
        # Protocol: Simulate initiator's receipt of responder's keyed-hash commitment to its public nonce-share & assoc.
        #   ZKPoK of its dlog (verifying correct decoding into a SealedDiscreteLogProofCommitment):
        # Decode string-encoded keyed-hash commitment from responder (simulating initiator's receipt of it).
        responder_commitment = SealedDiscreteLogProofCommitment.from_string_encoding(encoded_responder_commitment)
        # Verify correct decoding of responder's keyed-hash commitment to its public nonce-share & assoc. ZKPoK.
        self.assertIsInstance(responder_commitment, SealedDiscreteLogProofCommitment)

        # Protocol: Simulate Initiator's signer initialization & receipt of their public key-share (P_A'), over an
        #   authenticated channel.
        _initiating_signer, _initiator_signing_session = self._simulate_initiator_signer_init(
            _counterparty_unhardened_key_share,
            responder_unhardened_key_share.public_key()
        )
        self.assertIsInstance(_initiating_signer, TwoPartySchnorrSigner)
        self.assertIsInstance(_initiator_signing_session, TwoPartySchnorrInitiatorSigningSession)
        initiator_pub_keyshare: ECC.EccKey = _initiating_signer.key_share.private_ecc_keypair.public_key()
        # DEBUG:
        print(f"Received Initiator public key-share (P_A'): {initiator_pub_keyshare!s}")

        # Protocol: Simulate receipt of initiator's string-encoded public nonce-share & ZKPoK of dlog (re: their private
        #   nonce-share).
        encoded_initiator_nonce_proof: str = _initiator_signing_session.nonce_dlog_proof.encode_as_string()
        # DEBUG
        print(f"Received Initiator nonce-share ZKPoK proof (encoded): {encoded_initiator_nonce_proof}")
        # Decode string-encoded initiator nonce proof.
        initiator_nonce_proof = NIZKDiscreteLogProof.from_string_encoding(encoded_initiator_nonce_proof)
        # Verify correct decoding of initiator's ZKPoK of dlog for its nonce-share.
        self.assertIsInstance(initiator_nonce_proof, NIZKDiscreteLogProof)

        # Protocol: Verify received Initiator's ZKPoK proof for its nonce-share and the associated nonce-share:
        # Obtain initiator's public nonce-share from the decoded ZKPoK of dlog proof.
        initiator_public_nonce_share: ECC.EccPoint = initiator_nonce_proof.dlog_reference_point
        # Verify the Initiator's public nonce-share equals the dlog reference point in their nonce-share ZKPoK proof.
        self.assertEqual(
            initiator_public_nonce_share,
            _initiator_signing_session.public_nonce
        )
        # Verify valid ZKPoK of discrete log for the initiator's nonce dlog proof.
        #   - NOTE: This check is also performed by the Responder's calc_responder_signature_share() method call below.
        self.assertTrue(
            dlog_proof_verifier.verify_proof(initiator_nonce_proof)
        )

        # Calculate responder's 2-party ECC Schnorr signature-share.
        signing_session = responding_signer.calc_responder_signature_share(
            signing_session,
            initiator_public_nonce_share,
            initiator_nonce_proof,
            self.encoded_test_message
        )
        # Protocol: Simulate sending of responder's 2-party ECC Schnorr signature-share, over an authenticated channel.
        responder_signature_share: int = signing_session.signature_share
        # DEBUG: Simulating sending of responder's signature-share.
        print(f"Responder signature-share (int): {responder_signature_share}")

        # Protocol: Simulate sending of responder's reveal of its keyed-hash commitment: incl. ZKPoK of dlog for their
        #   private nonce-share & commitment verification key, to the signing protocol initiator over an authenticated
        #   channel.
        encoded_revealed_responder_commitment: str = signing_session.nonce_dlog_proof_commitment.reveal(
            signing_session.nonce_dlog_proof,
            signing_session.proof_commitment_verification_key
        ).encode_as_string()
        # DEBUG: Simulating sending of responder's revealed keyed-hash commitment.
        print(f"Responder revealed commitment (encoded): {encoded_revealed_responder_commitment}")

        # Protocol: Simulate initiator's receipt of responder's revealed keyed-hash commitment: incl. public nonce-
        #   share, its ZKPoK of dlog & the commitment's verification key, over an authenticated channel.
        # Decode string-encoded revealed ZKPoK commitment received from Responder.
        revealed_responder_commitment = RevealedDiscreteLogProofCommitment.from_string_encoding(
            encoded_revealed_responder_commitment
        )
        self.assertIsInstance(revealed_responder_commitment, RevealedDiscreteLogProofCommitment)
        # Simulate the initiator's verification of the responder's revealed commitment is valid.
        self.assertTrue(
            revealed_responder_commitment.verify(responder_commitment.commitment)
        )

        # Protocol: Simulate receipt of initiator-constructed full signature.
        encoded_joint_schnorr_sig: str = _initiating_signer.calc_full_signature(
            _initiator_signing_session,
            signing_session.nonce_dlog_proof_commitment,
            revealed_responder_commitment,
            signing_session.public_nonce,
            signing_session.signature_share,
            self.encoded_test_message
        ).encode_as_string()
        # DEBUG
        print(f"Received joint Schnorr signature (encoded): {encoded_joint_schnorr_sig}")
        # Decode received string-encoded joint Schnorr signature.
        joint_schnorr_sig = SchnorrSignature.from_string_encoding(
            encoded_joint_schnorr_sig,
            self.context.as_schnorr_context()
        )
        self.assertIsInstance(joint_schnorr_sig, SchnorrSignature)

        # Verify the joint signature received by the signing protocol initiator is valid for the given test message.
        self.assertTrue(
            responding_signer.joint_pubkey.verify_joint_signature(joint_schnorr_sig, self.encoded_test_message)
        )

    def _simulate_responder_signer_init(
            self,
            responder_unhardened_key_share: ECC.EccKey,
            initiator_public_unhardened_key_share: ECC.EccKey,
    ) -> (TwoPartySchnorrSigner, TwoPartySchnorrResponderSigningSession):

        responding_signer = TwoPartySchnorrSigner.for_responding_party(
            self.context,
            responder_unhardened_key_share,
            initiator_public_unhardened_key_share
        )

        responder_signing_session: TwoPartySchnorrResponderSigningSession = responding_signer.init_signing()

        return responding_signer, responder_signing_session

    def _simulate_initiator_signer_init(
            self,
            initiator_unhardened_key_share: ECC.EccKey,
            responder_public_unhardened_key_share: ECC.EccKey
    ) -> (TwoPartySchnorrSigner, TwoPartySchnorrInitiatorSigningSession):
        initiating_signer = TwoPartySchnorrSigner.for_initiating_party(
            self.context,
            initiator_unhardened_key_share,
            responder_public_unhardened_key_share
        )

        initiator_signing_session: TwoPartySchnorrInitiatorSigningSession = initiating_signer.init_signing()

        return initiating_signer, initiator_signing_session


if __name__ == '__main__':
    unittest.main()
