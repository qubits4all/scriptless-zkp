"""
Provides a non-interactive zero-knowledge (NIZK) proof of knowledge (PoK) of N _equal_ discrete logarithms, over a
prime-order elliptic curve group (e.g., NIST P-256).
- This NIZK proof construction is based on the `Chaum-Pedersen (interactive) protocol
<https://link.springer.com/content/pdf/10.1007/3-540-48071-4_7.pdf>` for proving knowledge in ZK of _two_ equal discrete
logarithms, which has been adapted to operate over elliptic curves and generalized from 2 to N equal discrete logs.
- The `Fiat-Shamir transform <https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic>` is then used to produce a
non-interactive ZK proof construction, featuring both non-interactive proof generation & verification.
"""
from __future__ import annotations

from collections import OrderedDict
from typing import OrderedDict, NewType

from Cryptodome.PublicKey import ECC

from scriptless_zkp.ecc.ecc_utils import generate_random_nonce
from scriptless_zkp.ecc.weierstrass_curves import WeierstrassEllipticCurveConfig

from scriptless_zkp.hashing import PrimeLengthTruncatedHasher


DEFAULT_HASH_ALGORITHM = 'sha3_256'  # Note: Suitable for 255 & 256-bit elliptic curves.
DOMAIN_SEPARATION_TAG = 'nizk_equal_dlogs_proof_pub_hash'

NIZKEqualDiscreteLogsProofSignature = NewType('NIZKEqualDiscreteLogsProofSignature', int)
"""
Efficient type for the NIZK proof's signature, which auto-casts to an `int`, but not from an `int`, providing type
safety in function & method calls (i.e., where other int-typed parameters may be present).
"""

NIZKEqualDiscreteLogsProofHash = NewType('NIZKEqualDiscreteLogsProofHash', int)
"""
Efficient type for the NIZK proof's public hash, which auto-casts to an `int`, but not from an `int, providing type
safety in function & method calls (i.e., where other int-typed parameters may be present).
"""


class NIZKDiscreteLogParametersSet:
    curve_config: WeierstrassEllipticCurveConfig
    dlog_ref_points_by_base: OrderedDict[ECC.EccPoint, ECC.EccPoint]

    def __init__(
            self,
            curve_config: WeierstrassEllipticCurveConfig,
            dlog_ref_points_by_base: OrderedDict[ECC.EccPoint, ECC.EccPoint]
    ):
        self.curve_config = curve_config
        self.dlog_ref_points_by_base = dlog_ref_points_by_base


class NIZKEqualDiscreteLogsProof:
    common: NIZKEqualDiscreteLogsCommon
    discrete_log_params_set: NIZKDiscreteLogParametersSet
    proof_pub_hash: NIZKEqualDiscreteLogsProofHash
    proof_signature: NIZKEqualDiscreteLogsProofSignature
    hash_algo: str

    def __init__(
            self,
            discrete_log_params_set: NIZKDiscreteLogParametersSet,
            proof_public_hash: NIZKEqualDiscreteLogsProofHash,
            proof_signature: NIZKEqualDiscreteLogsProofSignature,
            hash_algorithm: str
    ):
        self.curve_config = discrete_log_params_set.curve_config
        self.hash_algo = hash_algorithm
        self.common = NIZKEqualDiscreteLogsCommon(
            discrete_log_params_set.curve_config,
            hash_algorithm
        )
        self.discrete_log_params_set = discrete_log_params_set
        self.proof_pub_hash = proof_public_hash
        self.proof_signature = proof_signature

    def verify(self) -> bool:
        # Reconstruct each nonce point from the corresponding EC base & reference points, and the ZK proof's signature
        # & public hash scalars (as `nonce_pt_i := proof_sig * base_pt_i + proof_pub_hash * ref_pt_i`, for i in [1,N]),
        # according to the Chaum-Pedersen protocol (adapted for discrete logs over elliptic curves).
        nonce_points: list[ECC.EccPoint] = []
        for (dlog_base, dlog_ref_point) in self.discrete_log_params_set.dlog_ref_points_by_base.items():
            nonce_point: ECC.EccPoint = dlog_base * self.proof_signature + dlog_ref_point * self.proof_pub_hash
            nonce_points.append(nonce_point)

        # Recalculate the ZK proof's public hash via the reconstructed nonce points, and the provided corresponding
        # pairs of EC base & reference points (provided via this ZK proof object's NIZKDiscreteLogParametersSet field).
        expected_pub_hash: NIZKEqualDiscreteLogsProofHash = self.common.calc_public_hash(
            self.discrete_log_params_set,
            nonce_points
        )

        # The ZK proof is valid if the recalculated public hash equals the proof's public hash.
        return expected_pub_hash == self.proof_pub_hash


class NIZKEqualDiscreteLogsCommon:
    curve_config: WeierstrassEllipticCurveConfig
    curve: str
    order: int
    G: ECC.EccPoint
    hash_algo: str
    domain_separator: str = DOMAIN_SEPARATION_TAG

    def __init__(
            self,
            curve_config: WeierstrassEllipticCurveConfig,
            hash_algorithm: str = DEFAULT_HASH_ALGORITHM
    ):
        self.curve_config = curve_config
        self.curve = self.curve_config.curve
        self.order = self.curve_config.order
        self.G = self.curve_config.base_point  # curve's generator
        self.hash_algo = hash_algorithm

    def calc_public_hash(
            self,
            discrete_log_params_set: NIZKDiscreteLogParametersSet,
            secret_nonce_points: list[ECC.EccPoint]
    ) -> NIZKEqualDiscreteLogsProofHash:
        # Verify we have the required nonce point per dlog base/ref. point pair.
        assert len(secret_nonce_points) == len(discrete_log_params_set.dlog_ref_points_by_base)

        # Init. a truncated hasher for hashing to bit-length of elliptic curve sub-group's order (i.e., `|<G>|`).
        hasher = PrimeLengthTruncatedHasher(self.order, self.hash_algo)

        # Ensure distinct hashes from other uses of SHA3-256 via a domain separation tag.
        hasher.update(self.domain_separator.encode('utf-8'))

        # Hash each pair of discrete log base and reference points (where each `ref_point := dlog * dlog_base`), using
        # the 'SEC1' binary encoding for each EC point w/out point compression (in order to retain each EC point's
        # y-coordinate's entropy).
        for dlog_base, dlog_ref_point in discrete_log_params_set.dlog_ref_points_by_base.items():
            hasher.update(self.encode_ecc_point(dlog_base))
            hasher.update(self.encode_ecc_point(dlog_ref_point))

        # Hash each nonce point, following 'SEC1' encoding w/out EC point compression.
        # (Note: There is one nonce point per dlog base/ref point pair.)
        for nonce_point in secret_nonce_points:
            hasher.update(self.encode_ecc_point(nonce_point))

        # Finalize the (possibly) bit-length truncated hash and encode as a big integer.
        pub_hash: int = hasher.intdigest()

        return NIZKEqualDiscreteLogsProofHash(pub_hash)

    @staticmethod
    def encode_public_key(public_key: ECC.EccKey) -> bytes:
        if public_key.has_private():
            return public_key.public_key().export_key(format='SEC1')
        else:
            return public_key.export_key(format='SEC1')

    def encode_ecc_point(self, ecc_point: ECC.EccPoint) -> bytes:
        return self.ecc_point_to_pubkey(ecc_point).export_key(format='SEC1')

    def ecc_point_to_pubkey(self, ecc_point: ECC.EccPoint) -> ECC.EccKey:
        return ECC.construct(curve=self.curve_config.curve, point_x=ecc_point.x, point_y=ecc_point.y)

    def generate_random_nonce(self) -> int:
        """
        Generates a random big integer in the range `[1, q-1]` inclusive, where `q` is the configured elliptic curve
        sub-group's order (i.e., `|<G>|` where `<G>` is the sub-group generated by the public base point `G`).
        :return: a random big integer in the range `[1, q-1]` inclusive, where `q` is the configured elliptic curve
                 sub-group's order.
        """
        return generate_random_nonce(self.curve_config)


class NIZKEqualDiscreteLogsProver:
    def __init__(self, curve_config: WeierstrassEllipticCurveConfig, hash_algorithm: str = DEFAULT_HASH_ALGORITHM):
        self.curve_config = curve_config
        self.curve = self.curve_config.curve
        self.order = self.curve_config.order
        self.G: ECC.EccPoint = self.curve_config.base_point  # curve's generator
        self.common = NIZKEqualDiscreteLogsCommon(self.curve_config, hash_algorithm)

    def calc_proof(
            self,
            discrete_log: int,
            discrete_log_params_set: NIZKDiscreteLogParametersSet
    ) -> NIZKEqualDiscreteLogsProof:
        # Generate a private nonce (i.e., ephemeral private key), to be used for this single ZK proof only.
        private_nonce: int = self.common.generate_random_nonce()

        # Construct a nonce point for each provided discrete log base (as `nonce_point := nonce * base_point`),
        # using the same nonce for each point's construction (i.e., a common dlog for each nonce point).
        nonce_points: list[ECC.EccPoint] = []
        for base_point in discrete_log_params_set.dlog_ref_points_by_base.keys():
            nonce_point: ECC.EccPoint = base_point * private_nonce
            nonce_points.append(nonce_point)

        # Calculate the public hash as: `H_q( base_pt1, ref_pt1, base_pt2, ref_pt2, ..., nonce_pt1, nonce_pt2, ... )`,
        # where H_q(...) is a cryptographic hash that has been truncated to the bit-length of the configured elliptic
        # curve sub-group's order `q` (i.e., `self.order`).
        pub_hash: NIZKEqualDiscreteLogsProofHash = self.common.calc_public_hash(discrete_log_params_set, nonce_points)

        # Calculate the NIZK proof of knowledge (PoK) (as: `sig := ephemeral_key - pub_hash * dlog mod q`), according
        # to the Chaum-Pedersen protocol (adapted for discrete logs over elliptic curves).
        proof_signature: int = (private_nonce - int(pub_hash) * discrete_log) % self.order

        return NIZKEqualDiscreteLogsProof(
            discrete_log_params_set,
            pub_hash,
            NIZKEqualDiscreteLogsProofSignature(proof_signature),
            hash_algorithm=self.common.hash_algo
        )
