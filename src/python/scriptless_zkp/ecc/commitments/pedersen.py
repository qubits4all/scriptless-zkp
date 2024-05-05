"""
This module provides support for generating sealed Pedersen commitments over elliptic curves, and verifying revealed
(unsealed) commitments. This commitment scheme also lends itself to limited homomorphic operations, where the sum of
two commitments is a commitment to the sum of the committed values (up to a blinding factor, equal to the sum of the
original commitments' blinding factors).
"""
from __future__ import annotations

from dataclasses import dataclass

from Cryptodome.PublicKey import ECC
from Cryptodome.Util import number

from scriptless_zkp.ecc import ecc_utils
from scriptless_zkp.ecc.generators import RandomGeneratorDerivationContext
from scriptless_zkp.ecc.weierstrass_curves import WeierstrassEllipticCurveConfig


class PedersenCommitmentContext:
    curve_config: WeierstrassEllipticCurveConfig
    nums_generator: ECC.EccPoint

    DEFAULT_NUMS_GENERATOR_NONCE: int = 1
    DEFAULT_NUMS_GENERATOR_HASH_ALGO: str = "sha3_256"
    NUMS_GENERATOR_DOMAIN_SEPARATOR: str = "Pedersen-NUMS-Generator"

    def __init__(self, curve_config: WeierstrassEllipticCurveConfig, nums_generator: ECC.EccPoint):
        self.curve_config = curve_config
        self.nums_generator = nums_generator

    @classmethod
    def for_curve(
            cls,
            curve_config: WeierstrassEllipticCurveConfig,
            nonce: int = DEFAULT_NUMS_GENERATOR_NONCE
    ) -> PedersenCommitmentContext:
        """
        Creates a new Pedersen commitment context for the provided elliptic curve configuration, using a derived NUMS
        ("Nothing Up My Sleeve") generator point (for which nobody knows the discrete logarithm), constructed from the
        provided nonce, hash algorithm, and domain separator.
        :param curve_config: the elliptic curve configuration to use for Pedersen commitments.
        :param nonce: a nonce to use when deriving the NUMS generator.
        :return: a new Pedersen commitment context for the provided elliptic curve configuration, using a derived NUMS
                 generator point.
        """
        generator_context: RandomGeneratorDerivationContext = RandomGeneratorDerivationContext(
            curve_config,
            hash_algorithm=PedersenCommitmentContext.DEFAULT_NUMS_GENERATOR_HASH_ALGO,
            domain_separation_tag=PedersenCommitmentContext.NUMS_GENERATOR_DOMAIN_SEPARATOR
        )

        # Derive an effectively independent (NUMS) generator point for which nobody knows the discrete logarithm.
        nums_generator: ECC.EccPoint = generator_context.derive_generator_for_nonce(nonce)

        return cls(curve_config, nums_generator)

    @classmethod
    def for_nums_generator(
            cls,
            curve_config: WeierstrassEllipticCurveConfig,
            nums_generator: ECC.EccPoint
    ) -> PedersenCommitmentContext:
        """
        Creates a new Pedersen commitment context for the provided elliptic curve configuration, using the provided NUMS
        ("Nothing Up My Sleeve") generator point.
        :param curve_config: the elliptic curve configuration to use for Pedersen commitments.
        :param nums_generator: the NUMS generator point to use for Pedersen commitments.
        :return: a new Pedersen commitment context for the provided elliptic curve configuration, using the provided
                 NUMS generator point.
        """
        return cls(curve_config, nums_generator)

    def commit(self, value: int) -> tuple[SealedPedersenCommitment, RevealedPedersenCommitment]:
        blinding_factor: int = ecc_utils.generate_random_nonce(self.curve_config)
        commitment: ECC.EccPoint = self.nums_generator * value + self.nums_generator * blinding_factor

        sealed_commitment: SealedPedersenCommitment = SealedPedersenCommitment(
            self.curve_config,
            self.nums_generator,
            commitment
        )
        revealed_commitment: RevealedPedersenCommitment = RevealedPedersenCommitment(
            self.curve_config,
            self.nums_generator,
            commitment,
            value,
            blinding_factor
        )

        return sealed_commitment, revealed_commitment

    def commit_to_bytes(self, value: bytes) -> tuple[SealedPedersenCommitment, RevealedPedersenCommitment]:
        committed: int = number.bytes_to_long(value)
        return self.commit(committed)


@dataclass
class SealedPedersenCommitment:
    curve_config: WeierstrassEllipticCurveConfig
    nums_generator: ECC.EccPoint
    commitment: ECC.EccPoint


@dataclass
class RevealedPedersenCommitment:
    curve_config: WeierstrassEllipticCurveConfig
    nums_generator: ECC.EccPoint
    commitment: ECC.EccPoint
    committed: int
    blinding_factor: int

    def verify(self) -> bool:
        # Recalculate the commitment, using the revealed committed value and blinding factor.
        reconstructed_commitment: ECC.EccPoint = (
            self.curve_config.base_point * self.committed + self.nums_generator * self.blinding_factor
        )

        # Reject invalid commitments that are not on the curve or that equal the point-at-infinity.
        if not self.curve_config.is_point_on_curve(
            reconstructed_commitment
        ) or reconstructed_commitment.is_point_at_infinity():
            return False

        # Return whether the provided commitment matches the recalculated commitment.
        return self.commitment == reconstructed_commitment
