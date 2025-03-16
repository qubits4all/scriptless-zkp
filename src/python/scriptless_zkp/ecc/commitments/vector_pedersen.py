###############################################################################
# (c) 2025 W. Spann Systems Consulting
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###############################################################################

"""
This module provides support for generating sealed Vector Pedersen commitments over elliptic curves, and verifying revealed
(unsealed) vector commitments. Vector Pedersen commitments allow committing to multiple values in a single operation.
This commitment scheme also lends itself to limited homomorphic operations, where the sum of two commitments is a 
commitment to the sum of the committed vectors (up to a blinding factor, equal to the sum of the original commitments' 
blinding factors).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from Cryptodome.PublicKey import ECC

from scriptless_zkp.ecc import ecc_utils
from scriptless_zkp.ecc.generators import ECCGeneratorDerivationContext
from scriptless_zkp.ecc.weierstrass_curves import WeierstrassEllipticCurveConfig


class VectorPedersenCommitmentContext:
    curve_config: WeierstrassEllipticCurveConfig
    nums_generators: List[ECC.EccPoint]
    dimension: int

    DEFAULT_NUMS_GENERATOR_NONCE_BASE: int = 1000
    NUMS_GENERATOR_DOMAIN_SEPARATOR: str = "VectorPedersen-NUMS-Generator"

    def __init__(self, curve_config: WeierstrassEllipticCurveConfig, nums_generators: List[ECC.EccPoint]):
        self.curve_config = curve_config
        self.nums_generators = nums_generators
        self.dimension = len(nums_generators)

    @classmethod
    def for_curve(
            cls,
            curve_config: WeierstrassEllipticCurveConfig,
            dimension: int,
            base_nonce: int = DEFAULT_NUMS_GENERATOR_NONCE_BASE
    ) -> VectorPedersenCommitmentContext:
        """
        Creates a new Vector Pedersen commitment context for the provided elliptic curve configuration with the specified
        dimension, using derived NUMS ("Nothing Up My Sleeve") generator points (for which nobody knows the discrete 
        logarithm), constructed from the provided base nonce and domain separator.
        
        :param curve_config: the elliptic curve configuration to use for Vector Pedersen commitments.
        :param dimension: the number of values that can be committed to in a single commitment (dimension of vector).
        :param base_nonce: a base nonce to use when deriving the NUMS generators. Each generator will use base_nonce + i.
        :return: a new Vector Pedersen commitment context for the provided elliptic curve configuration and dimension.
        """
        if dimension < 1:
            raise ValueError(f"Dimension must be at least 1, got {dimension}")

        generator_context: ECCGeneratorDerivationContext = ECCGeneratorDerivationContext(
            curve_config,
            domain_separation_tag=VectorPedersenCommitmentContext.NUMS_GENERATOR_DOMAIN_SEPARATOR
        )

        # Derive effectively independent (NUMS) generator points for each dimension
        nums_generators: List[ECC.EccPoint] = []
        for i in range(dimension):
            nonce = base_nonce + i
            nums_generator = generator_context.derive_generator_for_nonce(nonce)
            nums_generators.append(nums_generator)

        return cls(curve_config, nums_generators)

    @classmethod
    def for_nums_generators(
            cls,
            curve_config: WeierstrassEllipticCurveConfig,
            nums_generators: List[ECC.EccPoint]
    ) -> VectorPedersenCommitmentContext:
        """
        Creates a new Vector Pedersen commitment context for the provided elliptic curve configuration, using the 
        provided NUMS ("Nothing Up My Sleeve") generator points.
        
        :param curve_config: the elliptic curve configuration to use for Vector Pedersen commitments.
        :param nums_generators: the NUMS generator points to use for Vector Pedersen commitments.
        :return: a new Vector Pedersen commitment context for the provided elliptic curve configuration, using the 
                 provided NUMS generator points.
        """
        if len(nums_generators) < 1:
            raise ValueError("At least one NUMS generator point must be provided")
        
        return cls(curve_config, nums_generators)

    def commit(self, committed_values: List[int]) -> Tuple[SealedVectorPedersenCommitment, RevealedVectorPedersenCommitment]:
        """
        Commits to the provided values using the Vector Pedersen commitment scheme over the configured elliptic curve,
        returning a sealed commitment and a revealed commitment.
        
        The sealed commitment is shared with a verifier that will verify the commitment once opened by the committer in
        the future. The public NUMS generator points are also shared with the verifier, as they're required for
        recalculating the commitment when the commitment is opened.
        
        The revealed commitment is retained by the committer and is required for them to "open" the sealed commitment
        later (i.e., by sharing the private committed values and the associated random blinding factor/nonce).
        
        Once in the verifier's possession, the private committed values and random blinding factor/nonce can be used to
        recalculate the Vector Pedersen commitment, and this elliptic curve point is compared with the sealed commitment's
        curve point, where equal points indicates a valid commitment.
        
        :param committed_values: the list of integer values to be committed to, each must lie in the range 
                                [0, curve_order - 1]. The length must match the dimension of the context.
        :return: a tuple containing a sealed Vector Pedersen commitment and a revealed Vector Pedersen commitment.
        :raises ValueError: if any provided value is not in the range [0, curve_order - 1] or if the list length
                           doesn't match the context dimension.
        """
        if len(committed_values) != self.dimension:
            raise ValueError(f"Expected {self.dimension} values, got {len(committed_values)}")

        # Validate all values are in the valid range
        for value in committed_values:
            if not (0 <= value < self.curve_config.order):
                raise ValueError(f"Each committed value must be in the range [0, {self.curve_config.order - 1}]")

        while True:
            blinding_factor: int = ecc_utils.generate_random_nonce(self.curve_config, exclude_one=True)
            
            # Initialize commitment with the blinding factor term
            commitment: ECC.EccPoint = self.curve_config.base_point * blinding_factor
            
            # Add the committed value terms (v_i * H_i)
            for i, value in enumerate(committed_values):
                if value != 0:  # Optimization: skip zero values
                    commitment = commitment + (self.nums_generators[i] * value)
            
            # Ensure the calculated commitment point is not the point-at-infinity
            if not commitment.is_point_at_infinity():
                break

        sealed_commitment: SealedVectorPedersenCommitment = SealedVectorPedersenCommitment(
            self.curve_config,
            self.nums_generators,
            commitment
        )
        revealed_commitment: RevealedVectorPedersenCommitment = RevealedVectorPedersenCommitment(
            self.curve_config,
            self.nums_generators,
            commitment,
            committed_values.copy(),  # Make a copy to avoid shared reference
            blinding_factor
        )

        return sealed_commitment, revealed_commitment


@dataclass
class SealedVectorPedersenCommitment:
    curve_config: WeierstrassEllipticCurveConfig
    nums_generators: List[ECC.EccPoint]
    commitment_point: ECC.EccPoint

    @property
    def dimension(self) -> int:
        """Get the dimension of this vector commitment (number of values it can hold)."""
        return len(self.nums_generators)

    def __add__(self, other) -> SealedVectorPedersenCommitment:
        """
        Adds this sealed Vector Pedersen commitment to another sealed Vector Pedersen commitment homomorphically, returning
        a new sealed commitment that is a commitment to the sum of the committed vectors (up to a blinding factor, equal to
        the sum of the original commitments' blinding factors).
        
        :param other: the other sealed Vector Pedersen commitment to homomorphically add to this commitment.
        :return: a new sealed Vector Pedersen commitment that is a commitment to the sum of the committed vectors of the
                 original two (sealed) Vector Pedersen commitments.
        """
        if not isinstance(other, SealedVectorPedersenCommitment):
            raise TypeError(f"Unsupported operand type for +: {type(other)}")
        elif self.curve_config != other.curve_config:
            raise ValueError(
                "Homomorphic addition of (sealed) Vector Pedersen commitments is only supported for commitments on the same"
                " elliptic curve."
            )
        elif self.dimension != other.dimension:
            raise ValueError(
                "Homomorphic addition of (sealed) Vector Pedersen commitments is only supported for commitments with the"
                " same dimension."
            )
        
        # Check that the generators are the same
        for i in range(self.dimension):
            if self.nums_generators[i] != other.nums_generators[i]:
                raise ValueError(
                    "Homomorphic addition of (sealed) Vector Pedersen commitments is only supported for commitments with"
                    " the same NUMS generator points."
                )

        # Add the commitments' curve points together, and return a new sealed commitment.
        return SealedVectorPedersenCommitment(
            self.curve_config,
            self.nums_generators,
            self.commitment_point + other.commitment_point  # homomorphic addition of commitments
        )


@dataclass
class RevealedVectorPedersenCommitment:
    curve_config: WeierstrassEllipticCurveConfig
    nums_generators: List[ECC.EccPoint]
    commitment_point: ECC.EccPoint
    committed: List[int]
    blinding_factor: int

    @property
    def dimension(self) -> int:
        """Get the dimension of this vector commitment (number of values it holds)."""
        return len(self.nums_generators)

    def __add__(self, other) -> RevealedVectorPedersenCommitment:
        """
        Adds this revealed Vector Pedersen commitment to another revealed Vector Pedersen commitment homomorphically,
        returning a new revealed commitment that is a commitment to the sum of the committed vectors (up to a blinding
        factor, equal to the sum of the original commitments' blinding factors).
        
        :param other: the other revealed Vector Pedersen commitment to homomorphically add to this commitment.
        :return: a new revealed Vector Pedersen commitment that is a commitment to the sum of the committed vectors of the
                 original two (revealed) Vector Pedersen commitments.
        """
        if not isinstance(other, RevealedVectorPedersenCommitment):
            raise TypeError(f"Unsupported operand type for +: {type(other)}")
        elif self.curve_config != other.curve_config:
            raise ValueError(
                "Homomorphic addition of (revealed) Vector Pedersen commitments is only supported for commitments on the same"
                " elliptic curve."
            )
        elif self.dimension != other.dimension:
            raise ValueError(
                "Homomorphic addition of (revealed) Vector Pedersen commitments is only supported for commitments with the"
                " same dimension."
            )
        
        # Check that the generators are the same
        for i in range(self.dimension):
            if self.nums_generators[i] != other.nums_generators[i]:
                raise ValueError(
                    "Homomorphic addition of (revealed) Vector Pedersen commitments is only supported for commitments with"
                    " the same NUMS generator points."
                )

        # Sum the committed values element-wise
        summed_committed = [self.committed[i] + other.committed[i] for i in range(self.dimension)]
        
        # Add the commitments' curve points together, along with the committed values and blinding factors,
        # and return a new revealed commitment.
        return RevealedVectorPedersenCommitment(
            self.curve_config,
            self.nums_generators,
            self.commitment_point + other.commitment_point,  # homomorphic addition of commitments
            summed_committed,
            self.blinding_factor + other.blinding_factor
        )

    def verify(self) -> bool:
        """
        Verifies that the revealed commitment is valid by recalculating the commitment using the revealed values
        and blinding factor and comparing it to the stored commitment point.
        
        :return: True if the commitment is valid, False otherwise.
        """
        if len(self.committed) != self.dimension:
            return False

        # Initialize with the blinding factor term
        reconstructed_commitment: ECC.EccPoint = self.curve_config.base_point * self.blinding_factor
        
        # Add the committed value terms (v_i * H_i)
        for i, value in enumerate(self.committed):
            if value != 0:  # Optimization: skip zero values
                reconstructed_commitment = reconstructed_commitment + (self.nums_generators[i] * value)

        # Reject invalid commitments that are not on the curve or that equal the point-at-infinity
        if not self.curve_config.is_point_on_curve(reconstructed_commitment) or reconstructed_commitment.is_point_at_infinity():
            return False

        # Return whether the provided commitment matches the recalculated commitment
        return self.commitment_point == reconstructed_commitment