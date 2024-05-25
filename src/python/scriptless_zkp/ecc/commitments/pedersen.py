###############################################################################
# (c) 2024 W. Spann Systems Consulting
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
This module provides support for generating sealed Pedersen commitments over elliptic curves, and verifying revealed
(unsealed) commitments. This commitment scheme also lends itself to limited homomorphic operations, where the sum of
two commitments is a commitment to the sum of the committed values (up to a blinding factor, equal to the sum of the
original commitments' blinding factors).
"""
from __future__ import annotations

from dataclasses import dataclass

from Cryptodome.PublicKey import ECC

from scriptless_zkp.ecc import ecc_utils
from scriptless_zkp.ecc.generators import ECCGeneratorDerivationContext
from scriptless_zkp.ecc.weierstrass_curves import WeierstrassEllipticCurveConfig


class PedersenCommitmentContext:
    curve_config: WeierstrassEllipticCurveConfig
    nums_generator: ECC.EccPoint

    DEFAULT_NUMS_GENERATOR_NONCE: int = 0
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
        generator_context: ECCGeneratorDerivationContext = ECCGeneratorDerivationContext(
            curve_config,
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

    def commit(self, committed_value: int) -> tuple[SealedPedersenCommitment, RevealedPedersenCommitment]:
        """
        Commits to the provided value using the Pedersen commitment scheme over the configured elliptic curve,
        returning a sealed commitment and a revealed commitment.
        <p>
        The sealed commitment is shared with a verifier that will verify the commitment once opened by the committer in
        the future. Sharing the sealed commitment with the intended verifier once it's produced is important to ensure
        the utility of the commitment's binding property (i.e., that the committer hasn't changed the value to which
        they've committed). The public NUMS generator point is also shared with the verifier, as it's required for
        recalculating the commitment when the commitment is opened. (Alternatively, the verifier could re-derive the
        NUMS generator point, if the committer and verifier agree on the specific procedure to do so.) The committer
        must keep the revealed commitment secret until they're ready to open the sealed commitment.</p>
        <p>
        The revealed commitment is retained by the committer and is required for them to "open" the sealed commitment
        later (i.e., by sharing the private committed value and the associated random blinding factor/nonce).
        (Note: Whether the opened commitment's private values are sent to the verifier over a confidential channel or
        can be publicly disclosed depends on the specific use case and security requirements of the protocol within
        which the Pedersen commitment is being used.)</p>
        <p>
        Once in the verifier's possession, the private committed value and random blinding factor/nonce can be used to
        recalculate the Pedersen commitment, and this elliptic curve point is compared with the sealed commitment's
        curve point, where equal points indicates a valid commitment.
        :param committed_value: the integer value to be committed to, which must lie in the range [0, curve_order - 1].
        :return: a tuple containing a sealed Pedersen commitment and a revealed Pedersen commitment.
        :raises ValueError: if the provided value to be committed to is not in the range [0, curve_order - 1].
        """
        if not (0 <= committed_value < self.curve_config.order):
            raise ValueError(f"The committed value must be in the range [0, {self.curve_config.order - 1}].")

        while True:
            blinding_factor: int = ecc_utils.generate_random_nonce(self.curve_config, exclude_one=True)
            commitment: ECC.EccPoint = self.nums_generator * committed_value + self.nums_generator * blinding_factor
            # Ensure the calculated commitment point is not the point-at-infinity.
            if not commitment.is_point_at_infinity():
                break

        sealed_commitment: SealedPedersenCommitment = SealedPedersenCommitment(
            self.curve_config,
            self.nums_generator,
            commitment
        )
        revealed_commitment: RevealedPedersenCommitment = RevealedPedersenCommitment(
            self.curve_config,
            self.nums_generator,
            commitment,
            committed_value,
            blinding_factor
        )

        return sealed_commitment, revealed_commitment


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
