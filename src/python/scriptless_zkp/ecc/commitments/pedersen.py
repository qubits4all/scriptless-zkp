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
from typing import Iterable

from Cryptodome.PublicKey import ECC

from scriptless_zkp.ecc import ecc_utils
from scriptless_zkp.ecc.exceptions import InvalidECCPedersenCommitmentPointException, InvalidECCPointException
from scriptless_zkp.ecc.generators import ECCGeneratorDerivationContext
from scriptless_zkp.ecc.weierstrass_curves import WeierstrassEllipticCurveConfig


class PedersenCommitmentContext:
    DEFAULT_NUMS_GENERATOR_NONCE: int = 0
    NUMS_GENERATOR_DOMAIN_SEPARATOR: str = "Pedersen-NUMS-Generator"

    def __init__(self, curve_config: WeierstrassEllipticCurveConfig, nums_generator: ECC.EccPoint):
        self.curve_config: WeierstrassEllipticCurveConfig = curve_config
        self.nums_generator: ECC.EccPoint = nums_generator

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
        :raises ValueError: if a NUMS generator point cannot be derived for the provided (or default) nonce, using the
                default maximum number of tweaks (``ECCGeneratorDerivationContext.DEFAULT_CANDIDATE_MAX_TWEAKS``).
                (Note: This is a rare occurrence, and the nonce can be changed to try again.)
        :see: ``ECCGeneratorDerivationContext.derive_generator_for_nonce(nonce)``
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
            commitment: ECC.EccPoint = (
                self.curve_config.base_point * committed_value + self.nums_generator * blinding_factor
            )
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
    commitment_point: ECC.EccPoint

    def __post_init__(self):
        """
        Validates the sealed Pedersen commitment's elliptic curve point, ensuring it is not the point-at-infinity and
        that it lies on the configured elliptic curve, and that the NUMS generator point is also on the configured
        elliptic curve.
        :raises InvalidECCPedersenCommitmentPointException: if the commitment point is the point-at-infinity.
        :raises InvalidECCPointException: if the commitment point or the NUMS generator point do not lie on the
                configured elliptic curve.
        """
        if self.commitment_point.is_point_at_infinity():
            raise InvalidECCPedersenCommitmentPointException(
                ecc_curve_name=self.curve_config.curve,
                message="Sealed Pedersen commitment point is the point-at-infinity (identity point) on the configured"
                        " elliptic curve, which is not a valid commitment."
            )
        elif not self.curve_config.is_point_on_curve(self.commitment_point):
            raise InvalidECCPointException(
                ecc_curve_name=self.curve_config.curve,
                point_x=self.commitment_point.x,
                point_y=self.commitment_point.y
            )
        elif not self.curve_config.is_point_on_curve(self.nums_generator):
            raise InvalidECCPointException(
                ecc_curve_name=self.curve_config.curve,
                point_x=self.nums_generator.x,
                point_y=self.nums_generator.y,
                msg="The sealed Pedersen commitment's NUMS generator point is not on the configured elliptic curve.",
                append_default_message=False
            )

    def __add__(self, other) -> SealedPedersenCommitment:
        """
        Adds this sealed Pedersen commitment to another sealed Pedersen commitment homomorphically, returning a new
        sealed commitment that is a commitment to the sum of the committed values (up to a blinding factor, equal to
        the sum of the original commitments' blinding factors).
        :param other: the other sealed Pedersen commitment to homomorphically add to this commitment.
        :return: a new sealed Pedersen commitment that is a commitment to the sum of the committed values of the
                 original two (sealed) Pedersen commitments.
        :raises TypeError: if the other operand is not a SealedPedersenCommitment.
        :raises ValueError: if the other commitment's elliptic curve is not the same as this commitment's curve, or if
                the other commitment's NUMS generator point is not the same as this commitment's NUMS generator point.
        :raises InvalidECCPedersenCommitmentPointException: if the homomorphic addition results in an invalid commitment
                point (i.e., the point-at-infinity). In this case, the homomorphic sum and the underlying commitments
                should be recalculated, using a new NUMS generator point `H`.
                - Additionally, in this case the existing generator point `H` should not be reused for any future
                commitments & should be considered potentially compromised, because this indicates the discrete log of
                `H` w.r.t. `G` can now be calculated by the committer/prover, and by anyone who later receives the
                revealed commitment, unless the associated blinding factors' sum is zero.
                - Note: In the case the sum of blinding factors equals `0 mod q`, the sum of committed values is also
                `0 mod q`, where the `q` is the configured elliptic curve's sub-group's order (i.e., since
                `O := 0*G + 0*H`).
        :raises InvalidECCPointException: if the homomorphic addition results in an invalid commitment point that is not
                on this commitment's elliptic curve. This may indicate that the commitments being summed may not in fact
                have been calculated using the same elliptic curve, or that they were otherwise incorrectly calculated.
        """
        return self.add(other)

    def add(self, other) -> SealedPedersenCommitment:
        """
        Adds this sealed Pedersen commitment to another sealed Pedersen commitment homomorphically, returning a new
        sealed commitment that is a commitment to the sum of the committed values (up to a blinding factor, equal to
        the sum of the original commitments' blinding factors).
        :param other: the other sealed Pedersen commitment to homomorphically add to this commitment.
        :return: a new sealed Pedersen commitment that is a commitment to the sum of the committed values of the
                 original two (sealed) Pedersen commitments.
        :raises TypeError: if the other operand is not a SealedPedersenCommitment.
        :raises ValueError: if the other commitment's elliptic curve is not the same as this commitment's curve, or if
                the other commitment's NUMS generator point is not the same as this commitment's NUMS generator point.
        :raises InvalidECCPedersenCommitmentPointException: if the homomorphic addition results in an invalid commitment
                point (i.e., the point-at-infinity). In this case, the homomorphic sum and the underlying commitments
                should be recalculated, using a new NUMS generator point `H`.
                - Additionally, in this case the existing generator point `H` should not be reused for any future
                commitments & should be considered potentially compromised, because this indicates the discrete log of
                `H` w.r.t. `G` can now be calculated by the committer/prover, and by anyone who later receives the
                revealed commitment, unless the associated blinding factors' sum is zero.
                - Note: In the case the sum of blinding factors equals `0 mod q`, the sum of committed values is also
                `0 mod q`, where the `q` is the configured elliptic curve's sub-group's order (i.e., since
                `O := 0*G + 0*H`).
        :raises InvalidECCPointException: if the homomorphic addition results in an invalid commitment point that is not
                on this commitment's elliptic curve. This may indicate that the commitments being summed may not in fact
                have been calculated using the same elliptic curve, or that they were otherwise incorrectly calculated.
        """
        if not isinstance(other, SealedPedersenCommitment):
            raise TypeError("Unsupported operand type for +: %s" % type(other))
        elif self.curve_config != other.curve_config:
            raise ValueError(
                "Homomorphic addition of (sealed) Pedersen commitments is only supported for commitments on the same"
                " elliptic curve."
            )
        elif self.nums_generator != other.nums_generator:
            raise ValueError(
                "Homomorphic addition of (sealed) Pedersen commitments is only supported for commitments with the same"
                " NUMS generator point `H`."
            )

        # Homomorphic addition of commitments: `C(x) + C(y) = C(x + y)`
        commitment_sum_point: ECC.EccPoint = self.commitment_point + other.commitment_point

        # Reject an invalid summed commitment, if its elliptic curve point is the point-at-infinity.
        if commitment_sum_point.is_point_at_infinity():
            raise InvalidECCPedersenCommitmentPointException(
                ecc_curve_name=self.curve_config.curve,
                message="Homomorphic addition of (sealed) Pedersen commitments resulted in an invalid commitment point"
                        " (point-at-infinity). This homomorphic sum and the underlying commitments should be"
                        " recalculated, using a new NUMS generator point H. -- NOTE: The existing generator H should"
                        " not be reused for any future commitments & should be considered potentially compromised."
            )
        # Reject an invalid summed commitment, if its elliptic curve point is not on the curve.
        elif not self.curve_config.is_point_on_curve(commitment_sum_point):
            raise InvalidECCPointException(
                ecc_curve_name=self.curve_config.curve,
                point_x=commitment_sum_point.x,
                point_y=commitment_sum_point.y,
                msg="Homomorphic addition of (sealed) Pedersen commitments resulted in an invalid commitment point"
                    " that is not on this commitment's elliptic curve. This may indicate that the vector commitments"
                    " being summed may not in fact have been calculated using the same elliptic curve, or that they"
                    " were otherwise incorrectly calculated.",
                append_default_message=False
            )

        # Add the commitments' curve points together, and return a new sealed commitment.
        return SealedPedersenCommitment(
            self.curve_config,
            self.nums_generator,
            commitment_sum_point
        )

    def sum(self, others: Iterable[SealedPedersenCommitment]) -> SealedPedersenCommitment:
        """
        Sums this sealed Pedersen commitment with one or more other sealed Pedersen commitments homomorphically,
        returning a new sealed commitment that is a commitment to the sum of the committed values (up to a blinding
        factor, equal to the sum of the original commitments' blinding factors).
        :param others: an iterable of other sealed Pedersen commitments to homomorphically add to this commitment.
        :return: a new sealed Pedersen commitment that is a commitment to the sum of the committed values of this
                 sealed Pedersen commitment and the provided iterable of other sealed Pedersen commitments.
        :raises TypeError: if the argument provided to the `others` parameter is not an Iterable or is a string.
        :raises ValueError: if no other sealed Pedersen commitments are provided, if any of the other commitments'
                elliptic curve is not the same as this commitment's curve, or if any of the other commitments' NUMS
                generator point is not the same as this commitment's NUMS generator point.
        """
        if not isinstance(others, Iterable) or isinstance(others, str):
            raise TypeError(
                f"A sealed Pedersen commitment's sum(others) method requires an Iterable of other sealed commitments"
                f" -- Unsupported type provided: {type(others).__qualname__}"
            )

        result: SealedPedersenCommitment = self
        for other in others:
            result = result + other

        if result == self:
            # If the result is still the same as the original commitment, then no other commitments were provided.
            raise ValueError(
                "A sealed Pedersen commitment's sum(others) method requires at least one sealed commitment be provided."
            )

        return result


@dataclass
class RevealedPedersenCommitment:
    curve_config: WeierstrassEllipticCurveConfig
    nums_generator: ECC.EccPoint
    commitment_point: ECC.EccPoint
    committed: int
    blinding_factor: int

    def __post_init__(self):
        """
        Validates the revealed Pedersen commitment's elliptic curve point, ensuring it is not the point-at-infinity and
        that it lies on the configured elliptic curve, and that the NUMS generator point is also on the configured
        elliptic curve.
        :raises InvalidECCPedersenCommitmentPointException: if the commitment point is the point-at-infinity.
        :raises InvalidECCPointException: if the commitment point or the NUMS generator point do not lie on the
                configured elliptic curve.
        """
        if self.commitment_point.is_point_at_infinity():
            raise InvalidECCPedersenCommitmentPointException(
                ecc_curve_name=self.curve_config.curve,
                message="Sealed Pedersen commitment point is the point-at-infinity (identity point) on the configured"
                        " elliptic curve, which is not a valid commitment."
            )
        elif not self.curve_config.is_point_on_curve(self.commitment_point):
            raise InvalidECCPointException(
                ecc_curve_name=self.curve_config.curve,
                point_x=self.commitment_point.x,
                point_y=self.commitment_point.y
            )
        elif not self.curve_config.is_point_on_curve(self.nums_generator):
            raise InvalidECCPointException(
                ecc_curve_name=self.curve_config.curve,
                point_x=self.nums_generator.x,
                point_y=self.nums_generator.y,
                msg="The revealed Pedersen commitment's NUMS generator point is not on the configured elliptic curve.",
                append_default_message=False
            )
        elif not (0 <= self.committed < self.curve_config.order):
            raise ValueError(
                f"The committed value must be in the range [0, {self.curve_config.order - 1}]."
            )
        elif not (1 < self.blinding_factor < self.curve_config.order):
            raise ValueError(
                f"The blinding factor must be in the range [2, {self.curve_config.order - 1}]."
            )

    def __add__(self, other) -> RevealedPedersenCommitment:
        """
        Adds this revealed Pedersen commitment to another revealed Pedersen commitment homomorphically, returning a new
        revealed commitment that is a commitment to the sum of the committed values (up to a blinding factor, equal to
        the sum of the original commitments' blinding factors).

        Note: Both the sum of committed values, and the sum of blinding factors, are proactively reduced modulo the
        curve sub-group's order (i.e., to account for a restriction in the underlying Python ECC library in use, which
        places an upper limit on the size of scalar multipliers used in scalar point multiplication operations).
        - Such scalar multipliers are always effectively reduced to lie in the range `[0, curve_order - 1]` (where
        `curve_order` is the elliptic curve sub-group `<G>`'s order), in the course of calculating a scalar point
        multiplication, with or without this proactive reduction prior to such multiplications.
        - Both this default sub-group `<G>` (formed by the curve's base point `G`) and the
        isomorphic curve sub-group `<H>` (formed by the NUMS generator point `H`) are finite cyclic groups with
        identical order (size), so the following scalar product equations hold: `a*G = (a+o(G))*G`, `b*H = (b+o(H))*H`,
        where `o(G)` and `o(H)` are the orders of the respective sub-groups, indicating exceeding `o(G) - 1` or
        `o(H) - 1` in a scalar multiplier results in curve points that are equivalent to the same curve point
        multiplied by a scalar that is first reduced modulo the sub-group's order.

        :param other: the other revealed Pedersen commitment to homomorphically add to this commitment.
        :return: a new revealed Pedersen commitment that is a commitment to the sum of the committed values of the
                 original two (revealed) Pedersen commitments.
        :raises TypeError: if the other operand is not a RevealedPedersenCommitment.
        :raises ValueError: if the other commitment's elliptic curve is not the same as this commitment's curve, or if
                the other commitment's NUMS generator point is not the same as this commitment's NUMS generator point.
        :raises InvalidECCPedersenCommitmentPointException: if the homomorphic addition results in an invalid commitment
                point (i.e., the point-at-infinity). In this case, the homomorphic sum and the underlying commitments
                should be recalculated, using a new NUMS generator point `H`.
                - Additionally, in this case the existing generator point `H` should not be reused for any future
                commitments & should be considered potentially compromised, because this indicates the discrete log of
                `H` w.r.t. `G` can be calculated by the committer/prover, and had the revealed commitment been retained
                this discrete log could be calculated by anyone who receives it, unless the associated blinding factors'
                sum equals `0 mod q`.
                - Note: In the case the sum of blinding factors equals `0 mod q`, the sum of committed values is also
                `0 mod q`, where the `q` is the configured elliptic curve's sub-group's order (i.e., since
                `O := 0*G + 0*H`).
        :raises InvalidECCPointException: if the homomorphic addition results in an invalid commitment point that is not
                on this commitment's elliptic curve. This may indicate that the commitments being summed may not in fact
                have been calculated using the same elliptic curve, or that they were otherwise incorrectly calculated.
        """
        return self.add(other)

    def add(self, other: RevealedPedersenCommitment) -> RevealedPedersenCommitment:
        """
        Adds this revealed Pedersen commitment to another revealed Pedersen commitment homomorphically, returning a new
        revealed commitment that is a commitment to the sum of the committed values (up to a blinding factor, equal to
        the sum of the original commitments' blinding factors).

        Note: Both the sum of committed values, and the sum of blinding factors, are proactively reduced modulo the
        curve sub-group's order (i.e., to account for a restriction in the underlying Python ECC library in use, which
        places an upper limit on the size of scalar multipliers used in scalar point multiplication operations).
        - Such scalar multipliers are always effectively reduced to lie in the range `[0, curve_order - 1]` (where
        `curve_order` is the elliptic curve sub-group `<G>`'s order), in the course of calculating a scalar point
        multiplication, with or without this proactive reduction prior to such multiplications.
        - Both this default sub-group `<G>` (formed by the curve's base point `G`) and the
        isomorphic curve sub-group `<H>` (formed by the NUMS generator point `H`) are finite cyclic groups with
        identical order (size), so the following scalar product equations hold: `a*G = (a+o(G))*G`, `b*H = (b+o(H))*H`,
        where `o(G)` and `o(H)` are the orders of the respective sub-groups, indicating exceeding `o(G) - 1` or
        `o(H) - 1` in a scalar multiplier results in curve points that are equivalent to the same curve point
        multiplied by a scalar that is first reduced modulo the sub-group's order.

        :param other: the other revealed Pedersen commitment to homomorphically add to this commitment.
        :return: a new revealed Pedersen commitment that is a commitment to the sum of the committed values of the
                 original two (revealed) Pedersen commitments.
        :raises TypeError: if the other operand is not a RevealedPedersenCommitment.
        :raises ValueError: if the other commitment's elliptic curve is not the same as this commitment's curve, or if
                the other commitment's NUMS generator point is not the same as this commitment's NUMS generator point.
        :raises InvalidECCPedersenCommitmentPointException: if the homomorphic addition results in an invalid commitment
                point (i.e., the point-at-infinity). In this case, the homomorphic sum and the underlying commitments
                should be recalculated, using a new NUMS generator point `H`.
                - Additionally, in this case the existing generator point `H` should not be reused for any future
                commitments & should be considered potentially compromised, because this indicates the discrete log of
                `H` w.r.t. `G` can be calculated by the committer/prover, and had the revealed commitment been retained
                this discrete log could be calculated by anyone who receives it, unless the associated blinding factors'
                sum equals `0 mod q`.
                - Note: In the case the sum of blinding factors equals `0 mod q`, the sum of committed values is also
                `0 mod q`, where the `q` is the configured elliptic curve's sub-group's order (i.e., since
                `O := 0*G + 0*H`).
        :raises InvalidECCPointException: if the homomorphic addition results in an invalid commitment point that is not
                on this commitment's elliptic curve. This may indicate that the commitments being summed may not in fact
                have been calculated using the same elliptic curve, or that they were otherwise incorrectly calculated.
        """
        if not isinstance(other, RevealedPedersenCommitment):
            raise TypeError("Unsupported operand type for +: %s" % type(other))
        elif self.curve_config != other.curve_config:
            raise ValueError(
                "Homomorphic addition of (revealed) Pedersen commitments is only supported for commitments on the same"
                " elliptic curve."
            )
        elif self.nums_generator != other.nums_generator:
            raise ValueError(
                "Homomorphic addition of (revealed) Pedersen commitments is only supported for commitments with the"
                " same NUMS generator point `H`."
            )

        # Homomorphic addition of commitments: `C(x) + C(y) = C(x + y)`
        commitment_sum_point: ECC.EccPoint = self.commitment_point + other.commitment_point

        # Reject an invalid summed commitment, if its elliptic curve point is the point-at-infinity.
        if commitment_sum_point.is_point_at_infinity():
            raise InvalidECCPedersenCommitmentPointException(
                ecc_curve_name=self.curve_config.curve,
                message="Homomorphic addition of (revealed) Pedersen commitments resulted in an invalid commitment point"
                        " (point-at-infinity). This homomorphic sum and the underlying commitments should be"
                        " recalculated, using a new NUMS generator point H. -- NOTE: The existing generator H should"
                        " not be reused for any future commitments & should be considered potentially compromised."
            )
        # Reject an invalid summed commitment, if its elliptic curve point is not on the curve.
        elif not self.curve_config.is_point_on_curve(commitment_sum_point):
            raise InvalidECCPointException(
                ecc_curve_name=self.curve_config.curve,
                point_x=commitment_sum_point.x,
                point_y=commitment_sum_point.y,
                msg="Homomorphic addition of (revealed) Pedersen commitments resulted in an invalid commitment point"
                    " that is not on this commitment's elliptic curve. This may indicate that the vector commitments"
                    " being summed may not in fact have been calculated using the same elliptic curve, or that they"
                    " were otherwise incorrectly calculated.",
                append_default_message=False
            )

        # Add the commitments' curve points together, along with the committed (secret) values and blinding factors,
        # and return a new revealed commitment.
        # Note: The committed values' & blinding factors' sums are each reduced modulo the curve order q, to avoid
        #   running afoul of a restriction in the underlying ECC library in use re: the size of scalars used in scalar
        #   point multiplication.
        return RevealedPedersenCommitment(
            self.curve_config,
            self.nums_generator,
            commitment_sum_point,
            (self.committed + other.committed) % self.curve_config.order,
            (self.blinding_factor + other.blinding_factor) % self.curve_config.order
        )

    def sum(self, others: Iterable[RevealedPedersenCommitment]) -> RevealedPedersenCommitment:
        """
        Sums this revealed Pedersen commitment with multiple other revealed Pedersen commitments homomorphically,
        returning a new revealed commitment that is a commitment to the sum of the committed values (up to a blinding
        factor, equal to the sum of the original commitments' blinding factors).
        :param others: an iterable of other revealed Pedersen commitments to homomorphically add to this commitment.
        :return: a new revealed Pedersen commitment that is a commitment to the sum of the committed values of the
                 original revealed Pedersen commitments.
        :raises TypeError: if the argument provided to the `others` parameter is not an Iterable or is a string.
        :raises ValueError: if no other revealed Pedersen commitments are provided, if any of the other commitments'
                elliptic curve is not the same as this commitment's curve, or if any of the other commitments' NUMS
                generator point is not the same as this commitment's NUMS generator point.
        """
        if not isinstance(others, Iterable) or isinstance(others, str):
            raise TypeError(
                f"A revealed Pedersen commitment's sum(others) method requires an Iterable of other revealed"
                f" commitments -- Unsupported type provided: {type(others).__qualname__}"
            )

        result: RevealedPedersenCommitment = self
        for other in others:
            result: RevealedPedersenCommitment = result + other

        if result == self:
            # If the result is still the same as the original commitment, then no other commitments were provided.
            raise ValueError(
                "A revealed Pedersen commitment's sum(others) method requires at least one revealed commitment be"
                " provided."
            )

        return result

    def verify(self) -> bool:
        # Check for invalid blinding factor (must be in the range: [1, curve_order - 1] ).
        if not (0 < self.blinding_factor < self.curve_config.order):
            return False

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
        return self.commitment_point == reconstructed_commitment
