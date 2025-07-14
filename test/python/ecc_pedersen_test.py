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

import unittest

from Cryptodome.PublicKey import ECC

from scriptless_zkp.ecc.commitments import RevealedPedersenCommitment
from scriptless_zkp.ecc.commitments.pedersen import PedersenCommitmentContext, SealedPedersenCommitment
from scriptless_zkp.ecc.exceptions import InvalidECCPedersenCommitmentPointException, InvalidECCPointException
from scriptless_zkp.ecc.weierstrass_curves import WeierstrassEllipticCurveConfig


class ECCPedersenCommitmentTests(unittest.TestCase):
    context = PedersenCommitmentContext.for_curve(
        WeierstrassEllipticCurveConfig.secp256r1()
    )
    test_committed_value1: int = 42
    test_committed_value2: int = 1337
    test_committed_large_value: int = 2 ** 128 - 1                # 2^128 - 1: Large value for testing overflow handling
    test_committed_special_large_value: int = context.curve_config.order - test_committed_value1  # Value for testing sums to `0 mod q`
    test_committed_largest_value: int = context.curve_config.order - 1  # Largest value that can be committed

    def test_pedersen_commitment_generation(self):
        sealed_commitment, revealed_commitment = self.context.commit(self.test_committed_value1)

        self.assertEqual(sealed_commitment.curve_config, self.context.curve_config)
        self.assertEqual(revealed_commitment.curve_config, self.context.curve_config)

        self.assertEqual(sealed_commitment.nums_generator, self.context.nums_generator)
        self.assertEqual(revealed_commitment.nums_generator, self.context.nums_generator)

        self.assertEqual(sealed_commitment.commitment_point, revealed_commitment.commitment_point)
        self.assertFalse(
            sealed_commitment.commitment_point.is_point_at_infinity(),
            "Commitment point should not be the point-at-infinity (O)."
        )
        self.assertNotEqual(revealed_commitment.blinding_factor, 0, "Blinding factor should not be zero.")

        self.assertEqual(sealed_commitment.commitment_point, revealed_commitment.commitment_point)
        self.assertEqual(revealed_commitment.committed, self.test_committed_value1)

        # Verify `C = v * G + r * H`, where `r` is the blinding factor scalar, `G` is the base point, `v` is the
        # committed value scalar, `H` is the NUMS generator point & `C` is the commitment point.
        expected_commitment_point: ECC.EccPoint = (
            self.context.curve_config.base_point * self.test_committed_value1
            + self.context.nums_generator * revealed_commitment.blinding_factor
        )
        self.assertEqual(expected_commitment_point, sealed_commitment.commitment_point)

    def test_pedersen_commitment_verification(self):
        sealed_commitment, revealed_commitment = self.context.commit(self.test_committed_value1)

        self.assertTrue(revealed_commitment.verify(), "Revealed commitment verification failed.")

    def test_pedersen_sealed_commitment_construction_valid_commitment_point(self):
        """
        Test that constructing a sealed Pedersen commitment with a valid commitment point does not raise an exception.
        """
        # Create a valid commitment point using the context's curve configuration and NUMS generator.
        valid_commitment_point: ECC.EccPoint = (
            self.context.curve_config.base_point * self.test_committed_value1
            + self.context.nums_generator * 42  # constant blinding factor for test
        )

        # Construct the sealed Pedersen commitment with the valid commitment point.
        sealed_commitment = SealedPedersenCommitment(
            curve_config=self.context.curve_config,
            nums_generator=self.context.nums_generator,
            commitment_point=valid_commitment_point
        )

        self.assertEqual(sealed_commitment.commitment_point, valid_commitment_point)
        self.assertEqual(sealed_commitment.curve_config, self.context.curve_config)
        self.assertEqual(sealed_commitment.nums_generator, self.context.nums_generator)

    def test_pedersen_sealed_commitment_construction_with_point_at_infinity_raises_exception(self):
        """
        Test that attempting to construct a sealed Pedersen commitment using the point-at-infinity as the commitment
        point (an invalid commitment) raises an exception.
        Note: This test would be especially useful in a scenario where a commitment point is incorrectly set to the
          point-at-infinity (identity) point, such as could occur when constructing a commitment from a serialized form,
          if the deserialization method does not validate the commitment point before deserialization.
        """
        with self.assertRaises(InvalidECCPedersenCommitmentPointException):
            SealedPedersenCommitment(
                curve_config=self.context.curve_config,
                nums_generator=self.context.nums_generator,
                commitment_point=self.context.curve_config.identity
            )

    def test_pedersen_sealed_commitment_construction_with_commitment_point_on_wrong_curve_raises_exception(self):
        """
        Test that attempting to construct a sealed Pedersen commitment using an invalid commitment point (not on the
        curve) raises an exception.
        """
        different_curve_config = WeierstrassEllipticCurveConfig.secp384r1()
        different_nums_generator_nonce: int = 7

        different_pedersen_context = PedersenCommitmentContext.for_curve(
            curve_config=different_curve_config,
            nonce=different_nums_generator_nonce
        )
        different_nums_generator: ECC.EccPoint = different_pedersen_context.nums_generator

        # Construct a Pedersen commitment point that is not on the curve to be specified in the sealed commitment's
        # constructor.
        invalid_commitment_point: ECC.EccPoint = (
            different_curve_config.base_point * 42
            + different_nums_generator * 1337
        )

        with self.assertRaises(InvalidECCPointException):
            SealedPedersenCommitment(
                curve_config=self.context.curve_config,
                nums_generator=self.context.nums_generator,
                commitment_point=invalid_commitment_point
            )

    def test_pedersen_sealed_commitment_construction_with_invalid_nums_generator_raises_exception(self):
        # Create a valid commitment point using the context's curve configuration and NUMS generator.
        valid_commitment_point: ECC.EccPoint = (
                self.context.curve_config.base_point * self.test_committed_value1
                + self.context.nums_generator * 42  # constant blinding factor for test
        )

        different_curve_config = WeierstrassEllipticCurveConfig.secp384r1()
        different_nums_generator_nonce: int = 7

        different_pedersen_context = PedersenCommitmentContext.for_curve(
            curve_config=different_curve_config,
            nonce=different_nums_generator_nonce
        )
        # Get a NUMS generator point that is not on the original curve.
        different_nums_generator: ECC.EccPoint = different_pedersen_context.nums_generator

        with self.assertRaises(InvalidECCPointException):
            # Attempt to construct the sealed Pedersen commitment with a NUMS generator not on the curve.
            SealedPedersenCommitment(
                curve_config=self.context.curve_config,
                nums_generator=different_nums_generator,
                commitment_point=valid_commitment_point
            )

    def test_pedersen_sealed_commitment_homomorphic_addition(self):
        sealed_commitment1, revealed_commitment1 = self.context.commit(self.test_committed_value1)
        sealed_commitment2, revealed_commitment2 = self.context.commit(self.test_committed_value2)

        summed_sealed_commitment: SealedPedersenCommitment = sealed_commitment1 + sealed_commitment2

        self.assertEqual(summed_sealed_commitment.curve_config, self.context.curve_config)
        self.assertEqual(summed_sealed_commitment.nums_generator, self.context.nums_generator)

        self.assertEqual(
            summed_sealed_commitment.commitment_point,
            sealed_commitment1.commitment_point + sealed_commitment2.commitment_point
        )

        # Verify `C = (v1 + v2) * G + (r1 + r2) * H`, where `r1` & `r2` are the blinding factor scalars, `G` is the
        # base point, `v1` & `v2` are the committed value scalars, `H` is the NUMS generator point & `C` is the summed
        # commitment point.
        expected_sum_commitment_point: ECC.EccPoint = self.context.curve_config.base_point * (
            (
                self.test_committed_value1 + self.test_committed_value2
            ) % self.context.curve_config.order
        ) + self.context.nums_generator * (
            (
                revealed_commitment1.blinding_factor + revealed_commitment2.blinding_factor
            ) % self.context.curve_config.order
        )

        self.assertEqual(expected_sum_commitment_point, summed_sealed_commitment.commitment_point)

    def test_pedersen_sealed_commitments_with_different_curves_sum_raises_exception(self):
        """
        Test that attempting to sum two sealed commitments with different elliptic curves raises an exception.
        """
        # Create a second context with a different curve configuration.
        different_curve_pedersen_context = PedersenCommitmentContext.for_curve(
            WeierstrassEllipticCurveConfig.secp384r1()
        )

        # Commit to value using the original context.
        sealed_commitment1, _ = self.context.commit(self.test_committed_value1)
        # Commit to another value using the different curve context.
        sealed_commitment2, _ = different_curve_pedersen_context.commit(self.test_committed_value2)

        # Attempt to sum the two sealed commitments, which should raise an exception.
        with self.assertRaises(ValueError):
            sealed_commitment1 + sealed_commitment2

    def test_pedersen_sealed_commitments_with_different_nums_generators_sum_raises_exception(self):
        """
        Test that attempting to sum two sealed commitments with different NUMS generators raises an exception.
        """
        different_nums_generator_nonce: int = 42

        # Create a second context with a different NUMS generator.
        different_nums_generator_pedersen_context = PedersenCommitmentContext.for_curve(
            self.context.curve_config,
            nonce=different_nums_generator_nonce
        )

        # Commit to value using the original context.
        sealed_commitment1, _ = self.context.commit(self.test_committed_value1)

        # Commit to another value using the other Pedersen context w/ a different NUMS generator point.
        sealed_commitment2, _ = different_nums_generator_pedersen_context.commit(self.test_committed_value2)

        # Attempt to sum the two sealed commitments, which should raise an exception.
        with self.assertRaises(ValueError):
            sealed_commitment1 + sealed_commitment2

    def test_pedersen_sealed_commitment_homomorphic_addition_with_None_raises_exception(self):
        """
        Test that attempting to add a sealed commitment with `None` raises an exception.
        """
        sealed_commitment, _ = self.context.commit(self.test_committed_value1)

        with self.assertRaises(TypeError):
            sealed_commitment + None

    def test_pedersen_sealed_commitment_homomorphic_add_with_None_raises_exception(self):
        """
        Test that attempting to add a sealed commitment with `None` raises an exception.
        """
        sealed_commitment, _ = self.context.commit(self.test_committed_value1)

        with self.assertRaises(TypeError):
            sealed_commitment.add(None)

    def test_pedersen_sealed_commitment_homomorphic_addition_with_overflow(self):
        sealed_commitment1, revealed_commitment1 = self.context.commit(self.test_committed_value2)
        sealed_commitment2, revealed_commitment2 = self.context.commit(self.test_committed_largest_value)

        summed_sealed_commitment: SealedPedersenCommitment = sealed_commitment1 + sealed_commitment2

        self.assertEqual(summed_sealed_commitment.curve_config, self.context.curve_config)
        self.assertEqual(summed_sealed_commitment.nums_generator, self.context.nums_generator)

        self.assertEqual(
            summed_sealed_commitment.commitment_point,
            sealed_commitment1.commitment_point + sealed_commitment2.commitment_point
        )

        # Verify `C = (v1 + v2) * G + (r1 + r2) * H`, where `r1` & `r2` are the blinding factor scalars, `G` is the
        # base point, `v1` & `v2` are the committed value scalars, `H` is the NUMS generator point & `C` is the summed
        # commitment point.
        # Note: The committed values' and associated blinding factors' respective scalar sums are reduced modulo the
        #   curve sub-group's order `o(G)`, to avoid running afoul of a restriction in the underlying ECC library in
        #   use re: the size of scalars used in scalar point multiplication.
        expected_sum_commitment_point: ECC.EccPoint = self.context.curve_config.base_point * (
            (
                self.test_committed_value2 + self.test_committed_largest_value
            ) % self.context.curve_config.order
        ) + self.context.nums_generator * (
            (
                revealed_commitment1.blinding_factor + revealed_commitment2.blinding_factor
            ) % self.context.curve_config.order
        )

        self.assertEqual(expected_sum_commitment_point, summed_sealed_commitment.commitment_point)

    def test_pedersen_sealed_commitment_sum_to_point_at_infinity_with_blinding_factors_eq_zero(self):
        """
        Test one case where the homomorphic sum of two sealed commitments results in the point-at-infinity (identity
        point) on the configured elliptic curve, which is not a valid commitment. The attempted sum should raise an
        `InvalidECCPedersenCommitmentPointException` in this case.

        In this case, the two sealed commitments are constructed such that their committed values sum to `0` modulo
        the curve sub-group's order, and their blinding factors are both zero (an invalid blinding factor, but chosen
        here to ensure the sum results in the point-at-infinity).
        """
        # Using an (invalid) blinding factor of zero for both commitments to ensure the sum results in the point-at-infinity.
        zero_blinding_factor: int = 0

        # Manually construct the 1st sealed commitment's commitment point using blinding factor of zero.
        commitment1_point: ECC.EccPoint = (
            self.context.curve_config.base_point * self.test_committed_value1
            + self.context.nums_generator * zero_blinding_factor
        )
        # Create the 1st sealed commitment using the 1st manually constructed commitment point.
        sealed_commitment1 = SealedPedersenCommitment(
            curve_config=self.context.curve_config,
            nums_generator=self.context.nums_generator,
            commitment_point=commitment1_point
        )

        # Manually construct the 2nd sealed commitment's commitment point using blinding factor of zero.
        commitment2_point: ECC.EccPoint = (
            self.context.curve_config.base_point * self.test_committed_special_large_value
            + self.context.nums_generator * zero_blinding_factor
        )
        # Create the 2nd sealed commitment using the 2nd manually constructed commitment point.
        sealed_commitment2 = SealedPedersenCommitment(
            curve_config=self.context.curve_config,
            nums_generator=self.context.nums_generator,
            commitment_point=commitment2_point
        )

        # Test a case where the sum of two sealed commitments results in the point-at-infinity.
        # This can happen if the committed values sum to `0` modulo the curve sub-group's order, and the blinding
        # factors sum to the same value (or both are zero, as in this case; technically an invalid blinding factor
        # value).
        with self.assertRaises(InvalidECCPedersenCommitmentPointException):
            sealed_commitment1 + sealed_commitment2

    def test_pedersen_sealed_commitment_sum_to_point_at_infinity_with_blinding_factors_sum_to_zero(self):
        blinding_factor1: int = 42
        blinding_factor2: int = self.context.curve_config.order - blinding_factor1

        # Manually construct the 1st sealed commitment's commitment point using a specific blinding factor chosen to
        # sum to 0 modulo the curve sub-group's order (i.e., when added to the 2nd commitment's blinding factor).
        commitment1_point: ECC.EccPoint = (
                self.context.curve_config.base_point * self.test_committed_value1
                + self.context.nums_generator * blinding_factor1
        )
        # Create the 1st sealed commitment using the 1st manually constructed commitment point.
        sealed_commitment1 = SealedPedersenCommitment(
            curve_config=self.context.curve_config,
            nums_generator=self.context.nums_generator,
            commitment_point=commitment1_point
        )

        # Manually construct the 2nd sealed commitment's commitment point using a specific blinding factor chosen to
        # sum to 0 modulo the curve sub-group's order (i.e., when added to the 2nd commitment's blinding factor).
        commitment2_point: ECC.EccPoint = (
                self.context.curve_config.base_point * self.test_committed_special_large_value
                + self.context.nums_generator * blinding_factor2
        )
        # Create the 2nd sealed commitment using the 2nd manually constructed commitment point.
        sealed_commitment2 = SealedPedersenCommitment(
            curve_config=self.context.curve_config,
            nums_generator=self.context.nums_generator,
            commitment_point=commitment2_point
        )

        # Test a case where the sum of two sealed commitments results in the point-at-infinity.
        # This can happen if the committed values sum to `0` modulo the curve sub-group's order, and the blinding
        # factors sum to the same value.
        with self.assertRaises(InvalidECCPedersenCommitmentPointException):
            sealed_commitment1 + sealed_commitment2

    def test_pedersen_sealed_commitments_homomorphic_sum_of_2(self):
        """
        Test that the homomorphic sum of two sealed commitments, using `sum(...)` results in a valid commitment.
        """
        sealed_commitment1, revealed_commitment1 = self.context.commit(self.test_committed_value1)
        sealed_commitment2, revealed_commitment2 = self.context.commit(self.test_committed_value2)

        summed_sealed_commitment: SealedPedersenCommitment = sealed_commitment1.sum([sealed_commitment2])

        self.assertEqual(summed_sealed_commitment.curve_config, self.context.curve_config)
        self.assertEqual(summed_sealed_commitment.nums_generator, self.context.nums_generator)

        # Verify the summed commitment point is the sum of the individual commitment points.
        self.assertEqual(
            summed_sealed_commitment.commitment_point,
            sealed_commitment1.commitment_point + sealed_commitment2.commitment_point
        )

        # Verify `C = (v1 + v2) * G + (r1 + r2) * H`, where `r1` & `r2` are the blinding factor scalars, `G` is the
        # base point, `v1` & `v2` are the committed value scalars, `H` is the NUMS generator point & `C` is the summed
        # commitment point.
        expected_sum_commitment_point: ECC.EccPoint = (
            self.context.curve_config.base_point * (
                (
                    self.test_committed_value1 + self.test_committed_value2
                ) % self.context.curve_config.order
            ) + self.context.nums_generator * (
                (
                    revealed_commitment1.blinding_factor + revealed_commitment2.blinding_factor
                ) % self.context.curve_config.order
            )
        )

        self.assertEqual(expected_sum_commitment_point, summed_sealed_commitment.commitment_point)

    def test_pedersen_sealed_commitments_homomorphic_sum_of_3(self):
        """
        Test that the homomorphic sum of three sealed commitments, using `sum(...)` results in a valid commitment.
        """
        sealed_commitment1, revealed_commitment1 = self.context.commit(self.test_committed_value1)
        sealed_commitment2, revealed_commitment2 = self.context.commit(self.test_committed_value2)
        sealed_commitment3, revealed_commitment3 = self.context.commit(self.test_committed_large_value)

        summed_sealed_commitment: SealedPedersenCommitment = sealed_commitment1.sum(
            [sealed_commitment2, sealed_commitment3]
        )

        self.assertEqual(summed_sealed_commitment.curve_config, self.context.curve_config)
        self.assertEqual(summed_sealed_commitment.nums_generator, self.context.nums_generator)

        # Verify the summed commitment point is the sum of the individual commitment points.
        self.assertEqual(
            summed_sealed_commitment.commitment_point,
            (sealed_commitment1.commitment_point + sealed_commitment2.commitment_point
             + sealed_commitment3.commitment_point)
        )

        # Verify `C = (v1 + v2 + v3) * G + (r1 + r2 + r3) * H`, where `r1`, `r2` & `r3` are the blinding factor scalars,
        # `G` is the base point, `v1`, `v2` & `v3` are the committed value scalars, `H` is the NUMS generator point &
        # `C` is the summed commitment point.
        expected_sum_commitment_point: ECC.EccPoint = (
            self.context.curve_config.base_point * (
                (
                    self.test_committed_value1 + self.test_committed_value2 + self.test_committed_large_value
                ) % self.context.curve_config.order
            ) + self.context.nums_generator * (
                (
                    revealed_commitment1.blinding_factor + revealed_commitment2.blinding_factor
                    + revealed_commitment3.blinding_factor
                ) % self.context.curve_config.order
            )
        )

        self.assertEqual(expected_sum_commitment_point, summed_sealed_commitment.commitment_point)

    def test_pedersen_sealed_commitments_homomorphic_sum_with_overflow(self):
        """
        Test that the homomorphic sum of two sealed commitments with large values does not overflow and results in a valid
        commitment.
        """
        sealed_commitment1, revealed_commitment1 = self.context.commit(self.test_committed_value1)
        sealed_commitment2, revealed_commitment2 = self.context.commit(self.test_committed_value2)
        sealed_commitment3, revealed_commitment3 = self.context.commit(self.test_committed_large_value)
        sealed_commitment4, revealed_commitment4 = self.context.commit(self.test_committed_large_value)  # repeated

        summed_sealed_commitment: SealedPedersenCommitment = sealed_commitment1.sum(
            [sealed_commitment2, sealed_commitment3, sealed_commitment4]
        )

        self.assertEqual(summed_sealed_commitment.curve_config, self.context.curve_config)
        self.assertEqual(summed_sealed_commitment.nums_generator, self.context.nums_generator)

        # Verify the summed commitment point is the sum of the individual commitment points.
        self.assertEqual(
            summed_sealed_commitment.commitment_point,
            (sealed_commitment1.commitment_point + sealed_commitment2.commitment_point
             + sealed_commitment3.commitment_point + sealed_commitment4.commitment_point)
        )

        # Verify `C = (v1 + v2 + v3 + v4) * G + (r1 + r2 + r3 + r4) * H`, where `r1`, `r2`, `r3` & `r4` are the
        # blinding factor scalars, `G` is the base point, `v1`, `v2`, `v3` & `v4` are the committed value scalars,
        # `H` is the NUMS generator point & `C` is the summed commitment point.
        # Note: The committed values' and associated blinding factors' respective scalar sums are proactively reduced
        #   modulo the curve sub-group's order `o(G)`, to avoid running afoul of a restriction in the underlying ECC
        #   library in use re: the size of scalars used in scalar point multiplication.
        expected_sum_commitment_point: ECC.EccPoint = (
            self.context.curve_config.base_point * (
                (
                    self.test_committed_value1 + self.test_committed_value2 + self.test_committed_large_value
                    + self.test_committed_large_value
                ) % self.context.curve_config.order
            ) + self.context.nums_generator * (
                (
                    revealed_commitment1.blinding_factor + revealed_commitment2.blinding_factor
                    + revealed_commitment3.blinding_factor + revealed_commitment4.blinding_factor
                ) % self.context.curve_config.order
            )
        )

        self.assertEqual(expected_sum_commitment_point, summed_sealed_commitment.commitment_point)

    def test_pedersen_sealed_commitments_homomorphic_sum_with_empty_list_raises_exception(self):
        """
        Test that attempting to sum a sealed commitment with an empty list raises an exception.
        """
        sealed_commitment, _ = self.context.commit(self.test_committed_value1)

        with self.assertRaises(ValueError):
            sealed_commitment.sum([])

    def test_pedersen_sealed_commitments_homomorphic_sum_with_None_raises_exception(self):
        """
        Test that attempting to sum a sealed commitment with `None` raises an exception.
        """
        sealed_commitment, _ = self.context.commit(self.test_committed_value1)

        with self.assertRaises(TypeError):
            # noinspection PyTypeChecker
            sealed_commitment.sum(None)

    def test_pedersen_revealed_commitment_construction_valid_commitment_point(self):
        """
        Test that constructing a revealed Pedersen commitment with a valid commitment point and other valid parameters
        does not raise an exception.
        """
        # Create a valid commitment point using the context's curve configuration and NUMS generator.
        valid_commitment_point: ECC.EccPoint = (
            self.context.curve_config.base_point * self.test_committed_value1
            + self.context.nums_generator * 42  # constant blinding factor for test
        )

        # Construct the revealed Pedersen commitment with the valid parameters.
        revealed_commitment = RevealedPedersenCommitment(
            curve_config=self.context.curve_config,
            nums_generator=self.context.nums_generator,
            commitment_point=valid_commitment_point,
            committed=self.test_committed_value1,
            blinding_factor=42
        )

        self.assertEqual(revealed_commitment.commitment_point, valid_commitment_point)
        self.assertEqual(revealed_commitment.curve_config, self.context.curve_config)
        self.assertEqual(revealed_commitment.nums_generator, self.context.nums_generator)
        self.assertEqual(revealed_commitment.committed, self.test_committed_value1)
        self.assertEqual(revealed_commitment.blinding_factor, 42)

        self.assertTrue(revealed_commitment.verify(), "Revealed Pedersen commitment verification failed.")

    def test_pedersen_revealed_commitment_homomorphic_addition(self):
        sealed_commitment1, revealed_commitment1 = self.context.commit(self.test_committed_value1)
        sealed_commitment2, revealed_commitment2 = self.context.commit(self.test_committed_value2)

        summed_revealed_commitment = revealed_commitment1 + revealed_commitment2

        self.assertEqual(summed_revealed_commitment.curve_config, self.context.curve_config)
        self.assertEqual(summed_revealed_commitment.nums_generator, self.context.nums_generator)

        # Verify the summed revealed commitment's point is the sum of the individual revealed commitments' points.
        self.assertEqual(
            summed_revealed_commitment.commitment_point,
            revealed_commitment1.commitment_point + revealed_commitment2.commitment_point
        )

        # Verify `C = (v1 + v2) * G + (r1 + r2) * H`, where `r1` & `r2` are the blinding factor scalars, `G` is the
        # base point, `v1` & `v2` are the committed value scalars, `H` is the NUMS generator point & `C` is the summed
        # commitment point.
        # Note: The committed values' and associated blinding factors' respective scalar sums are reduced modulo the
        #   curve sub-group's order `o(G)`, to avoid running afoul of a restriction in the underlying ECC library in
        #   use re: the size of scalars used in scalar point multiplication.
        expected_sum_commitment_point: ECC.EccPoint = (
            self.context.curve_config.base_point * (
                (
                    self.test_committed_value1 + self.test_committed_value2
                ) % self.context.curve_config.order
            ) + self.context.nums_generator * (
                (
                    revealed_commitment1.blinding_factor + revealed_commitment2.blinding_factor
                ) % self.context.curve_config.order
            )
        )

        self.assertEqual(expected_sum_commitment_point, summed_revealed_commitment.commitment_point)

        # Note: The committed values' scalar sum is reduced modulo the curve sub-group's order `o(G)`, to avoid running
        #   afoul of a restriction in the underlying ECC library in use re: the size of scalars used in scalar point
        #   multiplication.
        expected_committed_sum: int = (
            self.test_committed_value1 + self.test_committed_value2
        ) % self.context.curve_config.order

        self.assertEqual(
            summed_revealed_commitment.committed,
            expected_committed_sum
        )

        expected_blinding_factors_sum: int = (
            revealed_commitment1.blinding_factor + revealed_commitment2.blinding_factor
        ) % self.context.curve_config.order

        self.assertEqual(
            summed_revealed_commitment.blinding_factor,
            expected_blinding_factors_sum
        )

        # Verify the summed revealed commitment.
        self.assertTrue(summed_revealed_commitment.verify(), "Summed revealed commitment verification failed.")

    def test_pedersen_revealed_commitments_with_different_curves_sum_raises_exception(self):
        """
        Test that attempting to sum two revealed commitments with different elliptic curves raises an exception.
        """
        # Create a second context with a different curve configuration.
        different_curve_pedersen_context = PedersenCommitmentContext.for_curve(
            WeierstrassEllipticCurveConfig.secp384r1()
        )

        # Commit to value using the original context.
        _, revealed_commitment1 = self.context.commit(self.test_committed_value1)
        # Commit to another value using the different curve context.
        _, revealed_commitment2 = different_curve_pedersen_context.commit(self.test_committed_value2)

        # Attempt to sum the two revealed commitments, which should raise an exception.
        with self.assertRaises(ValueError):
            revealed_commitment1 + revealed_commitment2

    def test_pedersen_revealed_commitments_with_different_nums_generators_sum_raises_exception(self):
        """
        Test that attempting to sum two revealed commitments with different NUMS generators raises an exception.
        """
        different_nums_generator_nonce: int = 42

        # Create a second context with a different NUMS generator.
        different_nums_generator_pedersen_context = PedersenCommitmentContext.for_curve(
            self.context.curve_config,
            nonce=different_nums_generator_nonce
        )

        # Commit to value using the original context.
        _, revealed_commitment1 = self.context.commit(self.test_committed_value1)

        # Commit to another value using the other Pedersen context w/ a different NUMS generator point.
        _, revealed_commitment2 = different_nums_generator_pedersen_context.commit(self.test_committed_value2)

        # Attempt to sum the two revealed commitments, which should raise an exception.
        with self.assertRaises(ValueError):
            revealed_commitment1 + revealed_commitment2

    def test_pedersen_revealed_commitment_homomorphic_addition_with_overflow(self):
        sealed_commitment1, revealed_commitment1 = self.context.commit(self.test_committed_value2)
        sealed_commitment2, revealed_commitment2 = self.context.commit(self.test_committed_largest_value)

        summed_revealed_commitment = revealed_commitment1 + revealed_commitment2

        self.assertEqual(summed_revealed_commitment.curve_config, self.context.curve_config)
        self.assertEqual(summed_revealed_commitment.nums_generator, self.context.nums_generator)

        # Verify the summed revealed commitment's point is the sum of the individual revealed commitments' points.
        self.assertEqual(
            summed_revealed_commitment.commitment_point,
            revealed_commitment1.commitment_point + revealed_commitment2.commitment_point
        )

        # Verify `C = (v1 + v2) * G + (r1 + r2) * H`, where `r1` & `r2` are the blinding factor scalars, `G` is the
        # base point, `v1` & `v2` are the committed value scalars, `H` is the NUMS generator point & `C` is the summed
        # commitment point.
        expected_sum_commitment_point: ECC.EccPoint = (
            self.context.curve_config.base_point * (
                (
                    self.test_committed_value2 + self.test_committed_largest_value
                ) % self.context.curve_config.order
            ) + self.context.nums_generator * ((
                revealed_commitment1.blinding_factor + revealed_commitment2.blinding_factor
            ) % self.context.curve_config.order)
        )
        self.assertEqual(expected_sum_commitment_point, summed_revealed_commitment.commitment_point)

        expected_committed_sum: int = (
            self.test_committed_value2 + self.test_committed_largest_value
        ) % self.context.curve_config.order

        self.assertEqual(
            summed_revealed_commitment.committed,
            expected_committed_sum
        )

        expected_blinding_factors_sum: int = (
            revealed_commitment1.blinding_factor + revealed_commitment2.blinding_factor
        ) % self.context.curve_config.order

        self.assertEqual(
            summed_revealed_commitment.blinding_factor,
            expected_blinding_factors_sum
        )

        # Verify the summed revealed commitment.
        self.assertTrue(summed_revealed_commitment.verify(), "Summed revealed commitment verification failed.")

    def test_pedersen_revealed_commitment_sum_to_point_at_infinity_with_blinding_factors_eq_zero(self):
        """
        Test one case where the homomorphic sum of two revealed commitments results in the point-at-infinity (identity
        point) on the configured elliptic curve, which is not a valid commitment. The attempted sum should raise an
        `InvalidECCPedersenCommitmentPointException` in this case.

        In this case, the two revealed commitments are constructed such that their committed values sum to `0` modulo
        the curve sub-group's order, and their blinding factors are both zero (an invalid blinding factor, but chosen
        here to ensure the sum results in the point-at-infinity).
        """
        # Using an (invalid) blinding factor of zero for both commitments to ensure the sum results in the
        # point-at-infinity.
        zero_blinding_factor: int = 0

        # Manually construct the 1st revealed commitment's commitment point using blinding factor of zero.
        commitment1_point: ECC.EccPoint = (
            self.context.curve_config.base_point * self.test_committed_value1
            + self.context.nums_generator * zero_blinding_factor
        )
        # Create the 1st revealed commitment using the 1st manually constructed commitment point.
        revealed_commitment1 = RevealedPedersenCommitment(
            curve_config=self.context.curve_config,
            nums_generator=self.context.nums_generator,
            commitment_point=commitment1_point,
            committed=self.test_committed_value1,
            blinding_factor=2  # temp. value to pass __post_init__() validation
        )
        # Get around the blinding factor validation in RevealedPedersenCommitment's post-constructor.
        revealed_commitment1.blinding_factor = zero_blinding_factor

        # Manually construct the 2nd revealed commitment's commitment point using blinding factor of zero.
        commitment2_point: ECC.EccPoint = (
            self.context.curve_config.base_point * self.test_committed_special_large_value
            + self.context.nums_generator * zero_blinding_factor
        )
        # Create the 2nd revealed commitment using the 2nd manually constructed commitment point.
        revealed_commitment2 = RevealedPedersenCommitment(
            curve_config=self.context.curve_config,
            nums_generator=self.context.nums_generator,
            commitment_point=commitment2_point,
            committed=self.test_committed_special_large_value,
            blinding_factor=2  # temp. value to pass __post_init__() validation
        )
        # Get around the blinding factor validation in RevealedPedersenCommitment's post-constructor.
        revealed_commitment2.blinding_factor = zero_blinding_factor

        # Test a case where the sum of two revealed commitments results in the point-at-infinity.
        # This can happen if the committed values sum to `0` modulo the curve sub-group's order, and the blinding
        # factors sum to the same value (or both are zero, as in this case; technically an invalid blinding factor
        # value).
        with self.assertRaises(InvalidECCPedersenCommitmentPointException):
            revealed_commitment1 + revealed_commitment2

    def test_pedersen_revealed_commitment_sum_to_point_at_infinity_with_blinding_factors_sum_to_zero(self):
        blinding_factor1: int = 42
        blinding_factor2: int = self.context.curve_config.order - blinding_factor1

        # Manually construct the 1st revealed commitment's commitment point using a specific blinding factor chosen to
        # sum to 0 modulo the curve sub-group's order (i.e., when added to the 2nd commitment's blinding factor).
        commitment1_point: ECC.EccPoint = (
            self.context.curve_config.base_point * self.test_committed_value1
            + self.context.nums_generator * blinding_factor1
        )
        # Create the 1st revealed commitment using the 1st manually constructed commitment point.
        revealed_commitment1 = RevealedPedersenCommitment(
            curve_config=self.context.curve_config,
            nums_generator=self.context.nums_generator,
            commitment_point=commitment1_point,
            committed=self.test_committed_value1,
            blinding_factor=blinding_factor1
        )

        # Manually construct the 2nd revealed commitment's commitment point using a specific blinding factor chosen to
        # sum to 0 modulo the curve sub-group's order (i.e., when added to the 2nd commitment's blinding factor).
        commitment2_point: ECC.EccPoint = (
            self.context.curve_config.base_point * self.test_committed_special_large_value
            + self.context.nums_generator * blinding_factor2
        )
        # Create the 2nd revealed commitment using the 2nd manually constructed commitment point.
        revealed_commitment2 = RevealedPedersenCommitment(
            curve_config=self.context.curve_config,
            nums_generator=self.context.nums_generator,
            commitment_point=commitment2_point,
            committed=self.test_committed_special_large_value,
            blinding_factor=blinding_factor2
        )

        # Test a case where the sum of two revealed commitments results in the point-at-infinity.
        # This can happen if the committed values sum to `0` modulo the curve sub-group's order, and the blinding
        # factors sum to the same value.
        with self.assertRaises(InvalidECCPedersenCommitmentPointException):
            revealed_commitment1 + revealed_commitment2


if __name__ == '__main__':
    unittest.main()
