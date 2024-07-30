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

from scriptless_zkp.ecc.commitments.pedersen import PedersenCommitmentContext, SealedPedersenCommitment
from scriptless_zkp.ecc.weierstrass_curves import WeierstrassEllipticCurveConfig


class ECCPedersenCommitmentTests(unittest.TestCase):
    context = PedersenCommitmentContext.for_curve(
        WeierstrassEllipticCurveConfig.secp256r1()
    )
    test_committed_value1: int = 42
    test_committed_value2: int = 1337

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
                self.context.curve_config.base_point * self.test_committed_value1 + self.context.nums_generator *
                revealed_commitment.blinding_factor
        )
        self.assertEqual(expected_commitment_point, sealed_commitment.commitment_point)

    def test_pedersen_commitment_verification(self):
        sealed_commitment, revealed_commitment = self.context.commit(self.test_committed_value1)

        self.assertTrue(revealed_commitment.verify(), "Revealed commitment verification failed.")

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
        expected_sum_commitment_point: ECC.EccPoint = (
            self.context.curve_config.base_point * (self.test_committed_value1 + self.test_committed_value2) +
            self.context.nums_generator * (revealed_commitment1.blinding_factor + revealed_commitment2.blinding_factor)
        )
        self.assertEqual(expected_sum_commitment_point, summed_sealed_commitment.commitment_point)

    def test_pedersen_revealed_commitment_homomorphic_addition(self):
        sealed_commitment1, revealed_commitment1 = self.context.commit(self.test_committed_value1)
        sealed_commitment2, revealed_commitment2 = self.context.commit(self.test_committed_value2)

        summed_revealed_commitment = revealed_commitment1 + revealed_commitment2

        self.assertEqual(summed_revealed_commitment.curve_config, self.context.curve_config)
        self.assertEqual(summed_revealed_commitment.nums_generator, self.context.nums_generator)

        self.assertEqual(
            summed_revealed_commitment.commitment_point,
            revealed_commitment1.commitment_point + revealed_commitment2.commitment_point
        )

        # Verify `C = (v1 + v2) * G + (r1 + r2) * H`, where `r1` & `r2` are the blinding factor scalars, `G` is the
        # base point, `v1` & `v2` are the committed value scalars, `H` is the NUMS generator point & `C` is the summed
        # commitment point.
        expected_sum_commitment_point: ECC.EccPoint = (
            self.context.curve_config.base_point * (self.test_committed_value1 + self.test_committed_value2) +
            self.context.nums_generator * (revealed_commitment1.blinding_factor + revealed_commitment2.blinding_factor)
        )
        self.assertEqual(expected_sum_commitment_point, summed_revealed_commitment.commitment_point)

        self.assertEqual(
            summed_revealed_commitment.committed,
            self.test_committed_value1 + self.test_committed_value2
        )
        self.assertEqual(
            summed_revealed_commitment.blinding_factor,
            revealed_commitment1.blinding_factor + revealed_commitment2.blinding_factor
        )


if __name__ == '__main__':
    unittest.main()
