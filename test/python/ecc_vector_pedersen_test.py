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

import unittest

from Cryptodome.PublicKey import ECC

from scriptless_zkp.ecc.commitments.vector_pedersen import (
    VectorPedersenCommitmentContext, SealedVectorPedersenCommitment, RevealedVectorPedersenCommitment
)
from scriptless_zkp.ecc.weierstrass_curves import WeierstrassEllipticCurveConfig


class ECCVectorPedersenCommitmentTests(unittest.TestCase):
    dimension = 3
    context = VectorPedersenCommitmentContext.for_curve(
        WeierstrassEllipticCurveConfig.secp256r1(),
        dimension
    )
    
    test_vector1: list[int] = [42, 17, 99]
    test_vector2: list[int] = [1337, 21, 5]
    large_test_vector: list[int] = [context.curve_config.order - 1, 1337, 6]

    def test_vector_pedersen_commitment_context_creation(self):
        """
        Test creating a Vector Pedersen commitment context with different dimensions, using the NIST P-256 elliptic
        curve.
        """

        # Test with dimension 1 (equivalent to regular Pedersen)
        dim1_context = VectorPedersenCommitmentContext.for_curve(
            WeierstrassEllipticCurveConfig.secp256r1(),
            dimension=1
        )
        self.assertEqual(len(dim1_context.nums_generators), 1)
        
        # Test with larger dimension
        dim5_context = VectorPedersenCommitmentContext.for_curve(
            WeierstrassEllipticCurveConfig.secp256r1(),
            dimension=5
        )
        self.assertEqual(len(dim5_context.nums_generators), 5)
        
        # Test with invalid dimension
        with self.assertRaises(ValueError):
            VectorPedersenCommitmentContext.for_curve(
                WeierstrassEllipticCurveConfig.secp256r1(),
                dimension=0
            )

    def test_vector_pedersen_commitment_context_creation_p384(self):
        """Test creating a Vector Pedersen commitment context with a different elliptic curve: NIST P-384"""

        # Test different curves
        secp384r1_context = VectorPedersenCommitmentContext.for_curve(
            WeierstrassEllipticCurveConfig.secp384r1(),
            dimension=self.dimension
        )
        self.assertEqual(len(secp384r1_context.nums_generators), self.dimension)
        self.assertTrue(secp384r1_context.curve_config.has_curve_name("secp384r1"))

    def test_vector_pedersen_commitment_generation(self):
        """Test generating Vector Pedersen commitments."""
        sealed_commitment, revealed_commitment = self.context.commit(self.test_vector1)

        # Check basic properties
        self.assertEqual(sealed_commitment.curve_config, self.context.curve_config)
        self.assertEqual(revealed_commitment.curve_config, self.context.curve_config)
        self.assertEqual(sealed_commitment.nums_generators, self.context.nums_generators)
        self.assertEqual(revealed_commitment.nums_generators, self.context.nums_generators)
        self.assertEqual(sealed_commitment.commitment_point, revealed_commitment.commitment_point)
        
        # Point shouldn't be at infinity
        self.assertFalse(
            sealed_commitment.commitment_point.is_point_at_infinity(),
            "Commitment point should not be the point-at-infinity (O)."
        )
        
        # Blinding factor shouldn't be zero
        self.assertNotEqual(revealed_commitment.blinding_factor, 0, "Blinding factor should not be zero.")
        
        # Committed values should match
        self.assertEqual(revealed_commitment.committed, self.test_vector1)
        
        # Check the dimension property
        self.assertEqual(sealed_commitment.dimension, self.dimension)
        self.assertEqual(revealed_commitment.dimension, self.dimension)

        # Verify the commitment manually: C = r*G + v1*H1 + v2*H2 + v3*H3
        expected_commitment_point: ECC.EccPoint = self.context.curve_config.base_point * revealed_commitment.blinding_factor
        for i, value in enumerate(self.test_vector1):
            expected_commitment_point = expected_commitment_point + (self.context.nums_generators[i] * value)
            
        self.assertEqual(expected_commitment_point, sealed_commitment.commitment_point)

    def test_vector_pedersen_commitment_verification(self):
        """Test verifying Vector Pedersen commitments."""
        # Create and verify a valid commitment
        sealed_commitment, revealed_commitment = self.context.commit(self.test_vector1)
        self.assertTrue(revealed_commitment.verify(), "Revealed commitment verification failed.")
        
        # Tamper with a committed value and verify it fails
        tampered_commitment = RevealedVectorPedersenCommitment(
            revealed_commitment.curve_config,
            revealed_commitment.nums_generators,
            revealed_commitment.commitment_point,
            [revealed_commitment.committed[0] + 1] + revealed_commitment.committed[1:],  # Change first value
            revealed_commitment.blinding_factor
        )
        self.assertFalse(tampered_commitment.verify(), "Tampered commitment verification should fail.")
        
        # Tamper with the blinding factor and verify it fails
        tampered_commitment = RevealedVectorPedersenCommitment(
            revealed_commitment.curve_config,
            revealed_commitment.nums_generators,
            revealed_commitment.commitment_point,
            revealed_commitment.committed.copy(),
            revealed_commitment.blinding_factor + 1  # Change blinding factor
        )
        self.assertFalse(tampered_commitment.verify(), "Tampered commitment verification should fail.")

    def test_vector_pedersen_sealed_commitment_homomorphic_addition(self):
        """Test homomorphic addition of sealed Vector Pedersen commitments."""
        sealed_commitment1, revealed_commitment1 = self.context.commit(self.test_vector1)
        sealed_commitment2, revealed_commitment2 = self.context.commit(self.test_vector2)

        summed_sealed_commitment: SealedVectorPedersenCommitment = sealed_commitment1 + sealed_commitment2

        # Check basic properties
        self.assertEqual(summed_sealed_commitment.curve_config, self.context.curve_config)
        self.assertEqual(summed_sealed_commitment.nums_generators, self.context.nums_generators)
        self.assertEqual(
            summed_sealed_commitment.commitment_point,
            sealed_commitment1.commitment_point + sealed_commitment2.commitment_point
        )

        # Verify the summed commitment manually:
        # C = (r1+r2)*G + (v1_1+v2_1)*H1 + (v1_2+v2_2)*H2 + (v1_3+v2_3)*H3
        expected_blinding_factor_sum = (
            revealed_commitment1.blinding_factor + revealed_commitment2.blinding_factor
        ) % self.context.curve_config.order
        expected_sum_commitment_point: ECC.EccPoint = self.context.curve_config.base_point * expected_blinding_factor_sum
        
        for i in range(self.dimension):
            expected_value_sum = self.test_vector1[i] + self.test_vector2[i]
            expected_sum_commitment_point = expected_sum_commitment_point + (
                self.context.nums_generators[i] * expected_value_sum
            )
            
        self.assertEqual(expected_sum_commitment_point, summed_sealed_commitment.commitment_point)

    def test_vector_pedersen_revealed_commitment_homomorphic_addition(self):
        """Test homomorphic addition of revealed Vector Pedersen commitments."""
        sealed_commitment1, revealed_commitment1 = self.context.commit(self.test_vector1)
        sealed_commitment2, revealed_commitment2 = self.context.commit(self.test_vector2)

        summed_revealed_commitment = revealed_commitment1 + revealed_commitment2

        # Check basic properties
        self.assertEqual(summed_revealed_commitment.curve_config, self.context.curve_config)
        self.assertEqual(summed_revealed_commitment.nums_generators, self.context.nums_generators)
        self.assertEqual(
            summed_revealed_commitment.commitment_point,
            revealed_commitment1.commitment_point + revealed_commitment2.commitment_point
        )

        # Verify the summed committed values
        expected_summed_vector = [self.test_vector1[i] + self.test_vector2[i] for i in range(self.dimension)]
        self.assertEqual(summed_revealed_commitment.committed, expected_summed_vector)
        
        # Verify the summed blinding factor
        self.assertEqual(
            summed_revealed_commitment.blinding_factor,
            ((revealed_commitment1.blinding_factor + revealed_commitment2.blinding_factor)
                % self.context.curve_config.order)
        )
        
        # Verify the summed commitment
        self.assertTrue(summed_revealed_commitment.verify(), "Summed revealed commitment verification failed.")

    def test_vector_pedersen_revealed_commitment_homomorphic_addition_large_values(self):
        """Test homomorphic addition of revealed Vector Pedersen commitments, including a very large committed value."""
        sealed_commitment1, revealed_commitment1 = self.context.commit(self.test_vector1)
        sealed_commitment_lg, revealed_commitment_lg = self.context.commit(self.large_test_vector)

        summed_revealed_commitment = revealed_commitment1 + revealed_commitment_lg

        # Check basic properties
        self.assertEqual(summed_revealed_commitment.curve_config, self.context.curve_config)
        self.assertEqual(summed_revealed_commitment.nums_generators, self.context.nums_generators)
        self.assertEqual(
            summed_revealed_commitment.commitment_point,
            revealed_commitment1.commitment_point + revealed_commitment_lg.commitment_point
        )

        # Verify the summed committed values
        expected_summed_vector = [(self.test_vector1[i] + self.large_test_vector[i]) % self.context.curve_config.order
                                  for i in range(self.dimension)]
        self.assertEqual(summed_revealed_commitment.committed, expected_summed_vector)

        # Verify the summed blinding factor
        self.assertEqual(
            summed_revealed_commitment.blinding_factor,
            ((revealed_commitment1.blinding_factor + revealed_commitment_lg.blinding_factor)
             % self.context.curve_config.order)
        )

        # Verify the summed commitment
        self.assertTrue(summed_revealed_commitment.verify(), "Summed revealed commitment verification failed.")

    def test_vector_pedersen_input_validation(self):
        """Test input validation for Vector Pedersen commitments."""
        # Test with wrong vector length
        with self.assertRaises(ValueError):
            self.context.commit([1, 2])  # Too short
            
        with self.assertRaises(ValueError):
            self.context.commit([1, 2, 3, 4])  # Too long
            
        # Test with value outside valid range
        curve_order = self.context.curve_config.order
        with self.assertRaises(ValueError):
            self.context.commit([-1, 2, 3])  # Negative value
            
        with self.assertRaises(ValueError):
            self.context.commit([1, curve_order, 3])  # Value ≥ curve order
            
        # Test homomorphic addition with incompatible dimensions
        other_dimension_context = VectorPedersenCommitmentContext.for_curve(
            WeierstrassEllipticCurveConfig.secp256r1(),
            dimension=2
        )
        sealed1, _ = self.context.commit(self.test_vector1)
        sealed2, _ = other_dimension_context.commit([5, 10])
        
        with self.assertRaises(ValueError):
            sealed1 + sealed2  # Different dimensions


if __name__ == '__main__':
    unittest.main()
