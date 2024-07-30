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

from scriptless_zkp.ecc.generators import ECCGeneratorDerivationContext
from scriptless_zkp.ecc.weierstrass_curves import WeierstrassEllipticCurveConfig


class ECCGeneratorDerivationContextTests(unittest.TestCase):
    NUMS_GENERATOR_NONCE1: int = 42
    NUMS_GENERATOR_NONCE2: int = 1337
    NUMS_GENERATOR_DOMAIN_SEPARATOR: str = "NUMS-Generator-Test"

    curve_config = WeierstrassEllipticCurveConfig.secp256r1()

    generator_context_no_domain_separator = ECCGeneratorDerivationContext(curve_config)

    generator_context_with_domain_separator = ECCGeneratorDerivationContext(
        curve_config,
        domain_separation_tag=NUMS_GENERATOR_DOMAIN_SEPARATOR
    )

    def test_nums_generator_reproducible_derivation(self):
        generator1 = self.generator_context_no_domain_separator.derive_generator_for_nonce(
            ECCGeneratorDerivationContextTests.NUMS_GENERATOR_NONCE1
        )
        generator2 = self.generator_context_no_domain_separator.derive_generator_for_nonce(
            ECCGeneratorDerivationContextTests.NUMS_GENERATOR_NONCE1
        )

        self.assertFalse(generator1.is_point_at_infinity())
        self.assertFalse(generator2.is_point_at_infinity())

        self.assertEqual(generator1, generator2)

    def test_generate_random_nums_generator_unreproducible(self):
        generator1 = self.generator_context_no_domain_separator.derive_random_generator()
        generator2 = self.generator_context_no_domain_separator.derive_random_generator()

        self.assertFalse(generator1.is_point_at_infinity())
        self.assertFalse(generator2.is_point_at_infinity())

        self.assertNotEqual(generator1, generator2)

    def test_nums_generator_derivation_unequal_for_distinct_nonces(self):
        generator1 = self.generator_context_no_domain_separator.derive_generator_for_nonce(
            ECCGeneratorDerivationContextTests.NUMS_GENERATOR_NONCE1
        )
        generator2 = self.generator_context_no_domain_separator.derive_generator_for_nonce(
            ECCGeneratorDerivationContextTests.NUMS_GENERATOR_NONCE2
        )

        self.assertFalse(generator1.is_point_at_infinity())
        self.assertFalse(generator2.is_point_at_infinity())

        self.assertNotEqual(generator1, generator2)

    def test_nums_generator_derivation_unequal_for_distinct_domain_separators(self):
        generator_without_domain_separator = self.generator_context_no_domain_separator.derive_generator_for_nonce(
            ECCGeneratorDerivationContextTests.NUMS_GENERATOR_NONCE2
        )
        generator_with_domain_separator = self.generator_context_with_domain_separator.derive_generator_for_nonce(
            ECCGeneratorDerivationContextTests.NUMS_GENERATOR_NONCE2
        )

        self.assertFalse(generator_without_domain_separator.is_point_at_infinity())
        self.assertFalse(generator_with_domain_separator.is_point_at_infinity())

        self.assertNotEqual(generator_without_domain_separator, generator_with_domain_separator)

    def test_generate_random_nums_generator_unequal_for_distinct_domain_separators(self):
        generator_without_domain_separator = self.generator_context_no_domain_separator.derive_random_generator()
        generator_with_domain_separator = self.generator_context_with_domain_separator.derive_random_generator()

        self.assertFalse(generator_without_domain_separator.is_point_at_infinity())
        self.assertFalse(generator_with_domain_separator.is_point_at_infinity())

        self.assertNotEqual(generator_without_domain_separator, generator_with_domain_separator)


if __name__ == '__main__':
    unittest.main()
