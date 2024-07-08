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

from scriptless_zkp.ecc.ecc_utils import WeierstrassEllipticCurveConfig
from scriptless_zkp.ecc.signatures.schnorr import SchnorrContext, SchnorrKeyPair, SchnorrPublicKey, SchnorrSignature


class ECCSchnorrTests(unittest.TestCase):
    context = SchnorrContext(WeierstrassEllipticCurveConfig.secp256r1())

    def test_Schnorr_key_generation(self):
        key_pair = SchnorrKeyPair.generate(self.context)

        self.assertTrue(key_pair.ecc_key_pair.has_private())
        # Verify `Q != O` (i.e., the point-at-infinity).
        self.assertFalse(key_pair.ecc_key_pair.pointQ.is_point_at_infinity())
        self.assertEqual(key_pair.context, self.context)

    def test_Schnorr_signature_generation(self):
        key_pair = SchnorrKeyPair.generate(self.context)

        test_message: bytes = b'foo'
        signature: SchnorrSignature = key_pair.sign(test_message)

        # Verify `R != O` (i.e., the point-at-infinity).
        self.assertFalse(signature.public_nonce.is_point_at_infinity())
        # Verify `s * G != O` (i.e., the point-at-infinity).
        self.assertFalse((self.context.ecc_curve_config.base_point * signature.signature).is_point_at_infinity())

    def test_Schnorr_signature_verification(self):
        key_pair = SchnorrKeyPair.generate(self.context)

        test_message: bytes = b'foo'
        signature: SchnorrSignature = key_pair.sign(test_message)

        public_key: SchnorrPublicKey = key_pair.public_key
        self.assertTrue(public_key.verify_signature(signature, test_message))


if __name__ == '__main__':
    unittest.main()
