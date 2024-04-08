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

from __future__ import annotations

import unittest

from Cryptodome.PublicKey import ECC

from scriptless_zkp.ecc.weierstrass_curves import WeierstrassEllipticCurveConfig
from scriptless_zkp.ecc.zkp.nizk_equal_dlogs_proof import (
    NIZKEqualDiscreteLogsContext, NIZKEqualDiscreteLogsProver, NIZKDiscreteLogParameterSet,
    ECCDiscreteLogBaseAndProduct, NIZKEqualDiscreteLogsProof
)


class NIZKEqualDiscreteLogsProofTests(unittest.TestCase):
    context = NIZKEqualDiscreteLogsContext(WeierstrassEllipticCurveConfig.secp256r1())
    dlog_params_set: NIZKDiscreteLogParameterSet
    common_dlog: int = 13

    def setUp(self) -> None:
        base2_dlog: int = 7
        dlog_base1: ECC.EccPoint = self.context.G
        dlog_base2: ECC.EccPoint = self.context.G * base2_dlog
        ecc_pt1: ECC.EccPoint = self.context.G * self.common_dlog
        ecc_pt2: ECC.EccPoint = dlog_base2 * self.common_dlog
        self.dlog_params_set = NIZKDiscreteLogParameterSet(
            self.context.curve_config,
            [
                ECCDiscreteLogBaseAndProduct((dlog_base1, ecc_pt1)),
                ECCDiscreteLogBaseAndProduct((dlog_base2, ecc_pt2)),
            ]
        )

    def test_proof_creation(self):
        prover = NIZKEqualDiscreteLogsProver(self.context.curve_config)
        zk_proof: NIZKEqualDiscreteLogsProof = prover.calc_proof(self.common_dlog, self.dlog_params_set)

        self.assertIsNotNone(zk_proof)
        print(f"NIZK Equal Discrete Logs Proof: {zk_proof}\n")
        self.assertIsInstance(zk_proof, NIZKEqualDiscreteLogsProof)

        self.assertIsInstance(zk_proof.context, NIZKEqualDiscreteLogsContext)
        self.assertIsInstance(zk_proof.context.curve_config, WeierstrassEllipticCurveConfig)
        self.assertEqual(zk_proof.context.curve_config, self.context.curve_config)

        self.assertIsInstance(zk_proof.proof_pub_hash, int)
        self.assertGreater(zk_proof.proof_pub_hash, 0)

        self.assertIsInstance(zk_proof.proof_signature, int)
        self.assertGreater(zk_proof.proof_signature, 0)

        self.assertIsInstance(zk_proof.hash_algo, str)
        self.assertEqual(zk_proof.hash_algo, NIZKEqualDiscreteLogsContext.DEFAULT_HASH_ALGORITHM)

    def test_proof_verification(self):
        prover = NIZKEqualDiscreteLogsProver(self.context.curve_config)
        zk_proof: NIZKEqualDiscreteLogsProof = prover.calc_proof(self.common_dlog, self.dlog_params_set)

        self.assertIsNotNone(zk_proof)
        print(f"NIZK Equal Discrete Logs Proof: {zk_proof}\n")
        self.assertIsInstance(zk_proof, NIZKEqualDiscreteLogsProof)

        self.assertTrue(zk_proof.verify())


if __name__ == '__main__':
    unittest.main()
