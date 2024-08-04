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

from scriptless_zkp.he.paillier import PaillierKeyPair, MIN_KEY_SIZE, DEFAULT_KEY_SIZE


class PaillierHomomorphicEncryptionTests(unittest.TestCase):
    key_size: int = MIN_KEY_SIZE
    key_pair = PaillierKeyPair.generate(key_size_bits=key_size)

    def test_key_pair_generation(self):
        key_pair = PaillierKeyPair.generate(key_size_bits=self.key_size)

        # Check if: g^λ == 1 mod n
        self.assertEqual(
            pow(key_pair.public_key.g, key_pair.private_key.lam, key_pair.public_key.n),
            1,
            "The public key's generator `g` raised to the private key `λ(n)` should be congruent to 1 modulo `n`."
        )

        # Check if: g^nλ == 1 mod n^2
        self.assertEqual(
            pow(key_pair.public_key.g, key_pair.public_key.n * key_pair.private_key.lam, key_pair.public_key.n_squared),
            1,
            "The public key's generator `g` raised to the product of the public key `n` and the private key `λ(n)`"
            " should be congruent to 1 modulo `n^2`."
        )

    def test_encryption_validity(self):
        plaintext = 42
        ciphertext = self.key_pair.public_key.encrypt(plaintext)

        # Check if the ciphertext is a valid encryption of the plaintext.
        self.assertGreater(ciphertext.encrypted, 0, "The encrypted value should be a positive integer.")
        self.assertLess(
            ciphertext.encrypted, self.key_pair.public_key.n_squared, "The encrypted value should be less than n^2."
        )

    def test_encryption_decryption(self):
        plaintext = 42
        ciphertext = self.key_pair.public_key.encrypt(plaintext)

        decrypted = self.key_pair.private_key.decrypt(ciphertext)

        self.assertEqual(plaintext, decrypted, "The decrypted value should match the original plaintext.")


if __name__ == '__main__':
    unittest.main()
