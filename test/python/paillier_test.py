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

import secrets
import unittest

from scriptless_zkp.he.paillier import PaillierKeyPair, MIN_KEY_SIZE


class PaillierHomomorphicEncryptionTests(unittest.TestCase):
    test_key_size: int = MIN_KEY_SIZE
    test_key_pair: PaillierKeyPair = PaillierKeyPair.generate(key_size_bits=test_key_size)

    small_test_msg: int = 42
    while (large_test_msg := secrets.randbelow(test_key_pair.public_key.n)) == 0:
        pass

    def test_key_pair_generation(self):
        key_pair = PaillierKeyPair.generate(key_size_bits=self.test_key_size)

        # Print the base64-encoded public and private keys.
        print(
            f"\nPublic Key (n, g): {key_pair.public_key.encode_to_base64()}\n"
            f"Private Key (λ, n): {key_pair.private_key.encode_to_base64()}"
        )

        # Check if: g^λ == 1 mod n
        self.assertEqual(
            pow(key_pair.public_key.g, key_pair.private_key.λ, key_pair.public_key.n),
            1,
            "The public key's generator `g` raised to the private key `λ(n)` should be congruent to 1 modulo `n`."
        )

        # Check if: g^nλ == 1 mod n^2
        self.assertEqual(
            pow(key_pair.public_key.g, key_pair.public_key.n * key_pair.private_key.λ, key_pair.public_key.n2),
            1,
            "The public key's generator `g` raised to the product of the public key `n` and the private key `λ(n)`"
            " should be congruent to 1 modulo `n^2`."
        )

    def test_encryption_validity_small_message(self):
        # Print the base64-encoded public and private keys.
        print(
            f"\nPublic Key (n, g): {self.test_key_pair.public_key.encode_to_base64()}\n"
            f"Private Key (λ, n): {self.test_key_pair.private_key.encode_to_base64()}"
        )

        ciphertext = self.test_key_pair.public_key.encrypt(self.small_test_msg)

        # Check if the ciphertext is a valid encryption of the plaintext.
        self.assertGreater(ciphertext.encrypted, 0, "The encrypted value should be a positive integer.")
        self.assertLess(
            ciphertext.encrypted, self.test_key_pair.public_key.n2, "The encrypted value should be less than n^2."
        )

    def test_encryption_validity_large_message(self):
        # Print the base64-encoded public and private keys.
        print(
            f"\nPublic Key (n, g): {self.test_key_pair.public_key.encode_to_base64()}\n"
            f"Private Key (λ, n): {self.test_key_pair.private_key.encode_to_base64()}"
        )

        ciphertext = self.test_key_pair.public_key.encrypt(self.large_test_msg)

        # Check if the ciphertext is a valid encryption of the plaintext.
        self.assertGreater(ciphertext.encrypted, 0, "The encrypted value should be a positive integer.")
        self.assertLess(
            ciphertext.encrypted, self.test_key_pair.public_key.n2, "The encrypted value should be less than n^2."
        )

    def test_encryption_decryption_small_message(self):
        # Print the base64-encoded public and private keys.
        print(
            f"\nPublic Key (n, g): {self.test_key_pair.public_key.encode_to_base64()}\n"
            f"Private Key (λ, n): {self.test_key_pair.private_key.encode_to_base64()}"
        )

        ciphertext = self.test_key_pair.public_key.encrypt(self.small_test_msg)

        decrypted = self.test_key_pair.private_key.decrypt(ciphertext)

        self.assertEqual(self.small_test_msg, decrypted, "The decrypted value should match the original plaintext.")

    def test_encryption_decryption_large_message(self):
        # Print the base64-encoded public and private keys.
        print(
            f"\nPublic Key (n, g): {self.test_key_pair.public_key.encode_to_base64()}\n"
            f"Private Key (λ, n): {self.test_key_pair.private_key.encode_to_base64()}"
        )

        ciphertext = self.test_key_pair.public_key.encrypt(self.large_test_msg)

        decrypted = self.test_key_pair.private_key.decrypt(ciphertext)

        self.assertEqual(self.large_test_msg, decrypted, "The decrypted value should match the original plaintext.")


if __name__ == '__main__':
    unittest.main()
