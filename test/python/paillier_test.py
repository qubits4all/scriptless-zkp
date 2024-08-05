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

from scriptless_zkp.he.paillier import PaillierKeyPair, MIN_KEY_SIZE, EncryptedUnsignedInteger


class PaillierHomomorphicEncryptionTests(unittest.TestCase):
    # Reusable key-pair & test data:

    test_key_size: int = MIN_KEY_SIZE
    test_key_pair: PaillierKeyPair = PaillierKeyPair.generate(key_size_bits=test_key_size)

    small_test_msg1: int = 42
    small_test_msg2: int = 1337

    # Generate a full-size random integer, for testing encryption and decryption:
    while (large_test_msg1 := secrets.randbelow(test_key_pair.public_key.n)) == 0:
        pass

    # Generate random integers half the size of the public key's modulus, for testing homomorphic addition:
    half_modulus: int = test_key_pair.public_key.n // 2
    while (large_test_msg2 := secrets.randbelow(half_modulus)) == 0:
        pass
    while (large_test_msg3 := secrets.randbelow(half_modulus)) == 0:
        pass

    # Small test scalar for testing homomorphic scalar multiplication:
    small_test_scalar: int = 13

    # Generate random integers less than the square root of the public key's modulus, for testing homomorphic scalar
    # multiplication:
    # Calculate an approx. of sqrt(n) -- half key bit-size limit
    sqrt_modulus: int = test_key_pair.public_key.n << (test_key_size // 2)
    while (large_test_msg4 := secrets.randbelow(sqrt_modulus)) == 0:
        pass
    while (large_test_scalar := secrets.randbelow(sqrt_modulus)) == 0:
        pass

    def test_key_pair_generation(self):
        key_pair = PaillierKeyPair.generate(key_size_bits=self.test_key_size)

        # Print the base64-encoded public and private keys.
        print(
            f"\nPublic Key (n, g): {key_pair.public_key.encode_to_base64()}\n"
            f"Private Key (λ, n): {key_pair.private_key.encode_to_base64()}"
        )

        # Verify: `g^λ == 1 mod n` (see: PaillierPublicKey._validate(...))
        self.assertEqual(
            pow(key_pair.public_key.g, key_pair.private_key.λ, key_pair.public_key.n),
            1,
            "The public key's generator `g` raised to the private key `λ(n)` should be congruent to 1 modulo `n`"
            "  (i.e., `g^λ == 1 mod n`)."
        )

        # Verify: `g^nλ == 1 mod n^2` (see: PaillierPublicKey._validate(...))
        self.assertEqual(
            pow(key_pair.public_key.g, key_pair.public_key.n * key_pair.private_key.λ, key_pair.public_key.n2),
            1,
            "The public key's generator `g` raised to the product of the public key `n` and the private key `λ(n)`"
            " should be congruent to 1 modulo `n^2` (i.e., `g^nλ == 1 mod n^2`)."
        )

    def test_encryption_validity_small_value(self):
        # Print the base64-encoded public and private keys.
        print(
            f"\nPublic Key (n, g): {self.test_key_pair.public_key.encode_to_base64()}\n"
            f"Private Key (λ, n): {self.test_key_pair.private_key.encode_to_base64()}"
        )

        ciphertext = self.test_key_pair.public_key.encrypt(self.small_test_msg1)

        # Check if the ciphertext is a valid encryption of the plaintext.
        self.assertGreater(ciphertext.encrypted, 0, "The encrypted value should be a positive integer.")
        self.assertLess(
            ciphertext.encrypted, self.test_key_pair.public_key.n2, "The encrypted value should be less than n^2."
        )

    def test_encryption_validity_large_value(self):
        # Print the base64-encoded public and private keys.
        print(
            f"\nPublic Key (n, g): {self.test_key_pair.public_key.encode_to_base64()}\n"
            f"Private Key (λ, n): {self.test_key_pair.private_key.encode_to_base64()}"
        )

        ciphertext = self.test_key_pair.public_key.encrypt(self.large_test_msg1)

        # Check if the ciphertext is a valid encryption of the plaintext.
        self.assertGreater(ciphertext.encrypted, 0, "The encrypted value should be a positive integer.")
        self.assertLess(
            ciphertext.encrypted, self.test_key_pair.public_key.n2, "The encrypted value should be less than n^2."
        )

    def test_encryption_and_decryption_small_value(self):
        # Print the base64-encoded public and private keys.
        print(
            f"\nPublic Key (n, g): {self.test_key_pair.public_key.encode_to_base64()}\n"
            f"Private Key (λ, n): {self.test_key_pair.private_key.encode_to_base64()}"
        )

        ciphertext = self.test_key_pair.public_key.encrypt(self.small_test_msg1)

        decrypted = self.test_key_pair.private_key.decrypt(ciphertext)

        self.assertEqual(self.small_test_msg1, decrypted, "The decrypted value should match the original plaintext.")

    def test_encryption_and_decryption_large_value(self):
        # Print the base64-encoded public and private keys.
        print(
            f"\nPublic Key (n, g): {self.test_key_pair.public_key.encode_to_base64()}\n"
            f"Private Key (λ, n): {self.test_key_pair.private_key.encode_to_base64()}"
        )

        ciphertext = self.test_key_pair.public_key.encrypt(self.large_test_msg1)

        decrypted = self.test_key_pair.private_key.decrypt(ciphertext)

        self.assertEqual(self.large_test_msg1, decrypted, "The decrypted value should match the original plaintext.")

    def test_homomorphic_addition_of_small_values(self):
        # Print the base64-encoded public and private keys.
        print(
            f"\nPublic Key (n, g): {self.test_key_pair.public_key.encode_to_base64()}\n"
            f"Private Key (λ, n): {self.test_key_pair.private_key.encode_to_base64()}"
        )

        ciphertext1: EncryptedUnsignedInteger = self.test_key_pair.public_key.encrypt(self.small_test_msg1)
        ciphertext2: EncryptedUnsignedInteger = self.test_key_pair.public_key.encrypt(self.small_test_msg2)

        # Add the encrypted ciphertexts together, using Paillier homomorphic addition.
        sum_ciphertext: EncryptedUnsignedInteger = ciphertext1 + ciphertext2

        # Decrypt this homomorphic sum of ciphertexts.
        sum_decrypted: int = self.test_key_pair.private_key.decrypt(sum_ciphertext)

        print(
            f"\nOriginal plaintext integers (p1 + p2):"
            f" {self.small_test_msg1} + {self.small_test_msg2} ="
            f" {self.small_test_msg1 + self.small_test_msg2}"
        )
        print(f"Decrypted homomorphic sum of ciphertexts: Dec( Enc(p1 + p2) := Enc(p1) * Enc(p2) ): {sum_decrypted}")

        # Check if the decrypted homomorphic sum of ciphertexts equals the sum of the original plaintext integers,
        # modulo `n` (the public key's modulus).
        self.assertEqual(
            self.small_test_msg1 + self.small_test_msg2,
            sum_decrypted,
            "The decrypted homomorphic sum of Paillier ciphertexts should match the sum of the original plaintext"
            " integers."
        )

    def test_homomorphic_addition_of_large_values(self):
        # Print the base64-encoded public and private keys.
        print(
            f"\nPublic Key (n, g): {self.test_key_pair.public_key.encode_to_base64()}\n"
            f"Private Key (λ, n): {self.test_key_pair.private_key.encode_to_base64()}"
        )

        ciphertext1: EncryptedUnsignedInteger = self.test_key_pair.public_key.encrypt(self.large_test_msg2)
        ciphertext2: EncryptedUnsignedInteger = self.test_key_pair.public_key.encrypt(self.large_test_msg3)

        # Add the encrypted ciphertexts together, using Paillier homomorphic addition.
        sum_ciphertext: EncryptedUnsignedInteger = ciphertext1 + ciphertext2

        # Decrypt this homomorphic sum of ciphertexts.
        sum_decrypted: int = self.test_key_pair.private_key.decrypt(sum_ciphertext)

        print(
            f"\nOriginal plaintext integers (p1 + p2):"
            f" {self.large_test_msg2} + {self.large_test_msg3} ="
            f" {self.large_test_msg2 + self.large_test_msg3}"
        )
        print(f"Decrypted homomorphic sum of ciphertexts: Dec( Enc(p1 + p2) := Enc(p1) * Enc(p2) ): {sum_decrypted}")

        # Check if the decrypted homomorphic sum of ciphertexts equals the sum of the original plaintext integers,
        # modulo `n` (the public key's modulus).
        self.assertEqual(
            self.large_test_msg2 + self.large_test_msg3,
            sum_decrypted,
            "The decrypted homomorphic sum of Paillier ciphertexts should match the sum of the original plaintext"
            " integers."
        )

    def test_homomorphic_scalar_multiplication_mul_small_values(self):
        # Print the base64-encoded public and private keys.
        print(
            f"\nPublic Key (n, g): {self.test_key_pair.public_key.encode_to_base64()}\n"
            f"Private Key (λ, n): {self.test_key_pair.private_key.encode_to_base64()}"
        )

        ciphertext: EncryptedUnsignedInteger = self.test_key_pair.public_key.encrypt(self.small_test_msg1)

        # Calculate homomorphic scalar product of ciphertext and scalar multiplier, using left multiply operator.
        product_ciphertext: EncryptedUnsignedInteger = ciphertext * self.small_test_scalar

        product_decrypted: int = self.test_key_pair.private_key.decrypt(product_ciphertext)

        print(
            f"\nOriginal plaintext integer (p * s):"
            f" {self.small_test_msg1} * {self.small_test_scalar} ="
            f" {self.small_test_msg1 * self.small_test_scalar}"
        )
        print(f"Decrypted homomorphic product of ciphertexts: Dec( Enc(p * s) := Enc(p)^s ): {product_decrypted}")

        self.assertEqual(
            self.small_test_msg1 * self.small_test_scalar,
            product_decrypted,
            "The decrypted homomorphic scalar product of a Paillier ciphertext and scalar multiplier should match"
            " the product of the original plaintext integer and scalar."
        )

    def test_homomorphic_scalar_multiplication_rmul_small_values(self):
        # Print the base64-encoded public and private keys.
        print(
            f"\nPublic Key (n, g): {self.test_key_pair.public_key.encode_to_base64()}\n"
            f"Private Key (λ, n): {self.test_key_pair.private_key.encode_to_base64()}"
        )

        ciphertext: EncryptedUnsignedInteger = self.test_key_pair.public_key.encrypt(self.small_test_msg1)

        # Calculate homomorphic scalar product of ciphertext and scalar multiplier, using right multiply operator.
        product_ciphertext: EncryptedUnsignedInteger = self.small_test_scalar * ciphertext

        product_decrypted: int = self.test_key_pair.private_key.decrypt(product_ciphertext)

        print(
            f"\nOriginal plaintext integer (p * s):"
            f" {self.small_test_msg1} * {self.small_test_scalar} ="
            f" {self.small_test_msg1 * self.small_test_scalar}"
        )
        print(f"Decrypted homomorphic product of ciphertexts: Dec( Enc(p * s) := Enc(p)^s ): {product_decrypted}")

        self.assertEqual(
            self.small_test_msg1 * self.small_test_scalar,
            product_decrypted,
            "The decrypted homomorphic scalar product of a Paillier ciphertext and scalar multiplier should match"
            " the product of the original plaintext integer and scalar."
        )

    def test_ciphertext_obfuscation_and_decryption(self):
        ciphertext: EncryptedUnsignedInteger = self.test_key_pair.public_key.encrypt(self.large_test_msg1)
        obfuscated_ciphertext: EncryptedUnsignedInteger = ciphertext.obfuscate()

        decrypted: int = self.test_key_pair.private_key.decrypt(obfuscated_ciphertext)

        self.assertEqual(
            self.large_test_msg1,
            decrypted,
            "The decrypted obfuscated ciphertext should match the original plaintext non-negative integer."
        )


if __name__ == '__main__':
    unittest.main()
