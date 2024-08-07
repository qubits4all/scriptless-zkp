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

from scriptless_zkp.he.paillier import (
    PaillierKeyPair, MIN_KEY_SIZE, EncryptedUnsignedInteger
)
from scriptless_zkp.number_theory import mod_inverse
from scriptless_zkp.utils import random_positive_integer


class PaillierHomomorphicEncryptionTests(unittest.TestCase):
    # Reusable key-pair & test data:

    test_key_size: int = MIN_KEY_SIZE
    test_key_pair: PaillierKeyPair = PaillierKeyPair.generate(key_size_bits=test_key_size)

    small_test_msg1: int = 42
    small_test_msg2: int = 1337

    # Generate a full-size random integer, for testing encryption and decryption:
    large_test_msg1: int = random_positive_integer(test_key_pair.public_key.n)

    # Generate random integers half the size of the public key's modulus, for testing homomorphic addition:
    half_modulus: int = test_key_pair.public_key.n // 2
    large_test_msg2: int = random_positive_integer(half_modulus)
    large_test_msg3: int = random_positive_integer(half_modulus)

    # Small test scalar for testing homomorphic scalar multiplication:
    small_test_scalar: int = 13

    # Generate random integers less than the square root of the public key's modulus, for testing homomorphic scalar
    # multiplication:
    # Calculate an approx. of sqrt(n) -- half key bit-size limit
    sqrt_modulus: int = test_key_pair.public_key.n >> (test_key_size // 2)
    large_test_msg4: int = random_positive_integer(sqrt_modulus)
    large_test_scalar: int = random_positive_integer(sqrt_modulus)

    def test_key_pair_generation(self):
        key_pair = PaillierKeyPair.generate(key_size_bits=self.test_key_size)

        # Print the base64-encoded public and private keys.
        print(
            f"\nPublic Key (n, g): {key_pair.public_key.encode_to_base64()}\n"
            f"Private Key (λ, n): {key_pair.private_key.encode_to_base64()}"
        )

        self.assertIsNone(key_pair.validate_key_pair())

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

    def test_homomorphic_addition_of_scalar_and_ciphertext(self):
        # Print the base64-encoded public and private keys.
        print(
            f"\nPublic Key (n, g): {self.test_key_pair.public_key.encode_to_base64()}\n"
            f"Private Key (λ, n): {self.test_key_pair.private_key.encode_to_base64()}"
        )

        ciphertext: EncryptedUnsignedInteger = self.test_key_pair.public_key.encrypt(self.large_test_msg1)

        # Calculate homomorphic sum of ciphertext and scalar, using right-add operator.
        sum_ciphertext: EncryptedUnsignedInteger = self.small_test_scalar + ciphertext

        sum_decrypted: int = self.test_key_pair.private_key.decrypt(sum_ciphertext)

        plaintext_sum: int = self.small_test_scalar + self.large_test_msg1
        print(
            f"\nOriginal plaintext integer (s + p): {self.small_test_scalar} + {self.large_test_msg1} = {plaintext_sum}"
        )
        print(f"Decrypted homomorphic sum of ciphertexts: Dec( Enc(s + p) := Enc(s) * Enc(p) ): {sum_decrypted}")

        self.assertEqual(
            self.large_test_msg1 + self.small_test_scalar,
            sum_decrypted,
            "The decrypted homomorphic sum of a Paillier ciphertext and scalar should match the sum of the"
            " original plaintext integer and scalar."
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

    def test_homomorphic_scalar_multiplication_large_values(self):
        # Print the base64-encoded public and private keys.
        print(
            f"\nPublic Key (n, g): {self.test_key_pair.public_key.encode_to_base64()}\n"
            f"Private Key (λ, n): {self.test_key_pair.private_key.encode_to_base64()}"
        )

        ciphertext: EncryptedUnsignedInteger = self.test_key_pair.public_key.encrypt(self.large_test_msg4)

        # Calculate homomorphic scalar product of ciphertext and scalar multiplier.
        product_ciphertext: EncryptedUnsignedInteger = ciphertext.multiply(self.large_test_scalar)

        product_decrypted: int = self.test_key_pair.private_key.decrypt(product_ciphertext)

        print(
            f"\nOriginal plaintext integer (p * s):"
            f" {self.large_test_msg4} * {self.large_test_scalar} ="
            f" {self.large_test_msg4 * self.large_test_scalar}"
        )
        print(f"Decrypted homomorphic product of ciphertexts: Dec( Enc(p * s) := Enc(p)^s ): {product_decrypted}")

        self.assertEqual(
            self.large_test_msg4 * self.large_test_scalar,
            product_decrypted,
            "The decrypted homomorphic scalar product of a Paillier ciphertext and scalar multiplier should match"
            " the product of the original plaintext integer and scalar."
        )

    def test_ciphertext_obfuscation_and_decryption(self):
        ciphertext: EncryptedUnsignedInteger = self.test_key_pair.public_key.encrypt(self.large_test_msg1)
        obfuscated_ciphertext: EncryptedUnsignedInteger = ciphertext.obfuscate()

        decrypted: int = self.test_key_pair.private_key.decrypt(obfuscated_ciphertext)

        # Verify the obfuscated (re-blinded) ciphertext can be decrypted to recover the original plaintext integer
        # (i.e., showing the obfuscation does not affect the encrypted plaintext or its ability to be recovered).
        self.assertEqual(
            self.large_test_msg1,
            decrypted,
            "The decrypted obfuscated ciphertext should match the original plaintext non-negative integer."
        )

    def test_homomorphic_add_and_obfuscate(self):
        ciphertext1: EncryptedUnsignedInteger = self.test_key_pair.public_key.encrypt(self.large_test_msg2)
        ciphertext2: EncryptedUnsignedInteger = self.test_key_pair.public_key.encrypt(self.large_test_msg3)

        # Add the encrypted ciphertexts together, using Paillier homomorphic addition w/ obfuscation (re-blinding).
        obfuscated_sum: EncryptedUnsignedInteger = ciphertext1.add_and_obfuscate(ciphertext2)

        # Decrypt this homomorphic sum of ciphertexts.
        sum_decrypted: int = self.test_key_pair.private_key.decrypt(obfuscated_sum)

        plaintext_sum: int = self.large_test_msg2 + self.large_test_msg3
        print(
            f"\nOriginal plaintext integers (p1 + p2):"
            f" {self.large_test_msg2} + {self.large_test_msg3} ="
            f" {plaintext_sum}"
        )
        print(
            f"Decrypted obfuscated homomorphic sum of ciphertexts:"
            f" Dec( Enc'(p1 + p2) := Enc(p1) * Enc(p2) * r^n mod n^2 ): {sum_decrypted}"
        )

        # Check if the decrypted homomorphic sum of ciphertexts equals the sum of the original plaintext integers,
        # modulo `n` (the public key's modulus).
        self.assertEqual(
            self.large_test_msg2 + self.large_test_msg3,
            sum_decrypted,
            "The decrypted obfuscated homomorphic sum of Paillier ciphertexts should match the sum of the"
            " original plaintext integers."
        )

    def test_homomorphic_add_and_obfuscate_with_scalar(self):
        ciphertext: EncryptedUnsignedInteger = self.test_key_pair.public_key.encrypt(self.large_test_msg2)

        # Add the encrypted ciphertexts together, using Paillier homomorphic addition w/ obfuscation (re-blinding).
        obfuscated_sum: EncryptedUnsignedInteger = ciphertext.add_and_obfuscate(self.large_test_msg3)

        # Decrypt this homomorphic sum of ciphertexts.
        sum_decrypted: int = self.test_key_pair.private_key.decrypt(obfuscated_sum)

        plaintext_sum: int = self.large_test_msg2 + self.large_test_msg3
        print(
            f"\nOriginal plaintext integers (p1 + p2):"
            f" {self.large_test_msg2} + {self.large_test_msg3} ="
            f" {plaintext_sum}"
        )
        print(
            f"Decrypted obfuscated homomorphic sum of ciphertexts:"
            f" Dec( Enc'(p1 + p2) := Enc(p1) * Enc(p2) * r^n mod n^2 ): {sum_decrypted}"
        )

        # Check if the decrypted homomorphic sum of ciphertexts equals the sum of the original plaintext integers,
        # modulo `n` (the public key's modulus).
        self.assertEqual(
            self.large_test_msg2 + self.large_test_msg3,
            sum_decrypted,
            "The decrypted obfuscated homomorphic sum of Paillier ciphertexts should match the sum of the"
            " original plaintext integers."
        )

    def test_homomorphic_add_and_obfuscate_with_inversion_test(self):
        ciphertext1: EncryptedUnsignedInteger = self.test_key_pair.public_key.encrypt(self.large_test_msg2)
        ciphertext2: EncryptedUnsignedInteger = self.test_key_pair.public_key.encrypt(self.large_test_msg3)

        # Add the encrypted ciphertexts together, using Paillier homomorphic addition w/ obfuscation (re-blinding).
        obfuscated_sum: EncryptedUnsignedInteger = ciphertext1.add_and_obfuscate(ciphertext2)

        # Decrypt this homomorphic sum of ciphertexts.
        sum_decrypted: int = self.test_key_pair.private_key.decrypt(obfuscated_sum)

        plaintext_sum: int = self.large_test_msg2 + self.large_test_msg3
        print(
            f"\nOriginal plaintext integers (p1 + p2):"
            f" {self.large_test_msg2} + {self.large_test_msg3} ="
            f" {plaintext_sum}"
        )
        print(
            f"Decrypted obfuscated homomorphic sum of ciphertexts:"
            f" Dec( Enc'(p1 + p2) := Enc(p1) * Enc(p2) * r^n mod n^2 ): {sum_decrypted}"
        )

        # Check if the decrypted homomorphic sum of ciphertexts equals the sum of the original plaintext integers,
        # modulo `n` (the public key's modulus).
        self.assertEqual(
            self.large_test_msg2 + self.large_test_msg3,
            sum_decrypted,
            "The decrypted obfuscated homomorphic sum of Paillier ciphertexts should match the sum of the"
            " original plaintext integers."
        )

        # Invert the homomorphic addition, using the obfuscated sum and the inverse of the second ciphertext:
        inv_ciphertext2_encrypted: int = mod_inverse(ciphertext2.encrypted, self.test_key_pair.public_key.n2)
        inv_ciphertext2 = EncryptedUnsignedInteger(inv_ciphertext2_encrypted, self.test_key_pair.public_key)
        ciphertext_difference: EncryptedUnsignedInteger = obfuscated_sum + inv_ciphertext2

        # Verify inverting the homomorphic addition, using the obfuscated sum and the inverse of the second ciphertext,
        # does not equal the first ciphertext (i.e., showing the obfuscation prevents recovery of the original
        # ciphertext, given the obfuscated sum and the 2nd ciphertext).
        self.assertNotEqual(
            ciphertext1.encrypted,
            ciphertext_difference.encrypted
        )

        # Verify inverting the homomorphic addition, using the obfuscated sum and the inverse of the second ciphertext,
        # successfully decrypts, to the difference of the plaintext sum and the 2nd plaintext, verifying the obfuscation
        # does not affect the encrypted plaintext or its ability to be recovered.
        difference_decrypted: int = self.test_key_pair.private_key.decrypt(ciphertext_difference)
        self.assertEqual(
            plaintext_sum - self.large_test_msg3,  # self.large_test_msg2
            difference_decrypted
        )

    def test_homomorphic_scalar_multiply_and_obfuscate(self):
        ciphertext: EncryptedUnsignedInteger = self.test_key_pair.public_key.encrypt(self.large_test_msg4)

        # Calculate the obfuscated (re-blinded) homomorphic scalar product of a ciphertext and scalar multiplier.
        obfuscated_product: EncryptedUnsignedInteger = ciphertext.multiply_and_obfuscate(self.large_test_scalar)

        # Decrypt this obfuscated (re-blinded) homomorphic scalar product.
        product_decrypted: int = self.test_key_pair.private_key.decrypt(obfuscated_product)

        print(
            f"\nOriginal plaintext integer (p * s):"
            f" {self.large_test_msg4} * {self.large_test_scalar} ="
            f" {self.large_test_msg4 * self.large_test_scalar}"
        )
        print(
            f"Decrypted obfuscated homomorphic scalar product:"
            f" Dec( Enc'(p * s) := Enc(p)^s * r^n mod n^2 ): {product_decrypted}"
        )

        # Verify the obfuscated (re-blinded) homomorphic product of the ciphertext and scalar multiplier can be
        # decrypted to recover the product of the original plaintext integer and scalar (i.e., showing the re-blinding
        # does not affect the encrypted plaintext or its ability to be recovered).
        self.assertEqual(
            self.large_test_msg4 * self.large_test_scalar,
            product_decrypted,
            "The decrypted obfuscated (re-blinded) homomorphic scalar product of a Paillier ciphertext and scalar"
            " multiplier should match the product of the original plaintext integer and scalar."
        )

        # Knowledge of the scalar multiplier, or its discovery (e.g., via brute-force search for small scalars), should
        # not enable equality comparison of an un-obfuscated homomorphic product ciphertext, of the original ciphertext
        # and scalar, with the obfuscated homomorphic product ciphertext (i.e., ensuring indistinguishability of
        # ciphertexts).
        # (That is, obfuscation/re-blinding should prevent recovery of the scalar multiplier via brute-force search,
        # even for small scalars -- e.g., 32-bit integers.)
        # (Note: Equivalent test to the below test-case, but without requiring inversion of the scalar multiplier.)
        unblinded_product = ciphertext.multiply(self.large_test_scalar)
        self.assertNotEqual(
            unblinded_product.encrypted,
            obfuscated_product.encrypted,
            "The homomorphic scalar product of the ciphertext and its scalar multiplier should not equal the"
            " obfuscated homomorphic scalar product ciphertext."
        )

        # Verify the unblinded homomorphic product, of the original ciphertext and scalar multiplier, decrypts to the
        # same value as the re-blinded (obfuscated) homomorphic product.
        unblinded_product_decrypted: int = self.test_key_pair.private_key.decrypt(unblinded_product)
        self.assertEqual(
            product_decrypted,
            unblinded_product_decrypted,
            "The decrypted homomorphic product of the ciphertext and scalar multiplier should match the decrypted"
            " homomorphic product of the un-obfuscated ciphertext and scalar multiplier."
        )

    def test_homomorphic_scalar_multiply_and_obfuscate_with_inversion_test(self):
        ciphertext: EncryptedUnsignedInteger = self.test_key_pair.public_key.encrypt(self.large_test_msg4)

        # Calculate the obfuscated (re-blinded) homomorphic scalar product of a ciphertext and scalar multiplier.
        obfuscated_product: EncryptedUnsignedInteger = ciphertext.multiply_and_obfuscate(self.large_test_scalar)

        # Decrypt this obfuscated (re-blinded) homomorphic scalar product.
        product_decrypted: int = self.test_key_pair.private_key.decrypt(obfuscated_product)

        print(
            f"\nOriginal plaintext integer (p * s):"
            f" {self.large_test_msg4} * {self.large_test_scalar} ="
            f" {self.large_test_msg4 * self.large_test_scalar}"
        )
        print(
            f"Decrypted obfuscated homomorphic scalar product:"
            f" Dec( Enc'(p * s) := Enc(p)^s * r^n mod n^2 ): {product_decrypted}"
        )

        # Verify the obfuscated (re-blinded) homomorphic product of the ciphertext and scalar multiplier can be
        # decrypted to recover the product of the original plaintext integer and scalar (i.e., showing the re-blinding
        # does not affect the encrypted plaintext or its ability to be recovered).
        self.assertEqual(
            self.large_test_msg4 * self.large_test_scalar,
            product_decrypted,
            "The decrypted obfuscated (re-blinded) homomorphic scalar product of a Paillier ciphertext and scalar"
            " multiplier should match the product of the original plaintext integer and scalar."
        )

        # Verify the homomorphic product of the obfuscated (re-blinded) ciphertext and its scalar multiplier's inverse
        # modulo n^2 does _not_ equal the original ciphertext. This test shows that even knowledge of the scalar
        # multiplier is insufficient to recover the original ciphertext (i.e., due to the additional re-blinding
        # factor).
        # Note: This means the obfuscation (re-blinding) is effective at hiding the (homomorphic) linear relationship
        #   between the original ciphertext and obfuscated homomorphic product. Crucially this indicates the scalar
        #   multiplier cannot be recovered by an adversary via brute-force, even if this scalar multiplier is small
        #   (e.g., a 32-bit integer), given the original ciphertext and obfuscated homomorphic product ciphertext.
        exponent_modulus: int = self.test_key_pair.public_key.n
        scalar_inv: int = mod_inverse(self.large_test_scalar, exponent_modulus)

        # Invert the scalar multiplication, using the scalar's modular multiplicative inverse modulo λ(n^2) = λ(n) * n.
        obfuscated_quotient: EncryptedUnsignedInteger = obfuscated_product.multiply(scalar_inv)
        self.assertNotEqual(
            obfuscated_quotient.encrypted,
            ciphertext.encrypted,
            "The homomorphic product of the obfuscated ciphertext and its scalar multiplier's inverse modulo n^2"
            " should not equal the original ciphertext."
        )

        # Verify the homomorphic product of the obfuscated ciphertext and its scalar multiplier's inverse modulo n^2
        # can be decrypted to recover the original plaintext integer. This test shows that obfuscation does not prevent
        # the homomorphic scalar multiplication from being reversible, with knowledge of the scalar multiplier
        # (i.e., re: the decryption of such a quotient).
        quotient_decrypted: int = self.test_key_pair.private_key.decrypt(obfuscated_quotient)
        self.assertEqual(
            self.large_test_msg4,
            quotient_decrypted,
            "The decryption of the homomorphic product of the obfuscated ciphertext and its scalar multiplier's"
            " inverse modulo n^2 should match the original plaintext integer."
        )


if __name__ == '__main__':
    unittest.main()
