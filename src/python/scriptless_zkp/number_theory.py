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

"""
This module provides number-theoretic functions that are used by various modules.
"""

from libnum import sqrtmod_prime_power


def legendre_symbol(a: int, prime_modulus: int) -> int:
    """
    Computes the Legendre symbol of `a` modulo `p`, where `p` is an odd prime. This function returns 1 if `a` is a
    quadratic residue modulo `p`, -1 if `a` is a quadratic non-residue modulo `p`, and 0 if `a` is divisible by `p`.
    :param a: the integer for which the Legendre symbol is computed.
    :param prime_modulus: the odd prime modulus `p` for the Legendre symbol computation.
    :return: the Legendre symbol of `a` modulo `p`, for a prime modulus `p`.
    """
    return pow(a, (prime_modulus - 1) // 2, prime_modulus)


def is_quadratic_residue(a: int, prime_modulus: int) -> bool:
    """
    Determines whether the given integer `a` is a quadratic residue modulo the odd prime `prime_modulus`.
    :param a: the integer to be tested for being a quadratic residue.
    :param prime_modulus: the odd prime modulus for the quadratic residue test.
    :return: True if `a` is a quadratic residue modulo `prime_modulus`, False otherwise.
    """
    return legendre_symbol(a, prime_modulus) == 1


def is_quadratic_nonresidue(a: int, prime_modulus: int) -> bool:
    """
    Determines whether the given integer `a` is a quadratic non-residue modulo the odd prime `prime_modulus`.
    :param a: the integer to be tested for being a quadratic non-residue.
    :param prime_modulus: the odd prime modulus for the quadratic non-residue test.
    :return: True if `a` is a quadratic non-residue modulo `prime_modulus`, False otherwise.
    """
    return legendre_symbol(a, prime_modulus) == -1


def mod_sqrt(a: int, prime_modulus: int) -> int:
    """
    Computes the modular square root of the integer `a` modulo the odd prime `prime_modulus`, using the Tonelli-Shanks
    algorithm. This function returns the positive square root of `a` modulo `prime_modulus`.
    :param a: the integer for which the modular square root is computed.
    :param prime_modulus: the odd prime modulus for the modular square root computation.
    :return: the positive square root of `a` modulo `prime_modulus`.
    """
    if not is_quadratic_residue(a, prime_modulus):
        raise ValueError(f"The integer {a} is not a quadratic residue modulo the prime modulus {prime_modulus}")

    if prime_modulus % 4 == 3:
        # DEBUG
        print(
            f"DEBUG: Computing modular square root of a: {a} modulo prime modulus p: {prime_modulus} (p == 3 mod 4),"
            f" using identity: sqrt(a) mod p = a^((p + 1) / 4) mod p"
        )

        # Compute modular square root using the identity: `sqrt(a) mod p = a^((p + 1) / 4) mod p` (where p == 3 mod 4).
        return pow(a, (prime_modulus + 1) // 4, prime_modulus)
    else:  # prime_modulus % 4 == 1  (Note: Must use the Tonelli-Shanks algorithm for prime modulus p == 1 mod 4.)
        # DEBUG
        print(
            f"DEBUG: Computing modular square root of {a} modulo prime modulus {prime_modulus} (p == 1 mod 4), using"
            f" libnum's sqrtmod_prime_power(...)."
        )

        return next(
            sqrtmod_prime_power(a, prime_modulus, 1)
        )
