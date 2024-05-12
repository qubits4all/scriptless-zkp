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
    if prime_modulus < 3:
        raise ValueError("The Legendre symbol is only defined for an odd prime modulus.")

    if a == 0 or a % prime_modulus == 0:
        return 0
    elif a == 1 or a % prime_modulus == 1:
        return 1
    # Applying the law of quadratic reciprocity (1st supplement): `a == -1 or a == p - 1 (mod p)`
    elif a == -1 or a % prime_modulus == prime_modulus - 1:
        if prime_modulus % 4 == 1:
            return 1
        else:  # prime_modulus % 4 == 3
            return -1
    # Applying the law of quadratic reciprocity (2nd supplement):
    elif a == 2:
        if prime_modulus % 8 in {1, 7}:
            return 1
        else:  # prime_modulus % 8 in {3, 5}
            return -1
    # Applying special formula for a == 3 & p != 3:
    elif a == 3 and prime_modulus != 3:
        if prime_modulus % 12 in {1, 11}:
            return 1
        else:  # prime_modulus % 12 in {5, 7}
            return -1
    # Applying special formula for a == 5 & p != 5:
    elif a == 5 and prime_modulus != 5:
        if prime_modulus % 5 in {1, 4}:
            return 1
        else:  # prime_modulus % 5 in {2, 3}
            return -1
    # Using Euler's criterion: `a^((p - 1) / 2) mod p`
    else:
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


def has_mod_sqrt(a: int, prime_modulus: int) -> bool:
    """
    Determines whether the given integer `a` has a square root modulo the given prime `prime_modulus` (i.e., whether
    there exists an integer `n` such that `n² == a mod p`, where `==` here represents congruence).
    :param a: an integer for which the existence of a modular square root `n` is to be determined.
    :param prime_modulus: a prime modulus `p` for which the existence of a modular square root `n` is to be determined.
    :return: True if `a` has a modular square root modulo `prime_modulus`, False otherwise.
    """
    if a in {0, 1}:
        return True
    elif prime_modulus == 2:
        return True
    elif a % prime_modulus in {0, 1}:
        return True
    else:
        return legendre_symbol(a, prime_modulus) != -1


def mod_sqrt(a: int, prime_modulus: int) -> tuple[int, ...]:
    """
    Computes the modular square root of the integer `a` modulo the odd prime `prime_modulus`, using the Tonelli-Shanks
    algorithm. This function returns the positive square root of `a` modulo `prime_modulus`.
    :param a: the integer for which the modular square root is computed.
    :param prime_modulus: the odd prime modulus for the modular square root computation.
    :return: the positive square root of `a` modulo `prime_modulus`.
    """
    if is_quadratic_nonresidue(a, prime_modulus):
        raise ValueError(
            f"The integer {a} has no square root modulo {prime_modulus}, as it is a quadratic non-residue."
        )

    if a == 0 or a % prime_modulus == 0:
        return (0,)
    elif prime_modulus == 2:
        return (1,)
    elif a == 1 or a % prime_modulus == 1:
        return 1, prime_modulus - 1
    elif prime_modulus % 4 == 3:
        # Compute modular square root using the identity:
        #     `sqrt(a) mod p == +/- a^((p + 1) / 4) mod p`, where p == 3 mod 4 (for `==` here representing congruence).
        positive_root: int = pow(a, (prime_modulus + 1) // 4, prime_modulus)

        return positive_root, prime_modulus - positive_root
    else:  # prime_modulus % 4 == 1
        return tuple(
            sqrtmod_prime_power(a, prime_modulus, 1)  # note: this libnum function returns a Generator
        )
