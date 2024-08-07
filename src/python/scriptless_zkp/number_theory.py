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
from Cryptodome.Util import number

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
    # Special case for prime modulus 2:
    elif prime_modulus == 2:  # note: The Legendre symbol used below is not defined for p == 2.
        return True
    # Special case for `a == 0 mod p` or `a == 1 mod p`:
    elif a % prime_modulus in {0, 1}:
        return True
    else:
        # Otherwise, the integer `a` has a modular square root modulo `p` if and only if it's a quadratic residue.
        return legendre_symbol(a, prime_modulus) == 1


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
        # Compute modular square root using the following identity of Lagrange, for p == 3 mod 4:
        #     `sqrt(a) mod p == +/- a^((p + 1) / 4) mod p`
        positive_root: int = pow(a, (prime_modulus + 1) // 4, prime_modulus)

        return positive_root, prime_modulus - positive_root
    elif prime_modulus % 8 == 5:
        # If `a` is a quartic (biquadratic) residue modulo `p`, then the square roots can be computed using the
        # following identity of Legendre, for p == 5 mod 8:
        if is_quartic_residue(a, prime_modulus):  # i.e., there exists an integer `x` such that `x⁴ == a mod p`
            # Compute modular square root using the following identity, if `a` is a quartic residue modulo `p`:
            #     `sqrt(a) mod p == +/- a^((p + 3) / 8) mod p`
            positive_root: int = pow(a, (prime_modulus + 3) // 8, prime_modulus) % prime_modulus
        else:  # o.w. `a` is a quartic non-residue (i.e., there exists no integer `x` such that `x⁴ == a mod p`)
            # Compute modular square root using the following identity, if `a` is a quartic non-residue modulo `p`:
            #     `sqrt(a) mod p == +/- (2a) * (4a)^((p - 5) / 8) mod p`
            positive_root: int = (2 * a * pow(4 * a, (prime_modulus - 5) // 8, prime_modulus)) % prime_modulus

        return positive_root, prime_modulus - positive_root
    else:  # prime_modulus % 8 == 1
        return tuple(
            sqrtmod_prime_power(a, prime_modulus)  # note: this libnum function returns a Generator
        )


def quartic_residue_symbol(a: int, prime_modulus: int) -> int:
    """
    Computes the rational quartic (biquadratic) residue symbol of the integer `a` modulo the odd prime `prime_modulus`.
    This function returns +1 if `a` is a quartic residue modulo `prime_modulus`, and -1 if `a` is a quartic non-residue
    modulo `prime_modulus`. A quartic residue is an integer `a` such that `n⁴ == a mod p` has an integer solution `n`
    for prime modulus `p`.
    :param a: the integer for which the quartic residue symbol is computed.
    :param prime_modulus: the odd prime modulus for the quartic residue symbol computation.
    :return: the quartic residue symbol of `a` modulo `prime_modulus`.
    """
    if prime_modulus % 4 == 1 and is_quadratic_residue(a, prime_modulus):
        # For `p == 1 mod 4`, we can compute the quartic residue symbol using the following identity:
        #    `a^((p - 1) / 4) mod p`, where `^` denotes exponentiation.
        return pow(a, (prime_modulus - 1) // 4, prime_modulus)  # either +1 or -1
    else:
        return -1  # `a` is a quartic non-residue modulo `prime_modulus`


def is_quartic_residue(a: int, prime_modulus: int) -> bool:
    """
    Determines whether the given integer `a` is a quartic (biquadratic) residue modulo the odd prime `prime_modulus`
    (i.e., whether there exists an integer `n` such that `n⁴ == a mod p`).
    :param a: an integer to be tested for being a quartic residue.
    :param prime_modulus: an odd prime modulus for the quartic residue test.
    :return: whether `a` is a quartic residue modulo the odd prime `prime_modulus`.
    """
    return quartic_residue_symbol(a, prime_modulus) == 1


def is_quartic_nonresidue(a: int, prime_modulus: int) -> bool:
    """
    Determines whether the given integer `a` is a quartic (biquadratic) non-residue modulo the odd prime
    `prime_modulus` (i.e., whether there exists no integer `n` such that `n⁴ == a mod p`).
    :param a: an integer to be tested for being a quartic non-residue.
    :param prime_modulus: an odd prime modulus for the quartic non-residue test.
    :return: whether `a` is a quartic non-residue modulo the odd prime `prime_modulus`.
    """
    return quartic_residue_symbol(a, prime_modulus) == -1


def mod_inverse(a: int, modulus: int) -> int:
    """
    Computes the modular inverse of the integer `a` modulo `modulus`, if it exists; raising an exception otherwise.
    This function calculates the solution to the equation `a * x == 1 mod n`, where `==` represents congruence and `n`
    is the modulus, which may be prime or composite.
    :param a: an integer for which the modular inverse will be computed.
    :param modulus: a modulus for the modular inverse computation, which may be prime or composite.
    :return: the modular inverse of `a` modulo `modulus`.
    :raises ValueError: if the modular inverse of `a` modulo `modulus` does not exist, which can occur for composite
            moduli when `a` is not coprime to the modulus.
    """
    return number.inverse(a, modulus)
