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

"""Provides various helper functions, including several for random number and random prime generation."""

import secrets

from Cryptodome.Util import number


def random_integer_in_range(lower_inclusive: int, upper_exclusive: int) -> int:
    """
    Generates a random integer in the range [lower_inclusive, upper_exclusive), using Python's `secrets` module.
    :param lower_inclusive: The lower bound (inclusive) of the random integer to generate.
    :param upper_exclusive: The upper bound (exclusive) of the random integer to generate.
    :return: A random integer in the range: [lower_inclusive, upper_exclusive)
    """
    if lower_inclusive >= upper_exclusive:
        raise ValueError("The lower bound must be less than the upper bound.")
    elif upper_exclusive - lower_inclusive < 2:
        raise ValueError("The range must have at least two distinct values.")

    return secrets.randbelow(upper_exclusive - lower_inclusive) + lower_inclusive


def random_positive_integer(upper_limit_exclusive: int) -> int:
    """
    Generates a random positive integer in the range [1, upper_limit_exclusive), using Python's `secrets` module.
    :param upper_limit_exclusive: The upper limit (exclusive) of the random integer to generate.
    :return: A random positive integer in the range: [1, upper_limit_exclusive)
    """
    return random_integer_in_range(1, upper_limit_exclusive)


def random_nonnegative_integer(upper_limit_exclusive: int) -> int:
    """
    Generates a random non-negative integer in the range [0, upper_limit_exclusive), using Python's `secrets` module.
    :param upper_limit_exclusive: The upper limit (exclusive) of the random integer to generate.
    :return: A random non-negative integer in the range: [0, upper_limit_exclusive)
    """
    return secrets.randbelow(upper_limit_exclusive)


def random_prime_of_size(size_bits: int) -> int:
    """
    Generates a random prime number of the specified size in bits, specifically a prime lying in the range:
        `[2^(size_bits-1) + 1, 2^size_bits - 1]`

    :param size_bits: The number of bits to use in the prime number to be generated.
    :return: A random prime number of the specified bit size.
    """
    return number.getPrime(size_bits)


def random_strong_prime(size_bits: int) -> int:
    """
    Generates a random "strong" prime number of the specified size in bits, specifically a prime `p` such that `p - 1`
    `p + 1` both have at least one large prime factor.

    :param size_bits: The number of bits to use in the prime number to be generated.
    :return: A random "strong" prime number of the specified bit size.
    """
    return number.getStrongPrime(size_bits)


# TODO: Implement a more efficient version of this function that generates a random "safe" prime number.
#   Applying the Pocklington criterion (http://en.wikipedia.org/wiki/Pocklington_primality_test#Pocklington_criterion)
#   to the test for whether `p` is prime (i.e., where `p = 2*q + 1`) should provide a significant speed-up.
#   (In this special case, we only need a single Fermat base-2 pseudo-prime test for `p`.)
#   See: https://math.stackexchange.com/questions/870626/fast-check-of-safe-primes-or-sophie-germain-primes
def random_safe_prime(size_bits: int) -> int:
    """
    Generates a random "safe" prime number of the specified size in bits, specifically a prime `p` such that
    `p = 2*q + 1`, where `q` is also prime (i.e., where `q = (p - 1) / 2` is prime).
    :param size_bits: The number of bits to use in the prime number to be generated.
    :return: A random "safe" prime number of the specified bit size.
    """
    while True:
        q: int = number.getPrime(size_bits - 1)
        p: int = 2 * q + 1

        assert p.bit_length() == size_bits, \
            f"Generated prime has {p.bit_length()} bits, not the expected {size_bits} bits."

        if number.isPrime(p):
            return p
