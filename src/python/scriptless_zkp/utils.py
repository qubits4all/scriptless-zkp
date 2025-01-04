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


def safe_divide(dividend: int, divisor: int) -> int:
    """
    Divides the dividend by the divisor only if divisible, returning the result as an integer; otherwise raising an
    exception.
    :param dividend: The dividend to be divided, expected to be an integer.
    :param divisor: The divisor by which to divide the dividend, expected to be a non-zero integer.
    :return: The result of the division (i.e., the quotient), as an integer.
    :raises AssertionError: If the divisor is zero or the dividend is not divisible by the divisor.
    """
    assert isinstance(dividend, int) and isinstance(divisor, int), "The dividend and divisor must be integers."
    assert divisor != 0, "Cannot divide by zero."
    assert dividend % divisor == 0, f"{dividend} is not divisible by {divisor}."

    return dividend // divisor
