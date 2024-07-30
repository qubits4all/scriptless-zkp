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
This module supports the derivation of random elliptic curve generator points, for which nobody knows the associated
discrete logarithm. This is useful for generating effectively independent NUMS (Nothing Up My Sleeve) generators
for use in certain cryptographic protocols, such as Pedersen commitments.
"""
from __future__ import annotations

import math

from Cryptodome.PublicKey import ECC
from Cryptodome.Random import random
from Cryptodome.Util import number

from scriptless_zkp.ecc.ecc_utils import encode_ecc_point
from scriptless_zkp.ecc.weierstrass_curves import WeierstrassEllipticCurveConfig
from scriptless_zkp.hashing import UniversalPrimeLengthHasher
from scriptless_zkp.number_theory import is_quadratic_residue, mod_sqrt


class ECCGeneratorDerivationContext:
    curve_config: WeierstrassEllipticCurveConfig
    domain_separator: str

    MIN_CANDIDATE_MAX_TWEAKS: int = 2
    DEFAULT_CANDIDATE_MAX_TWEAKS: int = 8  # Note: Must be a power of 2.

    def __init__(
            self,
            curve_config: WeierstrassEllipticCurveConfig,
            domain_separation_tag: str | None = None
    ):
        self.curve_config = curve_config
        self.domain_separator = domain_separation_tag

    def derive_generator_for_nonce(self, nonce: int, max_tweaks: int = DEFAULT_CANDIDATE_MAX_TWEAKS) -> ECC.EccPoint:
        """
        Derives an effectively-independent elliptic curve generator point for the provided nonce, using the configured
        elliptic curve, cryptographic hash algorithm and domain separation tag. This generator point is derived from a
        cryptographic hash of the curve's public base point (`G`) and the provided nonce as follows:
            `x_0 := H_p(H(G || nonce))`,
        where `H_p` is a universal hash function that maps a cryptographic hash `H` (e.g., SHA3-256) to a candidate
        x-coordinate in `Z/Zp` (i.e., an integer in the range [0, p-1]). This hash is calculated from the configured
        elliptic curve's base point `G` (serialized using uncompressed SEC1 point encoding) concatenated with the given
        nonce. Whether this generated candidate x-coordinate produces a valid point on the curve is checked, and if not
        a hunt-and-peck algorithm is used to iterate over a range tweaks to its least-significant-bits
        (up to `max_tweaks`) until a valid point is found; raising `ValueError` if one could not be found.
        <p>
        Note: This algorithm does not run in constant time, due to its use of a probabilistic hunt-and-peck algorithm
        (bounded by the `max_tweaks` parameter) for finding a valid point on the elliptic curve. As such, it should not
        be used for constructing generator points based on a private key or other secret or sensitive information
        (e.g., passed via the `nonce` parameter), since such improper use may risk leakage of any secret information
        used this way (e.g., via potential timing side-channel attacks).</p>
        <p>
        However, use-cases like generating NUMS (Nothing Up My Sleeve) generator points for certain cryptographic
        protocols that use only public information and/or pre-agreed nonces as input(s) to this process
        (e.g., Pedersen commitments' NUMS generator used for calculating the blinding factor) are safe.</p>
        :param nonce: an integer nonce to use when deriving the generator point.
        :param max_tweaks: the maximum number of tweaks to use when deriving the generator point, which determines the
               number of x-coordinate tweaks (to least significant bits) to try when hunting for a valid point on the
               elliptic curve.
        :return: an elliptic curve generator point derived from a cryptographic hash of the configured curve's public
                 base point (`G`) and the provided nonce, for which nobody knows the discrete logarithm with respect
                 to `G`.
        :raises ValueError: if the generator point cannot be derived for the provided nonce, using the specified
                maximum number of tweaks.
        """
        return self._derive_generator(max_tweaks, nonce)

    def derive_random_generator(self, max_tweaks: int = DEFAULT_CANDIDATE_MAX_TWEAKS) -> ECC.EccPoint:
        """
        Derives an effectively-independent random elliptic curve generator point using a randomly generated nonce, using
        the configured elliptic curve, cryptographic hash algorithm and domain separation tag. This generator point is
        derived from a cryptographic hash of the curve's public base point (`G`) and this randomly generated nonce as
        follows:
            `x_0 := H_p(H(G || nonce))`,
        where `H_p` is a universal hash function that maps a cryptographic hash `H` (e.g., SHA3-256) to a candidate
        x-coordinate in `Z/Zp` (i.e., an integer in the range [0, p-1]). This hash is calculated from the configured
        elliptic curve's base point `G` (serialized using uncompressed SEC1 point encoding) concatenated with the
        randomly generated nonce. Whether this generated candidate x-coordinate produces a valid point on the curve is
        checked, and if not a hunt-and-peck algorithm is used to iterate over a range tweaks to its least-significant-
        bits (up to `max_tweaks`) until a valid point is found; raising `ValueError` if one could not be found.
        <p>
        Note: This algorithm does not run in constant time, due to its use of a probabilistic hunt-and-peck algorithm
        (bounded by the `max_tweaks` parameter) for finding a valid point on the elliptic curve. As such, it should not
        be used for constructing generator points based on a private key or other secret or sensitive information
        (e.g., improperly passed via this class's `domain_separation_tag` constructor parameter, which should be
        considered a public tag), since such improper use may risk leakage of any secret information used this way
        (e.g., via potential timing side-channel attacks).</p>
        <p>
        However, use-cases like generating NUMS (Nothing Up My Sleeve) generator points for certain cryptographic
        protocols that use only public information as input to this process (e.g., Pedersen commitments' NUMS generator
        used for calculating the blinding factor) are safe.
        </p>
        :param max_tweaks: the maximum number of tweaks to use when deriving the generator point, which determines the
               number of x-coordinate tweaks (to least significant bits) to try when hunting for a valid point on the
               elliptic curve.
        :return: an elliptic curve generator point derived from a cryptographic hash of the configured curve's public
                 base point (`G`) and a randomly generated nonce, for which nobody knows the discrete logarithm with
                 respect to `G`.
        :raises ValueError: if the generator point cannot be derived for the randomly generated nonce, using the
                specified maximum number of tweaks.
        """
        return self._derive_generator(max_tweaks, randomize_nonce=True)

    def _derive_generator(
            self,
            max_tweaks: int,
            nonce: int | None = None,
            randomize_nonce: bool = False
    ) -> ECC.EccPoint:
        if nonce is None and not randomize_nonce:
            raise ValueError("A nonce must be provided unless nonce randomization is selected.")
        elif max_tweaks < ECCGeneratorDerivationContext.MIN_CANDIDATE_MAX_TWEAKS or math.log2(max_tweaks) % 1 != 0:
            raise ValueError("The maximum number of tweaks must be a power of 2 that is greater or equal to 2.")

        base_point_pub_key_SEC1: bytes = encode_ecc_point(self.curve_config, self.curve_config.base_point)

        point_hasher = UniversalPrimeLengthHasher.for_field_order(
            self.curve_config.modulus,  # elliptic curve's coefficients' prime modulus
            domain_separation_tag=self.domain_separator,
            deterministic=True  # Ensure deterministic hash output for reproducibility.
        )

        point_hasher.update(base_point_pub_key_SEC1)
        if nonce is not None:
            # Calc. hash of `H_p(G || nonce)` to generate a candidate x-coordinate for the generator point.
            point_hasher.update(number.long_to_bytes(nonce))
        elif randomize_nonce:
            # Generate a random nonce in the range [0, p-1], where p is the curve's prime modulus (i.e., of the base
            # field `F_p` over which the elliptic curve is defined).
            nonce: int = random.randint(0, self.curve_config.modulus - 1)
            point_hasher.update(number.long_to_bytes(nonce))

        x_coord_candidate: int = point_hasher.intdigest()

        nums_generator: ECC.EccPoint | None = self._hunt_and_peck_for_generator(x_coord_candidate, max_tweaks)
        if nums_generator is None:
            if randomize_nonce:
                suggestion_msg: str = "Try increasing `max_tweaks`."
            else:
                suggestion_msg: str = "Try increasing `max_tweaks` or using a different nonce."

            raise ValueError(
                f"Failed to generate a valid generator point for nonce: {nonce} -- {suggestion_msg}"
            )
        else:
            return nums_generator

    def _hunt_and_peck_for_generator(
            self,
            x_coordinate_candidate: int,
            max_tweaks: int = DEFAULT_CANDIDATE_MAX_TWEAKS
    ) -> ECC.EccPoint | None:
        x_coord_least_sig_bits: int = x_coordinate_candidate & (max_tweaks - 1)  # e.g., least significant n bits

        x_coord: int = x_coordinate_candidate
        for i in range(-1, max_tweaks):
            if i >= 0 and i != x_coord_least_sig_bits:
                # Munge x-coordinate candidate by replacing the last n least-significant bits with the bits of i.
                mask: int = self._generate_x_coordinate_mask(max_tweaks)
                x_coord: int = x_coordinate_candidate & mask | i

            y_squared: int = self._check_x_coordinate_is_on_curve(x_coord)
            if y_squared is not None:
                y_coord: int = mod_sqrt(y_squared, self.curve_config.modulus)[0]  # positive square root
                generator = ECC.EccPoint(x_coord, y_coord, self.curve_config.curve)

                if not generator.is_point_at_infinity():
                    return generator
                else:
                    continue
        else:
            return None

    def _generate_x_coordinate_mask(self, max_tweaks: int) -> int:
        """
        Generate a mask for keeping all but the last n bits of an x-coordinate candidate (e.g., 3 bits for
        max_tweaks=8).
        """
        return ((1 << self.curve_config.size_bits) - 1) ^ (max_tweaks - 1)

    def _check_x_coordinate_is_on_curve(self, x_coordinate: int) -> int | None:
        """
        Check if the provided x-coordinate candidate corresponds to a valid point on the elliptic curve.
        :return: whether the given x-coordinate candidate corresponds to at least one valid point on the elliptic curve.
        """
        x_cubed: int = pow(x_coordinate, 3, self.curve_config.modulus)
        y_squared_candidate: int = (
            x_cubed + self.curve_config.coeff_a * x_coordinate + self.curve_config.coeff_b
        ) % self.curve_config.modulus

        # Check if the y² candidate n is a quadratic residue modulo the elliptic curve's prime modulus
        # (i.e., whether there exists a y in Z_p such that `y² = n mod p`), since not all integers have a square root
        # modulo a prime modulus.
        if is_quadratic_residue(y_squared_candidate, self.curve_config.modulus):
            return y_squared_candidate
        else:
            return None
