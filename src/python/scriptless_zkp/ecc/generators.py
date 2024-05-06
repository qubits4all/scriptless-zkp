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
discrete logarithm. This is useful for generating effectively independent NUMS (Non-Uniform Message Sampling) generators
for use in certain cryptographic protocols, such as Pedersen commitments.
"""
from __future__ import annotations

from Cryptodome.PublicKey import ECC
from Cryptodome.Util import number

from scriptless_zkp.ecc import ecc_utils
from scriptless_zkp.ecc.weierstrass_curves import WeierstrassEllipticCurveConfig
from scriptless_zkp.hashing import UniversalPrimeLengthHasher
from scriptless_zkp.number_theory import is_quadratic_residue, mod_sqrt


class RandomGeneratorDerivationContext:
    curve_config: WeierstrassEllipticCurveConfig
    hash_algo: str
    domain_separator: str

    MAX_CANDIDATE_TWEAKS: int = 8  # Note: Must be a power of 2.
    DEFAULT_HASH_ALGO: str = "sha3_256"

    def __init__(
            self,
            curve_config: WeierstrassEllipticCurveConfig,
            hash_algorithm: str = DEFAULT_HASH_ALGO,
            domain_separation_tag: str | None = None
    ):
        self.curve_config = curve_config
        self.hash_algo = hash_algorithm
        self.domain_separator = domain_separation_tag

    def derive_generator_for_nonce(self, nonce: int, max_tweaks: int = MAX_CANDIDATE_TWEAKS) -> ECC.EccPoint:
        return self._derive_generator(max_tweaks, nonce)

    def derive_random_generator(self, max_tweaks: int = MAX_CANDIDATE_TWEAKS) -> ECC.EccPoint:
        return self._derive_generator(max_tweaks, randomize_nonce=True)

    def _derive_generator(
            self,
            max_tweaks: int,
            nonce: int | None = None,
            randomize_nonce: bool = False
    ) -> ECC.EccPoint:
        if nonce is None and not randomize_nonce:
            raise ValueError("A nonce must be provided unless nonce randomization is selected.")

        base_point_pub_key: ECC.EccKey = ECC.construct(
            curve=self.curve_config.curve,
            point_x=self.curve_config.base_point.x,
            point_y=self.curve_config.base_point.y
        )
        base_point_pub_key_SEC1: bytes = base_point_pub_key.export_key(format="SEC1")

        large_prime_p: int = number.getPrime(self.curve_config.curve_size_bytes * 8 + 1)

        point_hasher = UniversalPrimeLengthHasher(
            self.curve_config.modulus,  # elliptic curve's coefficients' prime modulus
            large_prime_p,  # large prime number for hashing
            hash_algorithm=self.hash_algo,
            domain_separation_tag=self.domain_separator
        )
        if self.domain_separator is not None:
            point_hasher.update(self.domain_separator.encode('utf-8'))

        point_hasher.update(base_point_pub_key_SEC1)
        if nonce is not None:
            # Calc. hash of `H_p(G || nonce)` to generate a candidate x-coordinate for the generator point.
            point_hasher.update(nonce.to_bytes(self.curve_config.curve_size_bytes, byteorder='big'))
        elif randomize_nonce:
            # Generate a random nonce in the range [1, q-1], where q is the curve's sub-group's order (i.e., `o(G)`).
            nonce: int = ecc_utils.generate_random_nonce(self.curve_config)
            point_hasher.update(nonce.to_bytes(self.curve_config.curve_size_bytes, byteorder='big'))

        x_coord_candidate: int = point_hasher.intdigest()

        nums_generator: ECC.EccPoint | None = self._hunt_and_peck_for_generator(x_coord_candidate, max_tweaks)
        if nums_generator is None:
            raise ValueError(f"Failed to generate a valid generator point H := H_p(G || nonce) for nonce: {nonce}")
        else:
            return nums_generator

    def _hunt_and_peck_for_generator(
            self,
            x_coordinate_candidate: int,
            max_tweaks: int = MAX_CANDIDATE_TWEAKS
    ) -> ECC.EccPoint | None:
        x_coord_least_sig_bits: int = x_coordinate_candidate & (max_tweaks - 1)  # e.g., least significant 3 bits

        x_coord: int = x_coordinate_candidate
        for i in range(-1, max_tweaks):
            if i >= 0 and i != x_coord_least_sig_bits:
                # Munge x-coordinate candidate by replacing the last 3 least-significant bits with the bits of i.
                mask: int = self._generate_x_coordinate_mask()
                x_coord: int = x_coordinate_candidate & mask | i

            y_squared: int = self._check_x_coordinate_is_on_curve(x_coord)
            if y_squared is not None:
                y_coord: int = mod_sqrt(y_squared, self.curve_config.modulus)
                generator = ECC.EccPoint(x_coord, y_coord, self.curve_config.curve)

                if not generator.is_point_at_infinity():
                    return generator
                else:
                    continue
        else:
            return None

    def _generate_x_coordinate_mask(self) -> int:
        """
        Generate a mask for keeping all but the last 3 bits (i in [0, 7]) of an x-coordinate candidate.
        """
        return ((1 << self.curve_config.size_bits) - 1) ^ 0x7

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
