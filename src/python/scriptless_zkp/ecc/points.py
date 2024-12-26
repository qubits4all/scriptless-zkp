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
Abstract base classes for working with elliptic curve points and associated operations in elliptic curve cryptography
(ECC), including point addition, point scalar multiplication, point negation, point equality checking, and point
serialization/deserialization.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import cast, override

from Cryptodome.PublicKey import ECC

from py_ecc.secp256k1 import secp256k1

from scriptless_zkp.ecc.ecc_utils import encode_ecc_point
from scriptless_zkp.ecc.weierstrass_curves import WeierstrassEllipticCurveConfig
from scriptless_zkp.number_theory import is_quadratic_residue, mod_sqrt


class EccPoint2D(ABC):
    curve: str
    x: int
    y: int

    @abstractmethod
    def __init__(self, curve_name: str, x: int, y: int):
        self.curve = curve_name
        self.x = x
        self.y = y

    # noinspection PyPep8Naming
    @property
    def G(self) -> EccPoint2D:
        return self.base_point(self.curve)

    def __str__(self) -> str:
        return f"({self.x}, {self.y})"

    @abstractmethod
    def __repr__(self) -> str:
        pass

    @abstractmethod
    def __eq__(self, other: EccPoint2D) -> bool:
        pass

    @abstractmethod
    def __add__(self, other: EccPoint2D) -> EccPoint2D:
        pass

    @abstractmethod
    def __neg__(self) -> EccPoint2D:
        pass

    @abstractmethod
    def __mul__(self, scalar: int) -> EccPoint2D:
        pass

    def __rmul__(self, scalar: int) -> EccPoint2D:
        return self.__mul__(scalar)

    def __hex__(self):
        return self.to_hex()

    def to_hex(self):
        return f"({hex(self.x)}, {hex(self.y)})"

    @classmethod
    @abstractmethod
    def base_point(cls, curve_name: str) -> EccPoint2D:
        """Returns the base point (i.e., the public generator) for the elliptic curve."""
        pass

    @classmethod
    @abstractmethod
    def identity(cls, curve_name: str) -> EccPoint2D:
        """Returns the identity element (i.e., the "point-at-infinity") for the elliptic curve."""
        pass

    @abstractmethod
    def curve_order(self) -> int:
        pass

    @abstractmethod
    def curve_modulus(self) -> int:
        pass

    @abstractmethod
    def is_point_at_infinity(self) -> bool:
        """
        Returns `True` if the point is the identity element (i.e., the "point-at-infinity") for the elliptic curve.
        """
        pass

    @abstractmethod
    def serialize(self, compress: bool = False) -> bytes:
        pass

    @classmethod
    @abstractmethod
    def deserialize(cls, serialized_point: bytes) -> EccPoint2D:
        pass


class WeierstrassPoint2D(EccPoint2D):
    """
    Represents a (2D) point on an elliptic curve in Weierstrass form, including operations for point addition, point
    negation, point scalar multiplication, point equality checking, and point serialization/deserialization.
    """
    curve_config: WeierstrassEllipticCurveConfig
    _pt: ECC.EccPoint

    @override
    def __init__(self, curve_name: str, x: int, y: int):
        super().__init__(curve_name, x, y)

        self.curve_config = WeierstrassEllipticCurveConfig.for_curve_name(curve_name)
        self._pt = ECC.construct(curve=self.curve_config.curve, point_x=x, point_y=y).pointQ

    @override
    def __repr__(self) -> str:
        return f"WeierstrassPoint2D(curve='{self.curve}', x={self.x}, y={self.y})"

    @override
    def __eq__(self, other: WeierstrassPoint2D) -> bool:
        return self.curve_config.has_curve_name(other.curve) and self.x == other.x and self.y == other.y

    @override
    def __add__(self, other: WeierstrassPoint2D) -> WeierstrassPoint2D:
        sum: ECC.EccPoint = self._pt.__add__(other._pt)
        return WeierstrassPoint2D(self.curve, sum.x, sum.y)

    @override
    def __neg__(self) -> WeierstrassPoint2D:
        if self.is_point_at_infinity():
            return self
        else:
            return WeierstrassPoint2D(self.curve, self.x, -self.y)

    @override
    def __mul__(self, scalar: int) -> WeierstrassPoint2D:
        if self.is_point_at_infinity():
            return self
        if scalar == 0:
            return WeierstrassPoint2D.identity(self.curve)
        if scalar < 0 or scalar >= self.curve_order():
            return self.__mul__(scalar % self.curve_order())
        if scalar == 1:
            return self

        product: ECC.EccPoint = self._pt.__mul__(scalar)

        return WeierstrassPoint2D(self.curve, product.x, product.y)

    @classmethod
    @override
    def base_point(cls, curve_name: str) -> WeierstrassPoint2D:
        ecc_pt: ECC.EccPoint = ECC.construct(curve=curve_name, d=1).pointQ

        return WeierstrassPoint2D(curve_name, ecc_pt.x, ecc_pt.y)

    @classmethod
    @override
    def identity(cls, curve_name: str) -> WeierstrassPoint2D:
        curve_config = WeierstrassEllipticCurveConfig.for_curve_name(curve_name)
        ecc_pt: ECC.EccPoint = curve_config.identity

        return WeierstrassPoint2D(curve_name, ecc_pt.x, ecc_pt.y)

    @override
    def curve_order(self) -> int:
        return self.curve_config.order

    @override
    def curve_modulus(self) -> int:
        return self.curve_config.modulus

    @override
    def is_point_at_infinity(self) -> bool:
        return self._pt.is_point_at_infinity()

    @override
    def serialize(self, compress: bool = False) -> bytes:
        return encode_ecc_point(self.curve_config, self._pt, compress=compress)

    @classmethod
    @override
    def deserialize(cls, serialized_point: bytes) -> WeierstrassPoint2D:
        ecc_key: ECC.EccKey = ECC.import_key(serialized_point)
        ecc_pt: ECC.EccPoint = ecc_key.pointQ

        return WeierstrassPoint2D(ecc_key.curve, ecc_pt.x, ecc_pt.y)


# TODO: Add elliptic curve config. class for secp256k1 curve, including support for checking if a point is on the curve.
class Secp256K1Point2D(EccPoint2D):
    """
    Represents a (2D) point on the secp256k1 elliptic curve, including operations for point addition, point negation,
    point scalar multiplication, point equality checking, and point serialization/deserialization.
    """
    PlainPoint2D = tuple[int, int]

    @override
    def __init__(self, x: int, y: int):
        super().__init__(Secp256K1Point2D._curve_names()[0], x, y)

    @property
    def _pt(self) -> PlainPoint2D:
        return cast("PlainPoint2D", (self.x, self.y))

    @override
    def __repr__(self) -> str:
        return f"Secp256K1Point2D(curve='{self.curve}', x={self.x}, y={self.y})"

    @override
    def __eq__(self, other: Secp256K1Point2D) -> bool:
        return self.curve == other.curve and self.x == other.x and self.y == other.y

    # TODO: Verify correct handling of a sum that results in the point-at-infinity (identity) element.
    @override
    def __add__(self, other: Secp256K1Point2D) -> Secp256K1Point2D:
        sum_pt = secp256k1.add(self._pt, other._pt)

        return Secp256K1Point2D(sum_pt[0], sum_pt[1])

    @override
    def __neg__(self) -> Secp256K1Point2D:
        if self.is_point_at_infinity():
            return self
        else:
            return Secp256K1Point2D(self.x, -self.y)

    @override
    def __mul__(self, scalar: int) -> Secp256K1Point2D:
        if self.is_point_at_infinity():
            return self
        if scalar == 0:
            return Secp256K1Point2D.identity(self.curve)
        if scalar < 0 or scalar >= self.curve_order():
            return self.__mul__(scalar % self.curve_order())
        if scalar == 1:
            return self

        product_pt = secp256k1.multiply(self._pt, scalar)

        return Secp256K1Point2D(product_pt[0], product_pt[1])

    @classmethod
    @override
    def base_point(cls, curve_name: str) -> Secp256K1Point2D:
        return Secp256K1Point2D(secp256k1.G[0], secp256k1.G[1])

    @classmethod
    @override
    def identity(cls, curve_name: str) -> Secp256K1Point2D:
        if curve_name in Secp256K1Point2D._curve_names():
            # Using a special (marker) point in Cartesian coordinates (not otherwise on the curve) to encode the
            # "point-at-infinity" (identity) element for the secp256k1 elliptic curve.
            return Secp256K1Point2D(0, 0)
        else:
            raise ValueError(f"Unsupported curve name: {curve_name}")

    @override
    def curve_order(self) -> int:
        return secp256k1.N

    @override
    def curve_modulus(self) -> int:
        return secp256k1.P

    @override
    def is_point_at_infinity(self) -> bool:
        # Check for special (marker) point in Cartesian coordinates.
        return self.x == 0 and self.y == 0

    @override
    def serialize(self, compress: bool = False) -> bytes:
        return Secp256K1Point2D._encode_point_SEC1(self._pt, compress=compress)

    @classmethod
    @override
    def deserialize(cls, serialized_point: bytes) -> Secp256K1Point2D:
        return Secp256K1Point2D(
            *Secp256K1Point2D._decode_point_SEC1(serialized_point)
        )

    # noinspection PyPep8Naming
    @staticmethod
    def _encode_point_SEC1(ecc_point: PlainPoint2D, compress: bool = False) -> bytes:
        # If the identity element (i.e., the point-at-infinity), return only the single-byte Code: 0x00.
        if ecc_point[0] == 0 and ecc_point[1] == 0:
            return b"\x00"

        if compress:
            code: bytes = b"\x02" if ecc_point[1] & 1 == 0 else b"\x03"  # Code: 0x02 for even y, 0x03 for odd y
            return code + ecc_point[0].to_bytes(32, "big")  # encode only x-coordinate in big-endian
        else:
            code: bytes = b"\x04"  # Code: 0x04 for uncompressed point (i.e., both x & y coordinates are included)
            return (code + ecc_point[0].to_bytes(32, "big")  # encode x & y coords. in big-endian
                    + ecc_point[1].to_bytes(32, "big"))

    # noinspection PyPep8Naming
    @staticmethod
    def _decode_point_SEC1(serialized_point: bytes) -> PlainPoint2D:
        if len(serialized_point) == 1 and serialized_point[0] == 0x00:
            # Return the identity element (i.e., the point-at-infinity) for the secp256k1 elliptic curve.
            return 0, 0  # special (marker) point in Cartesian coordinates for the "point-at-infinity"

        code: int = serialized_point[0]
        if code == 0x02 or code == 0x03:
            if len(serialized_point) != 33:
                raise ValueError("Invalid SEC1 encoding: compressed point must be 33 bytes long.")

            x: int = int.from_bytes(serialized_point[1:], "big")
            y_sq: int = (pow(x, 3, secp256k1.P) + 7) % secp256k1.P   # SECP256k1 curve eq.: y^2 = x^3 + 7 (mod P)

            # Check if the calculated square of the encoded point's (supposed) y-coord. has a square root modulo P.
            if is_quadratic_residue(y_sq, secp256k1.P):
                y: int = mod_sqrt(y_sq, secp256k1.P)[0]  # positive square root of y^2 (mod P)
                if (y % 2) != code & 1:
                    y = secp256k1.P - y  # adjust y-coordinate to match the parity encoded in the SEC1 code

                return x, y
            else:
                raise ValueError(
                    f"Invalid SEC1 encoded compressed elliptic curve point -- no corresponding y-coordinate exists"
                    f" on the curve: {Secp256K1Point2D._curve_names()[0]} [x_coord={x}]"
                )
        elif code == 0x04:
            if len(serialized_point) != 65:
                raise ValueError("Invalid SEC1 encoding: uncompressed point must be 65 bytes long.")

            x: int = int.from_bytes(serialized_point[1:33], "big")
            y: int = int.from_bytes(serialized_point[33:], "big")

            return x, y
        else:
            raise ValueError(f"Invalid SEC1 encoding code: {code}")

    @staticmethod
    def _curve_names() -> list[str]:
        return ["secp256k1", "p256k1", "prime256k1", "ansip256k1"]
