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

from Cryptodome.PublicKey import ECC

from scriptless_zkp.ecc.ecc_utils import encode_ecc_point
from scriptless_zkp.ecc.weierstrass_curves import WeierstrassEllipticCurveConfig


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

    def __repr__(self) -> str:
        return f"EccPoint2D(x={self.x}, y={self.y})"

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
    def is_point_at_infinity(self) -> bool:
        """
        Returns `True` if the point is the identity element (i.e., the "point-at-infinity") for the elliptic curve.
        """
        pass

    @abstractmethod
    def serialize(self) -> bytes:
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
    pt: ECC.EccPoint

    def __init__(self, curve_name: str, x: int, y: int):
        super().__init__(curve_name, x, y)

        self.curve_config = WeierstrassEllipticCurveConfig.for_curve_name(curve_name)
        self.pt = ECC.construct(curve=self.curve_config.curve, point_x=x, point_y=y).pointQ

    def __eq__(self, other: WeierstrassPoint2D) -> bool:
        return self.curve_config.has_curve_name(other.curve) and self.x == other.x and self.y == other.y

    def __add__(self, other: WeierstrassPoint2D) -> WeierstrassPoint2D:
        sum: ECC.EccPoint = self.pt.__add__(other.pt)
        return WeierstrassPoint2D(self.curve, sum.x, sum.y)

    def __neg__(self) -> WeierstrassPoint2D:
        if self.is_point_at_infinity():
            return self
        else:
            return WeierstrassPoint2D(self.curve, self.x, -self.y)

    def __mul__(self, scalar: int) -> WeierstrassPoint2D:
        scalar = scalar % self.curve_config.order
        scalar = scalar if scalar != 0 else self.curve_config.order
        product: ECC.EccPoint = self.pt.__mul__(scalar)

        return WeierstrassPoint2D(self.curve, product.x, product.y)

    @classmethod
    def base_point(cls, curve_name: str) -> EccPoint2D:
        ecc_pt: ECC.EccPoint = ECC.construct(curve=curve_name, d=1).pointQ

        return WeierstrassPoint2D(curve_name, ecc_pt.x, ecc_pt.y)

    @classmethod
    def identity(cls, curve_name: str) -> WeierstrassPoint2D:
        curve_config = WeierstrassEllipticCurveConfig.for_curve_name(curve_name)
        ecc_pt: ECC.EccPoint = curve_config.identity

        return WeierstrassPoint2D(curve_name, ecc_pt.x, ecc_pt.y)

    def is_point_at_infinity(self) -> bool:
        return self.pt.is_point_at_infinity()

    def serialize(self) -> bytes:
        return encode_ecc_point(self.curve_config, self.pt)

    @classmethod
    def deserialize(cls, serialized_point: bytes) -> WeierstrassPoint2D:
        ecc_key: ECC.EccKey = ECC.import_key(serialized_point)
        ecc_pt: ECC.EccPoint = ecc_key.pointQ

        return WeierstrassPoint2D(ecc_key.curve, ecc_pt.x, ecc_pt.y)
