###############################################################################
# (c) 2022, 2023, 2024 W. Spann Systems Consulting
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

"""Custom exception classes used by elliptic curve cryptography (ECC) classes."""

from typing import Optional


class InvalidECCPublicKeyException(Exception):
    def __init__(self, msg: str):
        super().__init__(msg)
        self.msg = msg

    def __repr__(self) -> str:
        return f"{type(self).__name__}: {self.msg}"


class InvalidECCPointException(Exception):
    def __init__(
            self,
            ecc_curve_name: str,
            point_x: int,
            point_y: int,
            msg: Optional[str] = None,
            append_default_message: bool = True
    ):
        message: str = "ECC point does not lie on the given elliptic curve"
        if msg is not None and append_default_message:
            message = f"{msg} -- {message}"
        elif msg is not None:
            message = msg

        # Append ECC point coordinates and curve name metadata to the exception's message.
        message = f"{message} [curve={ecc_curve_name}, point_x={point_x}, point_y={point_y}]"

        super().__init__(message)
        self.ecc_curve = ecc_curve_name
        self.point_x = point_x
        self.point_y = point_y
        self.msg = message

    def __repr__(self) -> str:
        return f"{type(self).__name__}: {self.msg}"

    def invalid_coordinates(self) -> tuple[int, int]:
        return self.point_x, self.point_y


class IncorrectECCCurveException(Exception):
    def __init__(self, expected_ecc_curve: str, provided_ecc_curve: str, message: Optional[str] = None):
        metadata: str = f"expected_curve='{expected_ecc_curve}', provided_curve='{provided_ecc_curve}'"
        if message is None:
            msg: str = f"Incorrect ECC curve [{metadata}]"
        else:
            msg: str = f"{message} [{metadata}]"

        super().__init__(msg)
        self.msg = msg


class IncorrectECCSchnorrSignatureCurveException(Exception):
    def __init__(self, signature_ecc_curve: str, pubkey_ecc_curve: str, message: Optional[str] = None):
        metadata: str = f"signature_curve='{signature_ecc_curve}', pubkey_curve='{pubkey_ecc_curve}'"
        if message is None:
            msg: str = f"Incorrect ECC curve for Schnorr signature [{metadata}]"
        else:
            msg: str = f"{message} [{metadata}]"

        super().__init__(msg)
        self.msg = msg

    def __repr__(self) -> str:
        return f"{type(self).__name__}: {self.msg}"


class InvalidECCPedersenCommitmentPointException(Exception):
    def __init__(self, ecc_curve_name: str, message: Optional[str] = None):
        msg: str = ("ECC Pedersen Commitment point is the point-at-infinity (identity point) on the configured elliptic"
                    " curve, which is not a valid commitment")

        if message is not None:
            msg = message

        msg = f"{msg} [curve='{ecc_curve_name}']"

        super().__init__(msg)
        self.ecc_curve = ecc_curve_name
        self.msg = msg
