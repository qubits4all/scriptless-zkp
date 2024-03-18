"""Custom exception classes used by elliptic curve cryptography (ECC) classes."""

from typing import Optional

from scriptless_zkp.ecc.ecc_utils import WeierstrassEllipticCurveConfig


class InvalidECCPublicKeyException(Exception):
    def __init__(self, msg: str):
        super().__init__(msg)
        self.msg = msg

    def __repr__(self) -> str:
        return f"{type(self).__name__}: {self.msg}"


class InvalidECCPointException(Exception):
    def __init__(
            self,
            ecc_curve_config: WeierstrassEllipticCurveConfig,
            point_x: int,
            point_y: int,
            msg: Optional[str] = None
    ):
        message: str = "ECC point does not lie on the given elliptic curve"
        if msg is not None:
            message = f"{msg} -- {message}"

        message = f"{message} [curve={ecc_curve_config.curve}, point_x={point_x}, point_y={point_y}]"

        super().__init__(message)
        self.ecc_curve_config = ecc_curve_config
        self.point_x = point_x
        self.point_y = point_y
        self.msg = message

    def __repr__(self) -> str:
        return f"{type(self).__name__}: {self.msg}"

    def invalid_coordinates(self) -> (int, int):
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
