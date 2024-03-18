"""Custom exception classes used by cryptography classes."""


class InvalidHasherStateException(Exception):
    def __init__(self, msg: str):
        super().__init__(msg)
        self.msg = msg

    def __repr__(self) -> str:
        return f"{type(self).__name__}: {self.msg}"
