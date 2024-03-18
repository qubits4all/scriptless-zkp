"""Common constants and type aliases used in the 'scriptless_zkp' package."""

from typing import Literal

PartyId = Literal[1, 2]
"""Alias to the party ID literal type, which must be either 1 (initiator) or 2 (responder)."""

STRING_ENCODING_FIELD_DELIMITER: str = ':'
"""Default field delimiter used in string encodings."""
