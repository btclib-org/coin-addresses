# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Ethereum addresses, which the EVM chains write the same way.

An address is the last 20 bytes of the Keccak-256 of a secp256k1 public
key's two coordinates, 32 bytes each and big-endian, with no SEC prefix.
It is written as `0x` and 40 hex digits, whose case is the EIP-55
checksum: a letter is upper case where the hex digit at its position in
the Keccak-256 of the lower-case digits is 8 or more.

An address written in one case, all lower or all upper, carries no
checksum. EIP-55 gives no rule for one, and its own test cases include
addresses whose checksum happens to be in one case, so validation here
checks the form of such an address and the checksum of every other.

A refusal names what is wrong, never the address or the key it was
handed.
"""

from __future__ import annotations

from ecc.curves import PubKey, point_from_pub_key, secp256k1
from ecc.exceptions import EccTypeError, EccValueError

from coin_addresses._keccak import keccak_256
from coin_addresses.exceptions import (
    CoinAddressesException,
    CoinAddressesTypeError,
    CoinAddressesValueError,
)

__all__ = [
    "address_from_pub_key",
    "assert_valid_address",
    "is_valid_address",
]

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _checksum_encode(address: bytes) -> str:
    """Return the EIP-55 spelling of a 20-byte address."""
    digits = address.hex()
    # the first 40 of the hash's 64 hex digits, one per digit of the address
    hashed = keccak_256(digits.encode("ascii")).hex()[: len(digits)]
    return "0x" + "".join(
        digit.upper() if nibble in "89abcdef" else digit
        for digit, nibble in zip(digits, hashed, strict=True)
    )


def address_from_pub_key(pub_key: PubKey) -> str:
    """Return the EIP-55 address of a secp256k1 public key.

    The key is any spelling `ecc.curves.point_from_pub_key` reads: a
    point, or its SEC encoding, compressed or not, as bytes or as hex. A
    value of no type a key has is a `CoinAddressesTypeError`, and one that
    is no point of the curve a `CoinAddressesValueError`.
    """
    # the refusal is raised after the `try`, so that ecc's exception is
    # neither its cause nor its context
    kind: type[CoinAddressesException]
    try:
        x, y = point_from_pub_key(pub_key, secp256k1)
    except EccTypeError:
        kind = CoinAddressesTypeError
    except EccValueError:
        kind = CoinAddressesValueError
    else:
        coordinates = x.to_bytes(32, "big") + y.to_bytes(32, "big")
        return _checksum_encode(keccak_256(coordinates)[-20:])
    raise kind("not a public key")


def assert_valid_address(address: str) -> None:
    """Refuse a string that is not an Ethereum address.

    A non-string is a `CoinAddressesTypeError`. A string that is not `0x`
    and 40 hex digits is a `CoinAddressesValueError`, and so is a
    mixed-case address whose case is not its EIP-55 checksum; one in a
    single case is checked for its form alone, as the module's docstring
    says.
    """
    if not isinstance(address, str):
        raise CoinAddressesTypeError(f"not a string: {type(address).__name__}")
    if not address.startswith("0x"):
        raise CoinAddressesValueError("no 0x prefix")
    digits = address[2:]
    if len(digits) != 40:
        raise CoinAddressesValueError(f"{len(digits)} characters after 0x, not 40")
    for position, digit in enumerate(digits, start=2):
        if digit not in _HEX_DIGITS:
            raise CoinAddressesValueError(f"not a hex digit at position {position}")
    if digits in {digits.lower(), digits.upper()}:
        return
    if _checksum_encode(bytes.fromhex(digits)) != address:
        raise CoinAddressesValueError("wrong EIP-55 checksum")


def is_valid_address(address: str) -> bool:
    """Return whether a string is an Ethereum address.

    It answers `False` where `assert_valid_address` refuses the value,
    and a non-string is still a `CoinAddressesTypeError`.
    """
    try:
        assert_valid_address(address)
    except CoinAddressesValueError:
        return False
    return True
