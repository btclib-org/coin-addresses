# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What the bitcoin clones take from Bitcoin: the key hash and Base58Check.

A pay-to-public-key-hash address carries the HASH160 of the key's SEC
encoding, and its compressed and uncompressed encodings give different
addresses. The bitcoin clones' modules give the address of the
compressed one, which BIP32 wallets derive, and refuse a key written
uncompressed rather than answer an address its holder may not expect.
The cosmos module does the same: a Cosmos address carries that hash, in
bech32.

A legacy address is the Base58Check of a version byte and a hash. The
version byte says the coin and the script type; which ones a coin uses
is that coin's module's to say. Tron writes its address the same way,
with a hash of its own.

Whitespace around a legacy address is refused. The reference nodes'
`DecodeBase58` skips leading and trailing whitespace, so to Bitcoin Cash
Node `" 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"` is an address. Here it is
not: an address is checked as it is to be written. The skip, in each
node:

- https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/e13b48e37b3005dca9a316f75aea456697a5dfd6/src/base58.cpp#L40-80
- https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/src/base58.cpp#L40-L74
- https://github.com/dogecoin/dogecoin/blob/b38c83fbf10302b23ac6e7ad89bc83068efe2fd8/src/base58.cpp#L23-L56

A refusal names what is wrong, never the address or the key it was
handed. The refusals of `base58_bech32` do not quote them either, so
their messages are passed on.

The module is private: the coin modules publish what it serves.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from base58_bech32.base58 import b58decode_check, b58encode_check
from base58_bech32.exceptions import Base58Bech32ValueError
from ecc.curves import PubKey, bytes_from_point, point_from_pub_key, secp256k1
from ecc.exceptions import EccTypeError, EccValueError

from coin_addresses._hashes import hash160
from coin_addresses.exceptions import (
    CoinAddressesException,
    CoinAddressesTypeError,
    CoinAddressesValueError,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__: list[str] = []

# the first byte of an uncompressed SEC encoding
_UNCOMPRESSED = 0x04


def pub_key_hash(pub_key: PubKey) -> bytes:
    """Return the HASH160 of a public key's compressed SEC encoding.

    The key is any spelling `ecc.curves.point_from_pub_key` reads but an
    uncompressed SEC encoding: a point, or its compressed encoding, as
    bytes or as hex. A value of no type a key has is a
    `CoinAddressesTypeError`, and one that is no point of the curve, or
    is written uncompressed, a `CoinAddressesValueError`.
    """
    # the refusal is raised after the `try`, so that ecc's exception is
    # neither its cause nor its context
    kind: type[CoinAddressesException]
    try:
        point = point_from_pub_key(pub_key, secp256k1)
    except EccTypeError:
        kind = CoinAddressesTypeError
    except EccValueError:
        kind = CoinAddressesValueError
    else:
        # ecc has parsed it, so a string is hex and a buffer is octets
        if isinstance(pub_key, (str, bytes, bytearray, memoryview)):
            octets = bytes.fromhex(pub_key) if isinstance(pub_key, str) else pub_key
            if octets[0] == _UNCOMPRESSED:
                raise CoinAddressesValueError("uncompressed public key")
        return hash160(bytes_from_point(point, secp256k1))
    raise kind("not a public key")


def assert_string(address: object) -> None:
    """Refuse a non-string as a `CoinAddressesTypeError`.

    `object` and not `str`: a value of any type reaches it, and it is
    what refuses the ones that are no string.
    """
    if not isinstance(address, str):
        raise CoinAddressesTypeError(f"not a string: {type(address).__name__}")


def base58_address(version: int, digest: bytes) -> str:
    """Return the Base58Check address of a version byte and a hash."""
    return b58encode_check(bytes([version]) + digest).decode("ascii")


def decode_base58_address(
    address: str, sizes: Mapping[int, tuple[int, ...]]
) -> tuple[int, bytes]:
    """Return the version byte and the hash of a Base58Check address.

    `sizes` maps each version byte the coin uses to the hash sizes it
    takes. A string that is no Base58Check, a version byte not in
    `sizes`, and a hash of a size its version does not take are each a
    `CoinAddressesValueError`.
    """
    try:
        payload = b58decode_check(address)
    except Base58Bech32ValueError as e:
        reason = str(e)
    else:
        if not payload:
            raise CoinAddressesValueError("no version byte")
        version, digest = payload[0], payload[1:]
        if version not in sizes:
            raise CoinAddressesValueError(f"unknown version byte: {version}")
        if len(digest) not in sizes[version]:
            err_msg = f"{len(digest)}-byte hash for version byte {version}"
            raise CoinAddressesValueError(err_msg)
        return version, digest
    raise CoinAddressesValueError(reason)
