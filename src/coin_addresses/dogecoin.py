# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Dogecoin addresses: Bitcoin's legacy ones, with Dogecoin's version bytes.

An address is the Base58Check of a version byte and a 20-byte hash: 30
for pay-to-public-key-hash, written with a leading D, and 22 for
pay-to-script-hash, written with a leading 9 or A. Dogecoin has no
segwit, so a key has the one address, P2PKH, and `coin_addresses._bitcoin`
says which encoding of the key it hashes.

The version bytes are `CMainParams`'s `base58Prefixes`, and validation
is `CBitcoinAddress::IsValid`'s, in Dogecoin Core, but for whitespace
around an address, which `coin_addresses._bitcoin` says is refused:

- https://github.com/dogecoin/dogecoin/blob/b38c83fbf10302b23ac6e7ad89bc83068efe2fd8/src/chainparams.cpp#L167-L168
- https://github.com/dogecoin/dogecoin/blob/b38c83fbf10302b23ac6e7ad89bc83068efe2fd8/src/base58.cpp#L252-L258

A refusal names what is wrong, never the address or the key it was
handed.
"""

from __future__ import annotations

from ecc.curves import PubKey

from coin_addresses._bitcoin import (
    assert_string,
    base58_address,
    decode_base58_address,
    pub_key_hash,
)
from coin_addresses.exceptions import CoinAddressesValueError

__all__ = [
    "address_from_pub_key",
    "assert_valid_address",
    "is_valid_address",
]

_P2PKH = 30
_P2SH = 22
# the hash size each version byte takes
_SIZES = {_P2PKH: (20,), _P2SH: (20,)}


def address_from_pub_key(pub_key: PubKey) -> str:
    """Return the P2PKH address of a secp256k1 public key.

    The key is read as `coin_addresses._bitcoin` says: a point, or its
    compressed SEC encoding, as bytes or as hex. A value of no type a key
    has is a `CoinAddressesTypeError`, and one that is no point of the
    curve, or is written uncompressed, a `CoinAddressesValueError`.
    """
    return base58_address(_P2PKH, pub_key_hash(pub_key))


def assert_valid_address(address: str) -> None:
    """Refuse a string that is not a Dogecoin address, P2PKH or P2SH.

    A non-string is a `CoinAddressesTypeError`. A string that is no
    Base58Check, or whose version byte or hash size is not Dogecoin's, is
    a `CoinAddressesValueError`.
    """
    assert_string(address)
    decode_base58_address(address, _SIZES)


def is_valid_address(address: str) -> bool:
    """Return whether a string is a Dogecoin address.

    It answers `False` where `assert_valid_address` refuses the value,
    and a non-string is still a `CoinAddressesTypeError`.
    """
    try:
        assert_valid_address(address)
    except CoinAddressesValueError:
        return False
    return True
