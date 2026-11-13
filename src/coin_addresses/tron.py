# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tron addresses: an Ethereum address's 20 bytes, in Base58Check.

An address is the Base58Check of the byte 0x41 and the 20 bytes an
Ethereum address carries, which `coin_addresses.evm`'s docstring
defines, and `coin_addresses._ethereum` says how the key is read.
Base58Check writes 0x41 and 20 bytes as 34 characters, the first a T, so
a string of another length fails the decoding.

The prefix and the encoding are those of *TRON Address Generation* in
Tron's documentation. The derivation is java-tron's `computeAddress`,
the prefix its `ADD_PRE_FIX_BYTE_MAINNET`, and the validation its
`decodeFromBase58Check`:

- https://github.com/tronprotocol/documentation-en/blob/43931c1dfb7b824da32976ace8dad71f5bbb42d6/docs/mechanism-algorithm/account.md#tron-address-generation
- https://github.com/tronprotocol/java-tron/blob/b33eed89a6a424c498d4fb1b03ca2c86eddf4840/crypto/src/main/java/org/tron/common/crypto/Hash.java#L179-L199
- https://github.com/tronprotocol/java-tron/blob/b33eed89a6a424c498d4fb1b03ca2c86eddf4840/common/src/main/java/org/tron/core/Constant.java#L6
- https://github.com/tronprotocol/java-tron/blob/b33eed89a6a424c498d4fb1b03ca2c86eddf4840/chainbase/src/main/java/org/tron/common/utils/Commons.java#L49-L68

Tron's API also writes an address as hex, `41` and the 20 bytes. This
module reads and writes the Base58Check form alone.

A refusal names what is wrong, never the address or the key it was
handed.
"""

from __future__ import annotations

from base58_bech32.base58 import BITCOIN_ALPHABET
from ecc.curves import PubKey

from coin_addresses._bitcoin import (
    assert_string,
    base58_address,
    decode_base58_address,
)
from coin_addresses._ethereum import pub_key_hash
from coin_addresses.exceptions import CoinAddressesValueError

__all__ = [
    "address_from_pub_key",
    "assert_valid_address",
    "is_valid_address",
]

_PREFIX = 0x41
# the hash size the prefix takes
_SIZES = {_PREFIX: (20,)}


def address_from_pub_key(pub_key: PubKey) -> str:
    """Return the Tron address of a secp256k1 public key.

    The key is read, and refused, as
    `coin_addresses._ethereum.pub_key_hash` says.
    """
    return base58_address(_PREFIX, pub_key_hash(pub_key), alphabet=BITCOIN_ALPHABET)


def assert_valid_address(address: str) -> None:
    """Refuse a string that is not a Tron address.

    A non-string is a `CoinAddressesTypeError`. A string that is no
    Base58Check, or does not carry 0x41 and 20 bytes, is a
    `CoinAddressesValueError`.
    """
    assert_string(address)
    decode_base58_address(address, _SIZES, alphabet=BITCOIN_ALPHABET)


def is_valid_address(address: str) -> bool:
    """Return whether a string is a Tron address.

    It answers `False` where `assert_valid_address` refuses the value,
    and a non-string is still a `CoinAddressesTypeError`.
    """
    try:
        assert_valid_address(address)
    except CoinAddressesValueError:
        return False
    return True
