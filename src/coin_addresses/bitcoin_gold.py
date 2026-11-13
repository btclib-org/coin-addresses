# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Bitcoin Gold addresses: Bitcoin's, with its own version bytes and HRP.

A legacy address is the Base58Check of a version byte and a 20-byte
hash: 38 for pay-to-public-key-hash, written with a leading G, and 23
for pay-to-script-hash, written with a leading A. A segwit address is
BIP173's bech32, or BIP350's bech32m from witness version 1, with the
HRP `btg`.

`address_from_pub_key`'s `script_type` names the address a key gives,
as `coin_addresses._bitcoin.script_type_address` says, and
`coin_addresses._bitcoin` says which encoding of the key is hashed.

The version bytes and the HRP are `CMainParams`'s, the encodings are
`DestinationEncoder`'s, and validation is `DecodeDestination`'s, in BTG
Core, but for whitespace around a legacy address, which
`coin_addresses._bitcoin` says is refused. Its `bech32::Decode` reads at
most 90 characters:

- https://github.com/BTCGPU/BTCGPU/blob/1b85f0953725812dedcfc5a7ac077c16d419e4ba/src/chainparams.cpp#L181-L187
- https://github.com/BTCGPU/BTCGPU/blob/1b85f0953725812dedcfc5a7ac077c16d419e4ba/src/key_io.cpp#L20-L135
- https://github.com/BTCGPU/BTCGPU/blob/1b85f0953725812dedcfc5a7ac077c16d419e4ba/src/bech32.cpp#L178

A segwit address of witness version 1, such as a P2TR one, is valid as
`DecodeDestination` reads it, and no key here gives one: BTG Core's
wallet derives none, its `OutputType` being legacy, P2SH-segwit and
bech32:

- https://github.com/BTCGPU/BTCGPU/blob/1b85f0953725812dedcfc5a7ac077c16d419e4ba/src/outputtype.h#L17-L21

A refusal names what is wrong, never the address or the key it was
handed.
"""

from __future__ import annotations

from base58_bech32.base58 import BITCOIN_ALPHABET
from base58_bech32.exceptions import Base58Bech32ValueError
from ecc.curves import PubKey

from coin_addresses._bitcoin import (
    assert_string,
    assert_valid_segwit_address,
    decode_base58_address,
    script_type_address,
)
from coin_addresses.exceptions import CoinAddressesValueError

__all__ = [
    "address_from_pub_key",
    "assert_valid_address",
    "is_valid_address",
]

_P2PKH = 38
_P2SH = 23
# the hash size each version byte takes
_SIZES = {_P2PKH: (20,), _P2SH: (20,)}

_HRP = "btg"
# the length limit of BTG Core's `bech32::Decode`
_LIMIT = 90


def address_from_pub_key(pub_key: PubKey, *, script_type: str = "p2pkh") -> str:
    """Return the address of a secp256k1 public key, for one script type.

    `script_type` names the script type, and it and the key are read,
    and refused, as `coin_addresses._bitcoin.script_type_address` says.
    """
    return script_type_address(
        pub_key, script_type, p2pkh=_P2PKH, p2sh=_P2SH, hrp=_HRP, limit=_LIMIT
    )


def assert_valid_address(address: str) -> None:
    """Refuse a string that is not a Bitcoin Gold address.

    A non-string is a `CoinAddressesTypeError`. A string BTG Core reads
    as neither a legacy address nor a segwit address is a
    `CoinAddressesValueError`, which gives both reasons.
    """
    assert_string(address)
    try:
        decode_base58_address(address, _SIZES, alphabet=BITCOIN_ALPHABET)
    except CoinAddressesValueError as e:
        legacy = str(e)
    else:
        return
    try:
        assert_valid_segwit_address(
            address, hrp=_HRP, limit=_LIMIT, coin="Bitcoin Gold"
        )
    except (CoinAddressesValueError, Base58Bech32ValueError) as e:
        segwit = str(e)
    else:
        return
    err_msg = f"neither a legacy address ({legacy}) nor a segwit one ({segwit})"
    raise CoinAddressesValueError(err_msg)


def is_valid_address(address: str) -> bool:
    """Return whether a string is a Bitcoin Gold address.

    It answers `False` where `assert_valid_address` refuses the value,
    and a non-string is still a `CoinAddressesTypeError`.
    """
    try:
        assert_valid_address(address)
    except CoinAddressesValueError:
        return False
    return True
