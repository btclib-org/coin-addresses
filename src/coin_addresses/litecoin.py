# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Litecoin addresses: Bitcoin's, with Litecoin's version bytes and HRP.

A legacy address is the Base58Check of a version byte and a 20-byte
hash: 48 for pay-to-public-key-hash, written with a leading L, and 50
for pay-to-script-hash, written with a leading M. Litecoin Core also
reads P2SH written with Bitcoin's 5, a leading 3. A segwit address is
BIP173's bech32, or BIP350's bech32m from witness version 1, with the
HRP `ltc`.

`address_from_pub_key`'s `script_type` names the address a key gives:
"p2pkh", "p2sh-p2wpkh", the P2SH of the version 0 witness program of the
key hash, or "p2wpkh", that witness program as a segwit address.
`coin_addresses._bitcoin` says which encoding of the key is hashed.

The version bytes and the HRP are `CMainParams`'s, the encodings are
`DestinationEncoder`'s, which writes P2SH with 50, and validation is
`DecodeDestination`'s, in Litecoin Core, but for whitespace around a
legacy address, which `coin_addresses._bitcoin` says is refused:

- https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/src/chainparams.cpp#L145-L152
- https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/src/key_io.cpp#L28-L56
- https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/src/key_io.cpp#L82-L165

That function also reads an MWEB stealth address, HRP `ltcmweb`, which
no single public key gives: validation here refuses it.

A segwit address of witness version 1, such as a P2TR one, is valid as
`DecodeDestination` reads it, and no key here gives one: Litecoin Core's
wallet derives none, its `OutputType` being legacy, P2SH-segwit, bech32
and MWEB:

- https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/src/outputtype.h#L18-L23

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

_P2PKH = 48
_P2SH = 50
_P2SH_BITCOIN = 5
# the hash size each version byte takes
_SIZES = {_P2PKH: (20,), _P2SH: (20,), _P2SH_BITCOIN: (20,)}

_HRP = "ltc"
# BIP173's limit, which Litecoin Core's `bech32::Decode` keeps for a
# segwit address
_LIMIT = 90


def address_from_pub_key(pub_key: PubKey, *, script_type: str = "p2pkh") -> str:
    """Return the address of a secp256k1 public key, for one script type.

    `script_type` is "p2pkh", "p2sh-p2wpkh" or "p2wpkh", as the module's
    docstring says, and it and the key are read, and refused, as
    `coin_addresses._bitcoin.script_type_address` says.
    """
    return script_type_address(
        pub_key, script_type, p2pkh=_P2PKH, p2sh=_P2SH, hrp=_HRP, limit=_LIMIT
    )


def assert_valid_address(address: str) -> None:
    """Refuse a string that is not a Litecoin address.

    A non-string is a `CoinAddressesTypeError`. A string Litecoin Core
    reads as neither a legacy address nor a segwit address is a
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
        assert_valid_segwit_address(address, hrp=_HRP, limit=_LIMIT, coin="Litecoin")
    except (CoinAddressesValueError, Base58Bech32ValueError) as e:
        segwit = str(e)
    else:
        return
    err_msg = f"neither a legacy address ({legacy}) nor a segwit one ({segwit})"
    raise CoinAddressesValueError(err_msg)


def is_valid_address(address: str) -> bool:
    """Return whether a string is a Litecoin address.

    It answers `False` where `assert_valid_address` refuses the value,
    and a non-string is still a `CoinAddressesTypeError`.
    """
    try:
        assert_valid_address(address)
    except CoinAddressesValueError:
        return False
    return True
