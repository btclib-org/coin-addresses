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
from base58_bech32.bech32 import (
    BECH32_1_CONST,
    BECH32_M_CONST,
    bech32_decode,
    bech32_encode,
    convertbits,
)
from base58_bech32.exceptions import Base58Bech32ValueError
from ecc.curves import PubKey

from coin_addresses._bitcoin import (
    assert_string,
    base58_address,
    decode_base58_address,
    pub_key_hash,
)
from coin_addresses._hashes import hash160
from coin_addresses.exceptions import CoinAddressesTypeError, CoinAddressesValueError

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

_SCRIPT_TYPES = ("p2pkh", "p2sh-p2wpkh", "p2wpkh")


def _segwit_address(version: int, program: bytes) -> str:
    """Return the segwit address of a witness version and program."""
    data = [version, *convertbits(program, 8, 5)]
    m = BECH32_1_CONST if version == 0 else BECH32_M_CONST
    return bech32_encode(_HRP, data, m=m, limit=_LIMIT).decode("ascii")


def address_from_pub_key(pub_key: PubKey, *, script_type: str = "p2pkh") -> str:
    """Return the address of a secp256k1 public key, for one script type.

    `script_type` is "p2pkh", "p2sh-p2wpkh" or "p2wpkh", as the module's
    docstring says; another string is a `CoinAddressesValueError`, and a
    non-string a `CoinAddressesTypeError`. The key is read, and refused,
    as `coin_addresses._bitcoin.pub_key_hash` says.
    """
    if not isinstance(script_type, str):
        raise CoinAddressesTypeError(
            f"script type not a string: {type(script_type).__name__}"
        )
    if script_type not in _SCRIPT_TYPES:
        err_msg = f"unknown script type, not one of {', '.join(_SCRIPT_TYPES)}"
        raise CoinAddressesValueError(err_msg)
    digest = pub_key_hash(pub_key)
    if script_type == "p2pkh":
        return base58_address(_P2PKH, digest, alphabet=BITCOIN_ALPHABET)
    if script_type == "p2wpkh":
        return _segwit_address(0, digest)
    # the redeem script is the witness program: OP_0, then a push of the
    # 20-byte key hash
    return base58_address(
        _P2SH, hash160(b"\x00\x14" + digest), alphabet=BITCOIN_ALPHABET
    )


def _assert_valid_segwit_address(address: str) -> None:
    """Refuse a string that is not a Litecoin segwit address."""
    hrp, data, m = bech32_decode(address, limit=_LIMIT)
    if hrp != _HRP:
        raise CoinAddressesValueError("not the Litecoin HRP")
    if not data:
        raise CoinAddressesValueError("no witness version")
    version = data[0]
    if version > 16:
        raise CoinAddressesValueError(f"invalid witness version: {version}")
    if m != (BECH32_1_CONST if version == 0 else BECH32_M_CONST):
        raise CoinAddressesValueError(f"wrong checksum for witness version {version}")
    program = convertbits(data[1:], 5, 8, pad=False)
    if version == 0 and len(program) not in (20, 32):
        err_msg = f"{len(program)}-byte witness program for witness version 0"
        raise CoinAddressesValueError(err_msg)
    if not 2 <= len(program) <= 40:
        raise CoinAddressesValueError(f"{len(program)}-byte witness program")


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
        _assert_valid_segwit_address(address)
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
