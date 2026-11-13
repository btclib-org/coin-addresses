# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Stellar account addresses: the strkey of an ed25519 public key.

An account address is the strkey of the version byte `6 << 3` and the
key's 32 bytes: the base-32, without padding, of those 33 bytes and
their CRC16-XModem checksum, 56 characters starting with `G`. The
version byte is `STRKEY_PUBKEY` with the algorithm `STRKEY_ALG_ED25519`,
which is 0. The derivation hashes nothing, and the encoding is
`base58_bech32.strkey`'s.

The version byte, the sizes and the encoding are those of SEP-0023. The
reference is js-stellar-base's `StrKey`: its `ed25519PublicKey` version
byte, and its `isValid`, which takes 56 characters that decode, under
that version byte, to 32 bytes:

- https://github.com/stellar/stellar-protocol/blob/f2d364902615af726b3533021403c8b225aa6e5d/ecosystem/sep-0023.md#L41-L118
- https://github.com/stellar/js-stellar-base/blob/6ad55f781139898ade2bbb54987c268af0d6ecb6/src/strkey.js#L6-L16
- https://github.com/stellar/js-stellar-base/blob/6ad55f781139898ade2bbb54987c268af0d6ecb6/src/strkey.js#L286-L398

Neither a key nor an address is checked to lie on the curve: `isValid`
does not, and `ecc` has no ed25519. So `address_from_pub_key` takes any
32 bytes as the key.

A muxed account, `M...`, which writes an account with a 64-bit id, is
out of scope: `is_valid_address` refuses it by its version byte,
`12 << 3`. Every other strkey, a secret seed `S...` among them, is
refused by its version byte too.

A refusal names what is wrong, never the address or the key it was
handed. The refusals of `base58_bech32` do not quote them either, so
their messages are passed on.
"""

from __future__ import annotations

from base58_bech32.exceptions import Base58Bech32ValueError
from base58_bech32.strkey import strkey_decode, strkey_encode
from ecc.alias import Octets

from coin_addresses._bitcoin import assert_string
from coin_addresses._ed25519 import pub_key_bytes
from coin_addresses.exceptions import CoinAddressesValueError

__all__ = [
    "address_from_pub_key",
    "assert_valid_address",
    "is_valid_address",
]

# `STRKEY_PUBKEY | STRKEY_ALG_ED25519`, the version byte of an account
_VERSION = 6 << 3
# `STRKEY_MUXED | STRKEY_ALG_ED25519`, the version byte of a muxed account
_MUXED = 12 << 3
# the size of the key an account's strkey carries
_SIZE = 32


def address_from_pub_key(pub_key: Octets) -> str:
    """Return the Stellar account address of an ed25519 public key.

    The key is its 32 bytes, as bytes, a bytearray, a memoryview or a
    hex string, and is not checked to lie on the curve. A value of no
    such type is a `CoinAddressesTypeError`, and one that is not 32
    bytes a `CoinAddressesValueError`.
    """
    return strkey_encode(_VERSION, pub_key_bytes(pub_key)).decode("ascii")


def assert_valid_address(address: str) -> None:
    """Refuse a string that is not a Stellar account address.

    A non-string is a `CoinAddressesTypeError`. A string that is no
    strkey, a muxed account, a strkey of another version byte, and one
    that does not carry 32 bytes are each a `CoinAddressesValueError`.
    """
    assert_string(address)
    try:
        version, payload = strkey_decode(address)
    except Base58Bech32ValueError as e:
        reason = str(e)
    else:
        if version == _MUXED:
            raise CoinAddressesValueError("muxed account, not supported")
        if version != _VERSION:
            err_msg = f"not an account's version byte: {version}"
            raise CoinAddressesValueError(err_msg)
        if len(payload) != _SIZE:
            err_msg = f"{len(payload)}-byte key, not {_SIZE}"
            raise CoinAddressesValueError(err_msg)
        return
    raise CoinAddressesValueError(reason)


def is_valid_address(address: str) -> bool:
    """Return whether a string is a Stellar account address.

    It answers `False` where `assert_valid_address` refuses the value,
    and a non-string is still a `CoinAddressesTypeError`.
    """
    try:
        assert_valid_address(address)
    except CoinAddressesValueError:
        return False
    return True
