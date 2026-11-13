# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""XRP Ledger classic addresses: the key hash in Ripple's Base58Check.

A classic address is the Base58Check of the type prefix 0x00 and the
HASH160 of the key's compressed SEC encoding, written with Ripple's
alphabet, `rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz`,
in place of Bitcoin's. The checksum is Bitcoin's: the first four bytes
of the double SHA-256 of the prefix and the hash. The prefix 0x00 is
the alphabet's first character, `r`, which starts every address. The
encoding is `base58_bech32.base58`'s, which takes the alphabet as an
argument.

The key is read, and refused, as `coin_addresses._bitcoin.pub_key_hash`
says. The XRP Ledger's secp256k1 key is that 33-byte encoding alone, so
a key written uncompressed has no XRP Ledger address. Its Ed25519 key,
the byte 0xED and 32 bytes, is out of scope here and is refused as such.

The alphabet, the prefix and the checksum are those of *Addresses* and
*base58 Encodings* in the XRP Ledger's documentation. The derivation is
rippled's `calcAccountID`, the prefix its `TokenType::AccountID`, the
key types its `publicKeyType`, and validation its `parseBase58` of an
`AccountID`, which `decodeBase58Token` serves:

- https://github.com/XRPLF/xrpl-dev-portal/blob/182f8d20b157aa791433ff399a0f30dbed74a5eb/docs/concepts/accounts/addresses.md#address-encoding
- https://github.com/XRPLF/xrpl-dev-portal/blob/182f8d20b157aa791433ff399a0f30dbed74a5eb/docs/references/protocol/data-types/base58-encodings.md
- https://github.com/XRPLF/rippled/blob/00e640751460c137636fdb6dae6b4280de355d81/src/libxrpl/protocol/AccountID.cpp#L103-L111
- https://github.com/XRPLF/rippled/blob/00e640751460c137636fdb6dae6b4280de355d81/src/libxrpl/protocol/AccountID.cpp#L148-L156
- https://github.com/XRPLF/rippled/blob/00e640751460c137636fdb6dae6b4280de355d81/include/xrpl/protocol/tokens.h#L19-L28
- https://github.com/XRPLF/rippled/blob/00e640751460c137636fdb6dae6b4280de355d81/src/libxrpl/protocol/tokens.cpp#L126-L127
- https://github.com/XRPLF/rippled/blob/00e640751460c137636fdb6dae6b4280de355d81/src/libxrpl/protocol/tokens.cpp#L164-L178
- https://github.com/XRPLF/rippled/blob/00e640751460c137636fdb6dae6b4280de355d81/src/libxrpl/protocol/tokens.cpp#L636-L674
- https://github.com/XRPLF/rippled/blob/00e640751460c137636fdb6dae6b4280de355d81/src/libxrpl/protocol/PublicKey.cpp#L208-L221

An X-address, which writes a classic address with a destination tag
and a network, is out of scope: it decodes to another type prefix, and
`is_valid_address` refuses it.

A refusal names what is wrong, never the address or the key it was
handed. The refusals of `base58_bech32` do not quote them either, so
their messages are passed on.
"""

from __future__ import annotations

from base58_bech32.base58 import RIPPLE_ALPHABET
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

# `TokenType::AccountID`, the type prefix of a classic address
_PREFIX = 0x00
# the hash size the prefix takes
_SIZES = {_PREFIX: (20,)}
# the first byte of rippled's Ed25519 key, before its 32 bytes
_ED25519 = 0xED
_ED25519_SIZE = 33


def _assert_not_ed25519(pub_key: PubKey) -> None:
    """Refuse an Ed25519 key as the XRP Ledger writes it, 0xED and 32 bytes.

    Anything else is left to `pub_key_hash`, which refuses what is no
    secp256k1 key.
    """
    if isinstance(pub_key, str):
        try:
            octets = bytes.fromhex(pub_key)
        except ValueError:
            return
    elif isinstance(pub_key, (bytes, bytearray, memoryview)):
        octets = bytes(pub_key)
    else:
        return
    if len(octets) == _ED25519_SIZE and octets[0] == _ED25519:
        raise CoinAddressesValueError("Ed25519 public key, not supported")


def address_from_pub_key(pub_key: PubKey) -> str:
    """Return the XRP Ledger classic address of a secp256k1 public key.

    The key is read, and refused, as
    `coin_addresses._bitcoin.pub_key_hash` says. An Ed25519 key is a
    `CoinAddressesValueError` too.
    """
    _assert_not_ed25519(pub_key)
    return base58_address(_PREFIX, pub_key_hash(pub_key), alphabet=RIPPLE_ALPHABET)


def assert_valid_address(address: str) -> None:
    """Refuse a string that is not an XRP Ledger classic address.

    A non-string is a `CoinAddressesTypeError`. A string that is no
    Base58Check in Ripple's alphabet, or does not carry 0x00 and 20
    bytes, is a `CoinAddressesValueError`.
    """
    assert_string(address)
    decode_base58_address(address, _SIZES, alphabet=RIPPLE_ALPHABET)


def is_valid_address(address: str) -> bool:
    """Return whether a string is an XRP Ledger classic address.

    It answers `False` where `assert_valid_address` refuses the value,
    and a non-string is still a `CoinAddressesTypeError`.
    """
    try:
        assert_valid_address(address)
    except CoinAddressesValueError:
        return False
    return True
