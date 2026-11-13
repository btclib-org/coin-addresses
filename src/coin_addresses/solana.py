# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Solana addresses: 32 bytes in Base58, with no checksum.

An address is 32 bytes, written in Base58 with Bitcoin's alphabet. An
account's address is its ed25519 public key itself, so the derivation
hashes nothing. A program derived address is 32 bytes chosen off the
ed25519 curve, so that no private key signs for it, and is written the
same way.

The size and the encoding are those of *Account address* in Solana's
documentation. solana-sdk's `Address`, which `Pubkey` re-exports, holds
32 bytes, `ADDRESS_BYTES`, and its `FromStr` refuses a string of more
than 44 characters, then decodes with five8's `decode_32`. That refuses
a character outside Bitcoin's alphabet and a string that is not the
encoding of exactly 32 bytes:

- https://github.com/solana-foundation/solana-com/blob/ea7971b5f4f630dfa53e7e95cff408d877a8a459/apps/docs/content/docs/en/core/accounts/account-structure.mdx#L25-L27
- https://github.com/anza-xyz/solana-sdk/blob/617887a6f8a306a6ca94b5907eaa3772db43a54b/address/src/lib.rs#L56-L63
- https://github.com/anza-xyz/solana-sdk/blob/617887a6f8a306a6ca94b5907eaa3772db43a54b/address/src/lib.rs#L113-L131
- https://github.com/kevinheavey/five8/blob/311279fb81461df36e730458a0463a6a322042d7/crates/five8_core/src/lib.rs#L6-L27
- https://github.com/kevinheavey/five8/blob/311279fb81461df36e730458a0463a6a322042d7/crates/five8/src/decode.rs#L56-L185

Base58 writes each leading zero byte as one leading `1`, so a string
that decodes to 32 bytes is the one encoding of those bytes, and the
decoding is `base58_bech32.base58`'s.

Neither a key nor an address is checked to lie on the curve. A program
derived address does not, by design, and `Address` takes any 32 bytes;
its `is_on_curve` is a question apart:

- https://github.com/solana-foundation/solana-com/blob/ea7971b5f4f630dfa53e7e95cff408d877a8a459/apps/docs/content/docs/en/core/pda/index.mdx#L18-L20
- https://github.com/anza-xyz/solana-sdk/blob/617887a6f8a306a6ca94b5907eaa3772db43a54b/address/src/lib.rs#L312-L323

So `address_from_pub_key` takes any 32 bytes as the key, and a value
that is no point of the curve gives the address those bytes write.

A refusal names what is wrong, never the address or the key it was
handed. The refusals of `base58_bech32` do not quote them either, so
their messages are passed on.
"""

from __future__ import annotations

from base58_bech32.base58 import b58decode, b58encode
from base58_bech32.exceptions import Base58Bech32ValueError
from ecc.alias import Octets

from coin_addresses._bitcoin import assert_string
from coin_addresses.exceptions import CoinAddressesTypeError, CoinAddressesValueError

__all__ = [
    "address_from_pub_key",
    "assert_valid_address",
    "is_valid_address",
]

# `ADDRESS_BYTES`, the size of an address and of an ed25519 public key
_SIZE = 32
# `MAX_BASE58_LEN`, the longest string `FromStr` decodes: the Base58 of
# 32 bytes of 0xFF
_MAX_LENGTH = 44


def _key_bytes(pub_key: Octets) -> bytes:
    """Return the 32 bytes of a public key given as octets or as hex.

    A value of no octets type is a `CoinAddressesTypeError`. A string
    that is no hex, a `memoryview` that is released or is not plain
    contiguous bytes, and octets of another size are each a
    `CoinAddressesValueError`.
    """
    # each refusal of a value is the size check's, raised outside the
    # `except` that may come first, so that no error is chained
    if isinstance(pub_key, str):
        try:
            octets = bytes.fromhex(pub_key)
        except ValueError:
            octets = b""
    elif isinstance(pub_key, memoryview):
        try:
            plain = pub_key.c_contiguous and pub_key.format == "B"
            octets = bytes(pub_key) if plain else b""
        except ValueError:
            # a released view answers every read with a ValueError
            octets = b""
    elif isinstance(pub_key, (bytes, bytearray)):
        octets = bytes(pub_key)
    else:
        # what mypy rules out and a caller can still pass
        err_msg = f"not a public key: {type(pub_key).__name__}"  # type: ignore[unreachable]
        raise CoinAddressesTypeError(err_msg)
    if len(octets) != _SIZE:
        raise CoinAddressesValueError("not a public key")
    return octets


def address_from_pub_key(pub_key: Octets) -> str:
    """Return the Solana address of an ed25519 public key.

    The key is its 32 bytes, as bytes, a bytearray, a memoryview or a
    hex string, and is not checked to lie on the curve. A value of no
    such type is a `CoinAddressesTypeError`, and one that is not 32
    bytes a `CoinAddressesValueError`.
    """
    return b58encode(_key_bytes(pub_key)).decode("ascii")


def assert_valid_address(address: str) -> None:
    """Refuse a string that is not a Solana address.

    A non-string is a `CoinAddressesTypeError`. A string longer than 44
    characters, one with a character outside Bitcoin's Base58 alphabet,
    and one that does not decode to 32 bytes are each a
    `CoinAddressesValueError`.
    """
    assert_string(address)
    try:
        decoded = b58decode(address, max_length=_MAX_LENGTH)
    except Base58Bech32ValueError as e:
        reason = str(e)
    else:
        if len(decoded) != _SIZE:
            err_msg = f"{len(decoded)}-byte address, not {_SIZE}"
            raise CoinAddressesValueError(err_msg)
        return
    raise CoinAddressesValueError(reason)


def is_valid_address(address: str) -> bool:
    """Return whether a string is a Solana address.

    It answers `False` where `assert_valid_address` refuses the value,
    and a non-string is still a `CoinAddressesTypeError`.
    """
    try:
        assert_valid_address(address)
    except CoinAddressesValueError:
        return False
    return True
