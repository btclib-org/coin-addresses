# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Cosmos Hub addresses: the key hash in bech32, with the HRP `cosmos`.

An account address is the bech32 of the HASH160 of the key's compressed
SEC encoding, with the HRP `cosmos`. The key is read, and refused, as
`coin_addresses._bitcoin.pub_key_hash` says. The Cosmos SDK's secp256k1
key is that 33-byte encoding alone, and its `Address` refuses any other
length, so a key written uncompressed has no Cosmos address.

The derivation is the SDK's `PubKey.Address`, the HRP its
`Bech32MainPrefix`, and validation its `AccAddressFromBech32`: a bech32
string, BIP173's checksum and not BIP350's, of at most 1023 characters,
with the HRP `cosmos` and 1 to 255 bytes. So the 32 bytes the SDK's
`address.Module` derives for a module account with a key are an address
too. This is the SDK release the Cosmos Hub's gaia builds on, which sets
no address verifier of its own:

- https://github.com/cosmos/cosmos-sdk/blob/102db7cd8c9ade54b770e0f2eea1ca597fa97ed3/crypto/keys/secp256k1/secp256k1.go#L152-L164
- https://github.com/cosmos/cosmos-sdk/blob/102db7cd8c9ade54b770e0f2eea1ca597fa97ed3/types/address.go#L39
- https://github.com/cosmos/cosmos-sdk/blob/102db7cd8c9ade54b770e0f2eea1ca597fa97ed3/types/address.go#L166-L211
- https://github.com/cosmos/cosmos-sdk/blob/102db7cd8c9ade54b770e0f2eea1ca597fa97ed3/types/address.go#L687-L702
- https://github.com/cosmos/cosmos-sdk/blob/102db7cd8c9ade54b770e0f2eea1ca597fa97ed3/types/bech32/bech32.go#L20-L32
- https://github.com/cosmos/cosmos-sdk/blob/102db7cd8c9ade54b770e0f2eea1ca597fa97ed3/types/address/store_key.go#L10
- https://github.com/cosmos/cosmos-sdk/blob/102db7cd8c9ade54b770e0f2eea1ca597fa97ed3/types/address/hash.go#L66-L86
- https://github.com/cosmos/gaia/blob/f4e63e3abe4a4ced05533ca572d344bf774a2cad/go.mod#L25

A chain with another HRP need not hash the key this way: bip_utils
writes Injective's address as the bech32 of the 20 bytes of an Ethereum
address. So the module writes and reads the HRP `cosmos` alone, and an
address with any other HRP is refused, the SDK's own `cosmosvaloper`
among them:

- https://github.com/ebellocchia/bip_utils/blob/286f03d36c80e1a7229d9586dd3651f5f73ba9b4/bip_utils/addr/inj_addr.py#L84-L102

A refusal names what is wrong, never the address or the key it was
handed. The refusals of `base58_bech32` do not quote them either, so
their messages are passed on.
"""

from __future__ import annotations

from base58_bech32.bech32 import (
    BECH32_1_CONST,
    bech32_decode_bytes,
    bech32_encode_bytes,
)
from base58_bech32.exceptions import Base58Bech32ValueError
from ecc.curves import PubKey

from coin_addresses._bitcoin import assert_string, pub_key_hash
from coin_addresses.exceptions import CoinAddressesValueError

__all__ = [
    "address_from_pub_key",
    "assert_valid_address",
    "is_valid_address",
]

_HRP = "cosmos"
# the length limit of the SDK's `DecodeAndConvert`
_LIMIT = 1023
# `MaxAddrLen`, the most bytes an address may carry
_MAX_SIZE = 255


def address_from_pub_key(pub_key: PubKey) -> str:
    """Return the Cosmos Hub address of a secp256k1 public key.

    The key is read, and refused, as
    `coin_addresses._bitcoin.pub_key_hash` says.
    """
    digest = pub_key_hash(pub_key)
    return bech32_encode_bytes(_HRP, digest, m=BECH32_1_CONST).decode("ascii")


def assert_valid_address(address: str) -> None:
    """Refuse a string that is not a Cosmos Hub address.

    A non-string is a `CoinAddressesTypeError`. A string that is no
    bech32, or has another HRP, or carries no bytes or more than 255, is a
    `CoinAddressesValueError`.
    """
    assert_string(address)
    # the refusal is raised after the `try`, so that base58_bech32's
    # exception is neither its cause nor its context
    try:
        hrp, payload = bech32_decode_bytes(address, m=BECH32_1_CONST, limit=_LIMIT)
    except Base58Bech32ValueError as e:
        reason = str(e)
    else:
        if hrp != _HRP:
            raise CoinAddressesValueError("not the Cosmos HRP")
        if not payload:
            raise CoinAddressesValueError("no address bytes")
        if len(payload) > _MAX_SIZE:
            err_msg = f"{len(payload)}-byte address, more than {_MAX_SIZE}"
            raise CoinAddressesValueError(err_msg)
        return
    raise CoinAddressesValueError(reason)


def is_valid_address(address: str) -> bool:
    """Return whether a string is a Cosmos Hub address.

    It answers `False` where `assert_valid_address` refuses the value,
    and a non-string is still a `CoinAddressesTypeError`.
    """
    try:
        assert_valid_address(address)
    except CoinAddressesValueError:
        return False
    return True
