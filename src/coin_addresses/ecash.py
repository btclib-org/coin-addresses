# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""eCash addresses, in CashAddr with the prefix `ecash`, and legacy ones.

A CashAddr address is Bitcoin Cash's format, as `coin_addresses.bitcoin_cash`
says, with the prefix `ecash`: the prefix, ":", a version byte giving a
type and a hash size, the hash, and a checksum covering the prefix too.
The prefix may be left out of the string, and the checksum is then
verified with `ecash`. `base58_bech32.cashaddr` is the codec.

A legacy address is Bitcoin's: the Base58Check of version byte 0 for
pay-to-public-key-hash or 5 for pay-to-script-hash, each with a 20-byte
hash.

A key has one script, P2PKH, with an address in each format:
`address_from_pub_key` gives the CashAddr one and
`legacy_address_from_pub_key` the legacy one. `coin_addresses._bitcoin`
says which encoding of the key is hashed.

The prefix and the version bytes are `CMainParams`'s, the prefix being
`ecash` under `DEFAULT_ECASH`, and validation is `DecodeDestination`'s,
CashAddr first and then legacy, in Bitcoin ABC, but for whitespace
around a legacy address, which `coin_addresses._bitcoin` says is
refused. A CashAddr type is 0 for P2PKH and 1 for P2SH, and each takes a
20-byte hash:

- https://github.com/Bitcoin-ABC/bitcoin-abc/blob/e726999f0be7f985bf014d2284a0b95a390c9f2b/src/kernel/chainparams.cpp#L198-L203
- https://github.com/Bitcoin-ABC/bitcoin-abc/blob/e726999f0be7f985bf014d2284a0b95a390c9f2b/src/chainparams.cpp#L28
- https://github.com/Bitcoin-ABC/bitcoin-abc/blob/e726999f0be7f985bf014d2284a0b95a390c9f2b/src/currencyunit.h#L10
- https://github.com/Bitcoin-ABC/bitcoin-abc/blob/e726999f0be7f985bf014d2284a0b95a390c9f2b/src/cashaddrenc.h#L14
- https://github.com/Bitcoin-ABC/bitcoin-abc/blob/e726999f0be7f985bf014d2284a0b95a390c9f2b/src/cashaddrenc.cpp#L102-L172
- https://github.com/Bitcoin-ABC/bitcoin-abc/blob/e726999f0be7f985bf014d2284a0b95a390c9f2b/src/key_io.cpp#L43-L74
- https://github.com/Bitcoin-ABC/bitcoin-abc/blob/e726999f0be7f985bf014d2284a0b95a390c9f2b/src/key_io.cpp#L174-L186

So a CashAddr address with the prefix `bitcoincash` is refused.

A refusal names what is wrong, never the address or the key it was
handed.
"""

from __future__ import annotations

from base58_bech32.base58 import BITCOIN_ALPHABET
from base58_bech32.cashaddr import cashaddr_encode
from base58_bech32.exceptions import Base58Bech32ValueError
from ecc.curves import PubKey

from coin_addresses._bitcoin import (
    assert_string,
    assert_valid_cashaddr,
    base58_address,
    decode_base58_address,
    pub_key_hash,
)
from coin_addresses.exceptions import CoinAddressesValueError

__all__ = [
    "address_from_pub_key",
    "assert_valid_address",
    "is_valid_address",
    "legacy_address_from_pub_key",
]

_PREFIX = "ecash"
# the hash size each CashAddr type takes: P2PKH and P2SH
_CASHADDR_SIZES = {0: (20,), 1: (20,)}

_P2PKH = 0
_P2SH = 5
# the hash size each legacy version byte takes
_LEGACY_SIZES = {_P2PKH: (20,), _P2SH: (20,)}


def address_from_pub_key(pub_key: PubKey) -> str:
    """Return the CashAddr P2PKH address of a secp256k1 public key.

    The address carries its prefix. The key is read, and refused, as
    `coin_addresses._bitcoin.pub_key_hash` says.
    """
    return cashaddr_encode(_PREFIX, 0, pub_key_hash(pub_key)).decode("ascii")


def legacy_address_from_pub_key(pub_key: PubKey) -> str:
    """Return the legacy P2PKH address of a secp256k1 public key.

    The key is read, and refused, as
    `coin_addresses._bitcoin.pub_key_hash` says.
    """
    return base58_address(_P2PKH, pub_key_hash(pub_key), alphabet=BITCOIN_ALPHABET)


def assert_valid_address(address: str) -> None:
    """Refuse a string that is not an eCash address.

    A non-string is a `CoinAddressesTypeError`. A string Bitcoin ABC
    reads as neither a CashAddr address nor a legacy one is a
    `CoinAddressesValueError`, which gives both reasons.
    """
    assert_string(address)
    try:
        assert_valid_cashaddr(address, prefix=_PREFIX, sizes=_CASHADDR_SIZES)
    except (CoinAddressesValueError, Base58Bech32ValueError) as e:
        cashaddr = str(e)
    else:
        return
    try:
        decode_base58_address(address, _LEGACY_SIZES, alphabet=BITCOIN_ALPHABET)
    except CoinAddressesValueError as e:
        legacy = str(e)
    else:
        return
    err_msg = f"neither a CashAddr address ({cashaddr}) nor a legacy one ({legacy})"
    raise CoinAddressesValueError(err_msg)


def is_valid_address(address: str) -> bool:
    """Return whether a string is an eCash address.

    It answers `False` where `assert_valid_address` refuses the value,
    and a non-string is still a `CoinAddressesTypeError`.
    """
    try:
        assert_valid_address(address)
    except CoinAddressesValueError:
        return False
    return True
