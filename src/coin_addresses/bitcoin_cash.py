# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Bitcoin Cash addresses, in CashAddr and in Bitcoin's legacy format.

A CashAddr address is the prefix `bitcoincash`, ":", and a payload
whose checksum covers the prefix too: a version byte, giving a type and
a hash size, then the hash. `base58_bech32.cashaddr` is the codec, and
the specification is `spec/cashaddr.md` of
https://github.com/bitcoincashorg/bitcoincash.org. The prefix may be
left out of the string, and the checksum is then verified with
`bitcoincash`.

A legacy address is Bitcoin's: the Base58Check of version byte 0 and a
20-byte hash for pay-to-public-key-hash, or of version byte 5 and a
20-byte or 32-byte hash for pay-to-script-hash.

A key has one script, P2PKH, with an address in each format:
`address_from_pub_key` gives the CashAddr one and
`legacy_address_from_pub_key` the legacy one. `coin_addresses._bitcoin`
says which encoding of the key is hashed.

Validation is Bitcoin Cash Node's `DecodeDestination`, CashAddr first
and then legacy, but for whitespace around a legacy address, which
`coin_addresses._bitcoin` says is refused. A CashAddr type is 0 for
P2PKH, 1 for P2SH, and 2 and 3 for their token-aware forms; P2PKH takes
a 20-byte hash, P2SH a 20-byte or a 32-byte one:

- https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/e13b48e37b3005dca9a316f75aea456697a5dfd6/src/chainparams.cpp#L228-233
- https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/e13b48e37b3005dca9a316f75aea456697a5dfd6/src/cashaddrenc.h#L13-18
- https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/e13b48e37b3005dca9a316f75aea456697a5dfd6/src/cashaddrenc.cpp#L144-171
- https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/e13b48e37b3005dca9a316f75aea456697a5dfd6/src/key_io.cpp#L109-176

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

_PREFIX = "bitcoincash"
# the hash sizes each CashAddr type takes: P2PKH, P2SH, and the
# token-aware P2PKH and P2SH
_CASHADDR_SIZES = {0: (20,), 1: (20, 32), 2: (20,), 3: (20, 32)}

_P2PKH = 0
_P2SH = 5
# the hash sizes each legacy version byte takes
_LEGACY_SIZES = {_P2PKH: (20,), _P2SH: (20, 32)}


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
    """Refuse a string that is not a Bitcoin Cash address.

    A non-string is a `CoinAddressesTypeError`. A string Bitcoin Cash
    Node reads as neither a CashAddr address nor a legacy one is a
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
    """Return whether a string is a Bitcoin Cash address.

    It answers `False` where `assert_valid_address` refuses the value,
    and a non-string is still a `CoinAddressesTypeError`.
    """
    try:
        assert_valid_address(address)
    except CoinAddressesValueError:
        return False
    return True
