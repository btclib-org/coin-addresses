# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Bitcoin SV addresses: Bitcoin's legacy ones, with Bitcoin's version bytes.

An address is the Base58Check of a version byte and a 20-byte hash: 0
for pay-to-public-key-hash, written with a leading 1, and 5 for
pay-to-script-hash, written with a leading 3. Bitcoin SV has no segwit
and no CashAddr, so a key has the one address, P2PKH, and
`coin_addresses._bitcoin` says which encoding of the key it hashes.

The version bytes are `CMainParams`'s `base58Prefixes`, the encoding is
`DestinationEncoder`'s, and validation is `DecodeDestination`'s, which
reads Base58Check alone, in the Bitcoin SV node, but for whitespace
around an address, which `coin_addresses._bitcoin` says is refused:

- https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/chainparams.cpp#L1111-L1112
- https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/base58.cpp#L209-L257
- https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/dstencode.cpp#L16-L24

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
    pub_key_hash,
)
from coin_addresses.exceptions import CoinAddressesValueError

__all__ = [
    "address_from_pub_key",
    "assert_valid_address",
    "is_valid_address",
]

_P2PKH = 0
_P2SH = 5
# the hash size each version byte takes
_SIZES = {_P2PKH: (20,), _P2SH: (20,)}


def address_from_pub_key(pub_key: PubKey) -> str:
    """Return the P2PKH address of a secp256k1 public key.

    The key is read, and refused, as
    `coin_addresses._bitcoin.pub_key_hash` says.
    """
    return base58_address(_P2PKH, pub_key_hash(pub_key), alphabet=BITCOIN_ALPHABET)


def assert_valid_address(address: str) -> None:
    """Refuse a string that is not a Bitcoin SV address, P2PKH or P2SH.

    A non-string is a `CoinAddressesTypeError`. A string that is no
    Base58Check, or whose version byte or hash size is not Bitcoin SV's,
    is a `CoinAddressesValueError`.
    """
    assert_string(address)
    decode_base58_address(address, _SIZES, alphabet=BITCOIN_ALPHABET)


def is_valid_address(address: str) -> bool:
    """Return whether a string is a Bitcoin SV address.

    It answers `False` where `assert_valid_address` refuses the value,
    and a non-string is still a `CoinAddressesTypeError`.
    """
    try:
        assert_valid_address(address)
    except CoinAddressesValueError:
        return False
    return True
