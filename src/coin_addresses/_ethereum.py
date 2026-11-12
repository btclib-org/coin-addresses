# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What Tron takes from Ethereum: the 20 bytes an address carries.

They are the bytes `coin_addresses.evm`'s docstring defines. Every
spelling of one key gives the same bytes, its SEC encoding compressed or
not.

A refusal names what is wrong, never the key it was handed.

The module is private: the coin modules publish what it serves.
"""

from __future__ import annotations

from ecc.curves import PubKey, point_from_pub_key, secp256k1
from ecc.exceptions import EccTypeError, EccValueError

from coin_addresses._keccak import keccak_256
from coin_addresses.exceptions import (
    CoinAddressesException,
    CoinAddressesTypeError,
    CoinAddressesValueError,
)

__all__: list[str] = []


def pub_key_hash(pub_key: PubKey) -> bytes:
    """Return the 20 bytes of a secp256k1 public key's Ethereum address.

    The key is any spelling `ecc.curves.point_from_pub_key` reads: a
    point, or its SEC encoding, compressed or not, as bytes or as hex. A
    value of no type a key has is a `CoinAddressesTypeError`, and one that
    is no point of the curve a `CoinAddressesValueError`.
    """
    # the refusal is raised after the `try`, so that ecc's exception is
    # neither its cause nor its context
    kind: type[CoinAddressesException]
    try:
        x, y = point_from_pub_key(pub_key, secp256k1)
    except EccTypeError:
        kind = CoinAddressesTypeError
    except EccValueError:
        kind = CoinAddressesValueError
    else:
        return keccak_256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[-20:]
    raise kind("not a public key")
