# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What Solana and Stellar share: the 32 bytes of an ed25519 public key.

The key is not checked to lie on the curve: `ecc` has no ed25519, and
each coin's module says why its addresses take any 32 bytes.

A refusal names what is wrong, never the key it was handed.

The module is private: the coin modules publish what it serves.
"""

from __future__ import annotations

from ecc.alias import Octets

from coin_addresses.exceptions import CoinAddressesTypeError, CoinAddressesValueError

__all__: list[str] = []

# the size of an ed25519 public key
_SIZE = 32


def pub_key_bytes(pub_key: Octets) -> bytes:
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
