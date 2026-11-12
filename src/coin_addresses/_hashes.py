# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""HASH160, the RIPEMD-160 of the SHA-256 that a bitcoin address carries.

`ripemd160` is OpenSSL's, through `hashlib.new("ripemd160")`, where the
interpreter's OpenSSL answers the known digest of the empty input, and
the pure Python one of `coin_addresses._ripemd160` where it does not.
OpenSSL 3.0.0 to 3.0.6 ship RIPEMD-160 in the legacy provider alone,
so `hashlib.new` raises `ValueError` for the name where that provider is
not loaded.

The module is private: it serves the address formats of this package,
and a hash function is not among what the package publishes.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Protocol

from coin_addresses._ripemd160 import ripemd160 as pure_python_ripemd160

if TYPE_CHECKING:
    from collections.abc import Callable

__all__: list[str] = []

# RIPEMD-160 of the empty input, the first of the vectors its authors
# publish, which tests/ripemd160_test.py checks
EMPTY_DIGEST = bytes.fromhex("9c1185a5c5e9fc54612808977ee8f548b2258d31")


class _Hash(Protocol):
    """What `hashlib.new` returns, as far as this module reads it."""

    def digest(self) -> bytes:
        """Return the digest of what the object has hashed."""


def select(new: Callable[[str, bytes], _Hash]) -> Callable[[bytes], bytes]:
    """Return OpenSSL's RIPEMD-160 where `new` answers it, or the Python one.

    `new` is `hashlib.new` at import, and a stand-in in the tests, so that
    each branch runs on every interpreter. OpenSSL's is taken only where
    it answers `EMPTY_DIGEST`: a provider that answers the name with
    another digest is not trusted with an address.
    """
    try:
        digest = new("ripemd160", b"").digest()
    except ValueError:
        return pure_python_ripemd160
    if digest != EMPTY_DIGEST:
        return pure_python_ripemd160

    def openssl_ripemd160(data: bytes) -> bytes:
        """Return the RIPEMD-160 digest of data, computed by OpenSSL."""
        return new("ripemd160", data).digest()

    return openssl_ripemd160


ripemd160 = select(hashlib.new)


def hash160(data: bytes) -> bytes:
    """Return the RIPEMD-160 of the SHA-256 of data."""
    return ripemd160(hashlib.sha256(data).digest())
