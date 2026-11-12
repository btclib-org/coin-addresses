# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Keccak-256, the hash an Ethereum address and its EIP-55 checksum use.

Keccak-256 is the Keccak team's SHA-3 submission at a 1088-bit rate,
padded by pad10*1 alone. FIPS 202's SHA3-256 adds two domain bits before
that padding, so `hashlib.sha3_256` answers another digest for every
input.

`keccak_256` is OpenSSL's, through `hashlib.new("keccak-256")`, where the
interpreter's OpenSSL answers the known digest of the empty input, and
`pure_python_keccak_256` below where it does not: an interpreter linked
to LibreSSL, or to an OpenSSL without the algorithm, raises `ValueError`
for the name.

The module is private: it serves the address formats of this package,
and a hash function is not among what the package publishes.
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable

__all__: list[str] = []

# the rate of Keccak-256, in bytes: 1600 bits of state less a 512-bit
# capacity
RATE = 136

_MASK = (1 << 64) - 1

# the round constants of Keccak-f[1600], from the Keccak reference
_ROUND_CONSTANTS = (
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
)

# the rotation of the lane at x, y is _ROTATIONS[x][y], from the Keccak
# reference
_ROTATIONS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)

# Keccak-256 of the empty input: the first entry of the Keccak team's
# ShortMsgKAT_256, which tests/keccak_test.py checks this module against
EMPTY_DIGEST = bytes.fromhex(
    "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
)


def _rotate(lane: int, n: int) -> int:
    """Rotate a 64-bit lane left by n bits."""
    return ((lane << n) | (lane >> (64 - n))) & _MASK


def _permute(state: list[int]) -> None:
    """Apply Keccak-f[1600] in place to 25 lanes, the lane x, y at x + 5 y."""
    for constant in _ROUND_CONSTANTS:
        # theta
        parity = [
            state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
            for x in range(5)
        ]
        for x in range(5):
            d = parity[x - 1] ^ _rotate(parity[(x + 1) % 5], 1)
            for y in range(0, 25, 5):
                state[x + y] ^= d
        # rho and pi: the lane at x, y moves to y, 2x + 3y
        moved = [0] * 25
        for x in range(5):
            for y in range(5):
                lane = state[x + 5 * y]
                n = _ROTATIONS[x][y]
                moved[y + 5 * ((2 * x + 3 * y) % 5)] = _rotate(lane, n) if n else lane
        # chi
        for y in range(0, 25, 5):
            row = moved[y : y + 5]
            for x in range(5):
                state[x + y] = row[x] ^ (~row[(x + 1) % 5] & row[(x + 2) % 5])
        # iota
        state[0] ^= constant


def pure_python_keccak_256(data: bytes) -> bytes:
    """Return the Keccak-256 digest of data, computed in Python alone."""
    # pad10*1: a 1 bit, zeros, a 1 bit at the end of the block. The two
    # 1 bits share a byte, 0x81, where one byte of the block is left
    padded = bytearray(data)
    padded.append(0x01)
    padded.extend(bytes(-len(padded) % RATE))
    padded[-1] |= 0x80
    state = [0] * 25
    for start in range(0, len(padded), RATE):
        block = padded[start : start + RATE]
        for i in range(RATE // 8):
            state[i] ^= int.from_bytes(block[8 * i : 8 * i + 8], "little")
        _permute(state)
    return b"".join(lane.to_bytes(8, "little") for lane in state[:4])


class _Hash(Protocol):
    """What `hashlib.new` returns, as far as this module reads it."""

    def digest(self) -> bytes:
        """Return the digest of what the object has hashed."""


def select(new: Callable[[str, bytes], _Hash]) -> Callable[[bytes], bytes]:
    """Return OpenSSL's Keccak-256 where `new` answers it, or the Python one.

    `new` is `hashlib.new` at import, and a stand-in in the tests, so that
    each branch runs on every interpreter. OpenSSL's is taken only where
    it answers `EMPTY_DIGEST`: a provider that answers the name with
    another digest is not trusted with an address.
    """
    try:
        digest = new("keccak-256", b"").digest()
    except ValueError:
        return pure_python_keccak_256
    if digest != EMPTY_DIGEST:
        return pure_python_keccak_256

    def openssl_keccak_256(data: bytes) -> bytes:
        """Return the Keccak-256 digest of data, computed by OpenSSL."""
        return new("keccak-256", data).digest()

    return openssl_keccak_256


keccak_256 = select(hashlib.new)
