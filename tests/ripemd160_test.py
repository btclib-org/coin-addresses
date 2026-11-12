# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for RIPEMD-160, both the pure-Python one and OpenSSL's, and HASH160.

The pure-Python function is called by name here, so it runs on every
interpreter, OpenSSL's included. `select` is driven with stand-ins for
`hashlib.new`, so each of its branches runs whatever the interpreter's
OpenSSL holds.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass

import pytest

from coin_addresses import _hashes
from coin_addresses._hashes import EMPTY_DIGEST, hash160, ripemd160, select
from coin_addresses._ripemd160 import fi
from coin_addresses._ripemd160 import ripemd160 as pure_python_ripemd160
from coin_addresses.exceptions import CoinAddressesValueError

# the vectors the authors of RIPEMD-160 publish at
# https://homes.esat.kuleuven.be/~bosselae/ripemd160.html, as the
# vendored upstream carries them in its own unittest:
#
# repo    bitcoin/bitcoin
# path    test/functional/test_framework/crypto/ripemd160.py
# commit  9183edd25e60aa410bc3e4728989a1d75c309a09
# blob    12801364b406a36679a4fd3d6abef74b67011fe9
#
# all but the last, a million times "a", which the pure-Python function
# would take seconds over: `test_openssl_and_python_agree` reaches the
# many-block loop on shorter inputs
_VECTORS = (
    (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
    (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
    (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
    (b"message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
    (b"abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "12a053384a9c0c88e405a06c27dcf49ada62eb2b",
    ),
    (
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "b0e20b6e3116640286ed3a87a5713079b21f5189",
    ),
    (b"1234567890" * 8, "9b752e45573d4b39f4dbd3323cab82bf63326bfb"),
)

# each vector by the length of its message, in bytes
_IDS = [f"{len(message)} bytes" for message, _ in _VECTORS]

# the seed of the generated inputs, fixed so that two runs compare the
# same inputs
_SEED = 160


def _generated() -> list[bytes]:
    """Return the inputs the two implementations are compared on.

    Every length up to two blocks and a few bytes, so that both places
    the padding spills into a second block are reached, and random
    lengths up to sixteen blocks.
    """
    rng = random.Random(_SEED)
    lengths = [*range(136), *(rng.randrange(1024) for _ in range(8))]
    return [rng.randbytes(n) for n in lengths]


@pytest.mark.parametrize("message, digest", _VECTORS, ids=_IDS)
def test_the_pure_python_function_answers_the_reference(
    message: bytes, digest: str
) -> None:
    """The pure-Python function reproduces the published vectors."""
    assert pure_python_ripemd160(message).hex() == digest


@pytest.mark.parametrize("message, digest", _VECTORS, ids=_IDS)
def test_the_selected_function_answers_the_reference(
    message: bytes, digest: str
) -> None:
    """What the package hashes with reproduces them too."""
    assert ripemd160(message).hex() == digest


def test_the_empty_digest_is_the_reference() -> None:
    """`select` trusts OpenSSL on this one digest, so it is the reference's."""
    assert EMPTY_DIGEST.hex() == _VECTORS[0][1]


def test_openssl_and_python_agree() -> None:
    """OpenSSL's RIPEMD-160 and the Python one agree on generated inputs.

    Where the interpreter's OpenSSL has no RIPEMD-160, `select` answers
    the Python function, and the comparison is of that function with
    itself.
    """
    openssl = select(hashlib.new)
    for data in _generated():
        assert openssl(data) == pure_python_ripemd160(data), len(data)


def test_hash160_is_ripemd160_of_sha256() -> None:
    """HASH160 of the generator's compressed encoding is BIP173's key hash.

    BIP173's examples use that key, the public key of the private key 1,
    and its P2WPKH address carries this hash.
    """
    # repo    bitcoin/bips
    # path    bip-0173.mediawiki
    # commit  b34d9f751791d4feb22feff4f2ed00bcac83961b
    # blob    5bcc4a5255bc85c78f3a4abaa7f4782f8acf6477
    generator = bytes.fromhex(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )
    assert hash160(generator).hex() == "751e76e8199196d454941c45d1b3a323f1433bd6"


def test_an_invalid_round_number_is_refused() -> None:
    """`fi` is called with 0 to 4, and says so of anything else.

    Upstream ends the chain with `assert False`: this is the same
    unreachable line, reached on purpose.
    """
    for i in (5, -1):
        with pytest.raises(CoinAddressesValueError, match=f"invalid round number: {i}"):
            fi(0, 0, 0, i)


@dataclass
class _Answer:
    """What a stand-in for `hashlib.new` returns."""

    value: bytes

    def digest(self) -> bytes:
        """Return the digest the stand-in was built to answer."""
        return self.value


def _refusing(name: str, data: bytes) -> _Answer:
    """Refuse the name, as `hashlib.new` does without the algorithm."""
    raise ValueError(f"unsupported hash type {name}")


def _wrong(name: str, data: bytes) -> _Answer:
    """Answer a digest that is not RIPEMD-160's, as a broken provider would."""
    return _Answer(hashlib.sha256(data).digest()[:20])


def _right(name: str, data: bytes) -> _Answer:
    """Answer RIPEMD-160, computed by the Python function."""
    return _Answer(pure_python_ripemd160(data))


def test_select_falls_back_where_the_name_is_refused() -> None:
    """An interpreter without the algorithm gets the Python function."""
    assert select(_refusing) is pure_python_ripemd160


def test_select_falls_back_where_the_digest_is_wrong() -> None:
    """A provider answering the name with another digest is not used."""
    assert select(_wrong) is pure_python_ripemd160


def test_select_takes_a_provider_that_answers_right() -> None:
    """A provider answering the known digest is what the package calls."""
    selected = select(_right)
    assert selected is not pure_python_ripemd160
    assert selected(b"cc" * 70) == pure_python_ripemd160(b"cc" * 70)


def test_the_module_selects_at_import() -> None:
    """`ripemd160` is what `select` answers for the interpreter's hashlib."""
    selected = select(hashlib.new)
    assert (ripemd160 is pure_python_ripemd160) is (selected is pure_python_ripemd160)
    assert _hashes.__all__ == []
