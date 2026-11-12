# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for Keccak-256, both the pure-Python one and OpenSSL's.

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

from coin_addresses import _keccak
from coin_addresses._keccak import (
    EMPTY_DIGEST,
    RATE,
    keccak_256,
    pure_python_keccak_256,
    select,
)

# transcribed from the Keccak team's ShortMsgKAT_256, the entries whose
# message is 0, 1, 2, RATE - 1, RATE and RATE + 1 bytes long, as message
# and digest in hex:
#
# repo    Legrandin/pycryptodome
# path    test_vectors/pycryptodome_test_vectors/Hash/keccak/ShortMsgKAT_256.txt
# commit  bae38d8d881d1610309217e0a1661098aa1af858
# blob    15a1ba0bb6ed037f1eea40c192da6332c6b6ffb8
#
# The readme.txt beside that file says it comes from the Keccak team's
# KeccakKAT-3.zip, and its entries are the byte-aligned ones of that
# archive's file of the same name
_KAT = (
    (
        "",
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
    ),
    (
        "cc",
        "eead6dbfc7340a56caedc044696a168870549a6a7f6f56961e84a54bd9970b8a",
    ),
    (
        "41fb",
        "a8eaceda4d47b3281a795ad9e1ea2122b407baf9aabcb9e18b5717b7873537d2",
    ),
    (
        (
            "b771d5cef5d1a41a93d15643d7181d2a2ef0a8e84d91812f20ed21f147bef732"
            "bf3a60ef4067c3734b85bc8cd471780f10dc9e8291b58339a677b960218f71e7"
            "93f2797aea349406512829065d37bb55ea796fa4f56fd8896b49b2cd19b43215"
            "ad967c712b24e5032d065232e02c127409d2ed4146b9d75d763d52db98d949d3"
            "b0fed6a8052fbb"
        ),
        "bd6f5492582a7c1b116304de28314df9fffe95b0da11af52fe9440a717a34859",
    ),
    (
        (
            "b32d95b0b9aad2a8816de6d06d1f86008505bd8c14124f6e9a163b5a2ade55f8"
            "35d0ec3880ef50700d3b25e42cc0af050ccd1be5e555b23087e04d7bf9813622"
            "780c7313a1954f8740b6ee2d3f71f768dd417f520482bd3a08d4f222b4ee9dbd"
            "015447b33507dd50f3ab4247c5de9a8abd62a8decea01e3b87c8b927f5b08beb"
            "37674c6f8e380c04"
        ),
        "e717a7769448abbe5fef8187954a88ac56ded1d22e63940ab80d029585a21921",
    ),
    (
        (
            "04410e31082a47584b406f051398a6abe74e4da59bb6f85e6b49e8a1f7f2ca00"
            "dfba5462c2cd2bfde8b64fb21d70c083f11318b56a52d03b81cac5eec29eb31b"
            "d0078b6156786da3d6d8c33098c5c47bb67ac64db14165af65b44544d806dde5"
            "f487d5373c7f9792c299e9686b7e5821e7c8e2458315b996b5677d926dac57b3"
            "f22da873c601016a0d"
        ),
        "a95d50b50b4545f0947441df74a1e9d74622eb3baa49c1bbfc3a0cce6619c1aa",
    ),
)

# each vector by the length of its message, in bytes
_IDS = [f"{len(message) // 2} bytes" for message, _ in _KAT]

# the seed of the generated inputs, fixed so that two runs compare the
# same inputs
_SEED = 20261112


def _generated() -> list[bytes]:
    """Return the inputs the two implementations are compared on.

    Every length from 0 to one block and one byte, so that each place the
    padding can fall in a block is reached, the lengths around two blocks,
    and random lengths up to four blocks.
    """
    rng = random.Random(_SEED)
    lengths = [
        *range(RATE + 2),
        *range(2 * RATE - 1, 2 * RATE + 2),
        *(rng.randrange(4 * RATE) for _ in range(8)),
    ]
    return [rng.randbytes(n) for n in lengths]


def test_the_generated_inputs_reach_the_rate() -> None:
    """The lengths around the rate, and the empty input, are among them."""
    lengths = {len(data) for data in _generated()}
    assert {0, RATE - 1, RATE, RATE + 1, 2 * RATE, 2 * RATE + 1} <= lengths


@pytest.mark.parametrize("message, digest", _KAT, ids=_IDS)
def test_the_pure_python_function_answers_the_reference(
    message: str, digest: str
) -> None:
    """The pure-Python function reproduces the Keccak team's vectors."""
    assert pure_python_keccak_256(bytes.fromhex(message)).hex() == digest


@pytest.mark.parametrize("message, digest", _KAT, ids=_IDS)
def test_the_selected_function_answers_the_reference(message: str, digest: str) -> None:
    """What the package hashes with reproduces them too."""
    assert keccak_256(bytes.fromhex(message)).hex() == digest


def test_the_empty_digest_is_the_reference() -> None:
    """`select` trusts OpenSSL on this one digest, so it is the reference's."""
    assert EMPTY_DIGEST.hex() == _KAT[0][1]


def test_openssl_and_python_agree() -> None:
    """OpenSSL's Keccak-256 and the Python one agree on generated inputs.

    Where the interpreter's OpenSSL has no Keccak-256, `select` answers
    the Python function, and the comparison is of that function with
    itself.
    """
    openssl = select(hashlib.new)
    for data in _generated():
        assert openssl(data) == pure_python_keccak_256(data), len(data)


def test_sha3_256_is_another_function() -> None:
    """FIPS 202's padding gives another digest: hence `_keccak`."""
    assert hashlib.sha3_256(b"").digest() != EMPTY_DIGEST


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
    """Answer a digest that is not Keccak-256's, as a broken provider would."""
    return _Answer(hashlib.sha3_256(data).digest())


def _right(name: str, data: bytes) -> _Answer:
    """Answer Keccak-256, computed by the Python function."""
    return _Answer(pure_python_keccak_256(data))


def test_select_falls_back_where_the_name_is_refused() -> None:
    """An interpreter without the algorithm gets the Python function."""
    assert select(_refusing) is pure_python_keccak_256


def test_select_falls_back_where_the_digest_is_wrong() -> None:
    """A provider answering the name with another digest is not used."""
    assert select(_wrong) is pure_python_keccak_256


def test_select_takes_a_provider_that_answers_right() -> None:
    """A provider answering the known digest is what the package calls."""
    selected = select(_right)
    assert selected is not pure_python_keccak_256
    assert selected(b"cc" * 70) == pure_python_keccak_256(b"cc" * 70)


def test_the_module_selects_at_import() -> None:
    """`keccak_256` is what `select` answers for the interpreter's hashlib."""
    selected = select(hashlib.new)
    assert (keccak_256 is pure_python_keccak_256) is (
        selected is pure_python_keccak_256
    )
    assert _keccak.__all__ == []
