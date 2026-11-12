# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for Ethereum addresses: the derivation, EIP-55, the validation."""

from __future__ import annotations

import random

import pytest
from ecc.curves import PreparedPoint, bytes_from_point, mult, secp256k1

from coin_addresses import evm
from coin_addresses.evm import (
    address_from_pub_key,
    assert_valid_address,
    is_valid_address,
)
from coin_addresses.exceptions import CoinAddressesTypeError, CoinAddressesValueError

from .secret_free import assert_secret_free

# transcribed from the Test Cases of EIP-55, where each is an address in
# its checksum case:
#
# repo    ethereum/ERCs
# path    ERCS/erc-55.md
# commit  f44b973ba9b76e7fdee4d7ec15f74556e9fa4ce9
# blob    325a70f9683ef06b76e6e526c4526af5c9b5b69b
#
# The first two are the ones it heads "All caps", the next two "All
# Lower", the last four "Normal"
_EIP55 = (
    "0x52908400098527886E0F7030069857D2E4169EE7",
    "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
    "0xde709f2102306220921060314715629080e2fb77",
    "0x27b1fdb04752bbc536007a920d24acb045561c26",
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
    "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
)

# a private key and the address go-ethereum derives from it, in the
# lower case go-ethereum writes it in, `testPrivHex` and `testAddrHex`:
#
# repo    ethereum/go-ethereum
# path    crypto/crypto_test.go
# commit  4721b2cc765495073d9745995616b36b06480824
# blob    0636427a4fbaf0cc6782db3c2b887c99cb8de123
_GETH_PRV_KEY = 0x289C2857D4598E37FB9647507E47A309D6133539BF21A8B9CB6DF88FD5232032
_GETH_ADDRESS = "0x970e8128ab834e8eac17ab8e3812f010678cf791"

_GETH_POINT = mult(_GETH_PRV_KEY, secp256k1.G, secp256k1)

# the seed of the generated keys, fixed so that two runs ask the same
_SEED = 55


def _spellings(point: tuple[int, int]) -> list[object]:
    """Return every spelling of one public key `address_from_pub_key` reads."""
    compressed = bytes_from_point(point, secp256k1)
    uncompressed = bytes_from_point(point, secp256k1, compressed=False)
    return [
        point,
        PreparedPoint(point),
        compressed,
        compressed.hex(),
        uncompressed,
        uncompressed.hex(),
        bytearray(uncompressed),
        memoryview(compressed),
    ]


@pytest.mark.parametrize("address", _EIP55)
def test_the_checksum_is_eip55s(address: str) -> None:
    """Each EIP-55 test case is the checksum spelling of its own digits."""
    assert evm._checksum_encode(bytes.fromhex(address[2:])) == address
    assert is_valid_address(address)


def test_a_known_key_gives_its_address() -> None:
    """go-ethereum's test key gives go-ethereum's address."""
    address = address_from_pub_key(_GETH_POINT)
    assert address.lower() == _GETH_ADDRESS
    assert is_valid_address(address)


@pytest.mark.parametrize("spelling", range(len(_spellings(_GETH_POINT))))
def test_every_spelling_of_a_key_gives_one_address(spelling: int) -> None:
    """A point and its SEC encodings, compressed or not, are one key."""
    key = _spellings(_GETH_POINT)[spelling]
    assert address_from_pub_key(key).lower() == _GETH_ADDRESS  # type: ignore[arg-type]


def test_the_derivation_holds_over_generated_keys() -> None:
    """Derived addresses are valid, and a case flipped is caught.

    A property over keys from a fixed seed: the address of a key is valid
    in its own case and in one case, and a letter whose case is flipped
    fails the checksum. Every address of this seed is still in mixed case
    after the flip, which the assertion on `flipped` checks first: one in
    a single case would carry no checksum to fail.
    """
    rng = random.Random(_SEED)
    for _ in range(32):
        point = mult(rng.randrange(1, secp256k1.n), secp256k1.G, secp256k1)
        address = address_from_pub_key(point)
        assert is_valid_address(address)
        assert is_valid_address(address.lower())
        assert is_valid_address(f"0x{address[2:].upper()}")
        i = rng.choice([i for i, c in enumerate(address) if c in "abcdefABCDEF"])
        flipped = address[:i] + address[i].swapcase() + address[i + 1 :]
        assert flipped[2:] not in {flipped[2:].lower(), flipped[2:].upper()}
        assert not is_valid_address(flipped)


def test_validation_answers_every_string() -> None:
    """A property over strings from a fixed seed: each is answered.

    The strings are near-addresses: a prefix, right or wrong, and either
    40 lower-case hex digits or digits drawn from hex digits in both cases
    and characters that are not hex, at lengths around 40. None leaves
    `is_valid_address` as anything but a bool, and both answers come.
    """
    rng = random.Random(_SEED)
    alphabet = "0123456789abcdefABCDEF gGxX\uff10\n"
    answers = set()
    for _ in range(512):
        prefix = rng.choice(["0x", "0x", "0X", "", "x0"])
        body = "".join(rng.choices(alphabet[:16], k=40))
        if rng.random() < 0.5:
            body = "".join(rng.choices(alphabet, k=rng.randrange(36, 44)))
        answers.add(is_valid_address(prefix + body))
    assert answers == {True, False}


@pytest.mark.parametrize(
    "pub_key",
    [
        # a point off the curve
        (1, 2),
        # SEC encodings of no point: a compressed x with no point, a
        # prefix SEC does not define, and a length no encoding has
        b"\x02" + bytes(32),
        b"\x05" + bytes(32),
        bytes(64),
        # the hybrid encoding, prefix 0x06 or 0x07 by the parity of y, which
        # ecc reads only where asked to and this package does not ask
        bytes([6 + (_GETH_POINT[1] & 1)])
        + bytes_from_point(_GETH_POINT, secp256k1, compressed=False)[1:],
        "not hex",
    ],
)
def test_a_value_that_is_no_key_is_refused(pub_key: object) -> None:
    """A value of a key's type that is no point is a value error."""
    with pytest.raises(CoinAddressesValueError, match="not a public key") as caught:
        address_from_pub_key(pub_key)  # type: ignore[arg-type]
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


@pytest.mark.parametrize("pub_key", [None, 1, 1.5, [1, 2], ("a", "b")])
def test_a_value_of_no_key_type_is_refused(pub_key: object) -> None:
    """A value of no type a key has is a type error, ecc's not chained."""
    with pytest.raises(CoinAddressesTypeError, match="not a public key") as caught:
        address_from_pub_key(pub_key)  # type: ignore[arg-type]
    assert caught.value.__context__ is None


def test_a_refused_key_is_not_quoted() -> None:
    """A refusal of a would-be key prints none of it.

    Thirty-three bytes that are not a point may be an xprv's `00 || k`.
    """
    key = bytes.fromhex(
        "001d2f3e4d5c6b7a8998a7b6c5d4e3f20112233445566778899aabbccddeeff0a1"
    )
    for spelling in (key, key.hex()):
        with pytest.raises(CoinAddressesValueError) as caught:
            address_from_pub_key(spelling)
        assert_secret_free(caught.value, [key, key.hex()])


_ADDRESS = _EIP55[4]


@pytest.mark.parametrize(
    "address, reason",
    [
        ("", "no 0x prefix"),
        (_ADDRESS[2:], "no 0x prefix"),
        (f"0X{_ADDRESS[2:]}", "no 0x prefix"),
        ("0x", "0 characters after 0x, not 40"),
        (_ADDRESS[:-1], "39 characters after 0x, not 40"),
        (f"{_ADDRESS}0", "41 characters after 0x, not 40"),
        # the length is read before the digits, so no hex digit is named
        ("0xzz", "2 characters after 0x, not 40"),
        ("0x" + "g" * 41, "41 characters after 0x, not 40"),
        (f"{_ADDRESS[:-1]}g", "not a hex digit at position 41"),
        (f"0x {_ADDRESS[3:]}", "not a hex digit at position 2"),
        # a fullwidth digit is a digit to `str.isdigit`, and no hex digit
        (f"{_ADDRESS[:2]}\uff15{_ADDRESS[3:]}", "not a hex digit at position 2"),
        # the checksum's last letter in the other case
        (f"{_ADDRESS[:-1]}D", "wrong EIP-55 checksum"),
        (f"{_ADDRESS[:3]}A{_ADDRESS[4:]}", "wrong EIP-55 checksum"),
    ],
)
def test_a_malformed_address_is_refused(address: str, reason: str) -> None:
    """Each way an address is not one, and what the refusal says of it."""
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    assert str(caught.value) == reason
    assert not is_valid_address(address)
    if len(address) > 2:
        assert_secret_free(caught.value, [address[2:]])


@pytest.mark.parametrize(
    "address",
    [_ADDRESS.lower(), f"0x{_ADDRESS[2:].upper()}", "0x" + "0" * 40],
)
def test_an_address_in_one_case_carries_no_checksum(address: str) -> None:
    """All lower case, all upper case, or no letter: the form is checked."""
    assert_valid_address(address)
    assert is_valid_address(address)


@pytest.mark.parametrize("address", [None, b"0x" + bytes(40), 0, ["0x"]])
def test_an_address_of_no_string_type_is_refused(address: object) -> None:
    """A non-string is a caller's mistake, not an invalid address."""
    for check in (assert_valid_address, is_valid_address):
        with pytest.raises(CoinAddressesTypeError, match="not a string"):
            check(address)  # type: ignore[arg-type]
