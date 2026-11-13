# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for Solana addresses: the derivation, the validation."""

from __future__ import annotations

import random
from array import array

import pytest
from base58_bech32.base58 import b58decode

from coin_addresses.exceptions import CoinAddressesTypeError, CoinAddressesValueError
from coin_addresses.solana import (
    address_from_pub_key,
    assert_valid_address,
    is_valid_address,
)

from .secret_free import assert_secret_free

# 32 bytes and their Base58, the example of `decode_32`, then the strings
# `test_decode_error_32` refuses, each with the size it decodes to here
# or the refusal of a character outside the alphabet:
#
# repo    kevinheavey/five8
# path    crates/five8/src/decode.rs
# commit  311279fb81461df36e730458a0463a6a322042d7
# blob    378b828eba384126fe3e3e29488d49e47991073b
_FIVE8 = (
    bytes(
        [
            24, 243, 6, 223, 230, 153, 210, 8, 92, 137, 123, 67, 164, 197, 79, 196,
            125, 43, 183, 85, 103, 91, 232, 167, 73, 131, 104, 131, 0, 101, 214, 231,
        ]
    ),
    "2gPihUTjt3FJqf1VpidgrY5cZ6PuyMccGVwQHRfjMPZG",
)  # fmt: skip
_FIVE8_INVALID = (
    ("1", "1-byte address, not 32"),
    ("1111111111111111111111111111111", "31-byte address, not 32"),
    ("4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJz", "29-byte address, not 32"),
    ("4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofL", "31-byte address, not 32"),
    (
        "4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofLRda4",
        "too many base58 characters: 47, max is 44",
    ),
    ("111111111111111111111111111111111", "33-byte address, not 32"),
    # the second-smallest 33-byte value that does not start with 0x00
    ("JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFJ", "33-byte address, not 32"),
    ("11aEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWx", "33-byte address, not 32"),
    ("11111111111111111111111111111110", "Base58 string contains invalid characters"),
    ("1111111111111111111111111111111!", "Base58 string contains invalid characters"),
    ("1111111111111111111111111111111I", "Base58 string contains invalid characters"),
    ("1111111111111111111111111111111O", "Base58 string contains invalid characters"),
    ("1111111111111111111111111111111_", "Base58 string contains invalid characters"),
    ("1111111111111111111111111111111l", "Base58 string contains invalid characters"),
    # `test_decode_unprintable_32`
    ("1" * 32 + "\x00\x01\x00\x00\x00\x00\x00\x7f", "Base58 string contains invalid characters"),
)  # fmt: skip

# program ids, the System Program's being the address of 32 zero bytes:
#
# repo    anza-xyz/solana-sdk
# path    sdk-ids/src/lib.rs
# commit  617887a6f8a306a6ca94b5907eaa3772db43a54b
# blob    d161bb2d4f5b5fb0fc054660145a502d77613895
_SYSTEM_PROGRAM = "11111111111111111111111111111111"
_PROGRAM_IDS = (
    _SYSTEM_PROGRAM,
    "AddressLookupTab1e1111111111111111111111111",
    "BPFLoaderUpgradeab1e11111111111111111111111",
    "ComputeBudget111111111111111111111111111111",
    "Ed25519SigVerify111111111111111111111111111",
    "1nc1nerator11111111111111111111111111111111",
    "Vote111111111111111111111111111111111111111",
)

# program derived addresses of `test_create_program_address`, each off the
# ed25519 curve:
#
# repo    anza-xyz/solana-sdk
# path    address/src/lib.rs
# commit  617887a6f8a306a6ca94b5907eaa3772db43a54b
# blob    b6824bf50e114bbaca932aa111cb810d76280c09
_PROGRAM_DERIVED = (
    "BwqrghZA2htAcqq8dzP1WDAhTXYTYWj7CHxF5j7TDBAe",
    "13yWmRpaTR4r5nAktwLqMpRNr28tnVUZw26rTvPSSB19",
    "2fnQrngrQT4SeLcdToJAD96phoEjNL2man2kfRLCASVk",
    "976ymqVnfE32QFe6NfGDctSvVa36LWnvYxhU6G2232YL",
)

# ed25519 public keys and their addresses, from a library outside
# Solana's own, which derives them end to end: `TEST_VECT`, its keys
# without the 0x00 byte that library writes before some of them, then
# `TEST_VECT_DEC_INVALID`:
#
# repo    ebellocchia/bip_utils
# path    tests/addr/test_sol_addr.py
# commit  286f03d36c80e1a7229d9586dd3651f5f73ba9b4
# blob    387e732c2a345bb24c4e6c9b159f4d953c3e6e25
_BIP_UTILS = (
    (
        "e9b6062841bb977ad21de71ec961900633c26f21384e015b014a637a61499547",
        "GjJyeC1r2RgkuoCWMyPYkCWSGSGLcz266EaAkLA27AhL",
    ),
    (
        "8b4564d4b6be05d6ead16d246c5e30773da9459040370284b57c944a3d0a1481",
        "ANf3TEKFL6jPWjzkndo4CbnNdUNkBk4KHPggJs2nu8Xi",
    ),
    (
        "dff41688eadfb8574c8fbfeb8707e07ecf571e96e929c395cc506839cc3ef832",
        "G5DnnAkA9jV3WZ25xh1Z6FcH3vtSyLi6p9nmPpr6dQMX",
    ),
    (
        "e54f392e5ffd3ca8802d3dbaa052667f82f8ff559a9cb23eda39cd386639c6ea",
        "GS8RquhotKk9sDguxzjg5sJPM8RhfmKXWNEW61Jzjvvu",
    ),
    (
        "6031798a9f0f4939c3335d313848437fe72aefbe0d700de3268a2d45cebedc7c",
        "7UVttrLkRkZFn4FsTuihX5zCJ1ounF5Ts8CkSqPGN2Dh",
    ),
)
# refused there as no public key: 32 bytes off the curve
_BIP_UTILS_OFF_CURVE = "F9vSypJrvid1y1ckLUJoT1Ke4R5TgeMiyoZdFKBAA91j"
_BIP_UTILS_INVALID = (
    ("kkqJgedV2iZeiLdU9qa8SFT5Zv13JRorbW87bjAnkb", "31-byte address, not 32"),
    (
        "17UVttrLkRkZFn4FsTuihX5zCJ1ounF5Ts8CkSqPGN2Dh",
        "too many base58 characters: 45, max is 44",
    ),
)

# the Base58 of 32 bytes of 0xFF: the longest address, 44 characters,
# `MAX_BASE58_LEN` of the solana-sdk file above
_LONGEST = "JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG"

# the seed of the generated keys, fixed so that two runs ask the same
_SEED = 2020


def test_the_bytes_of_five8_give_its_string() -> None:
    """The example of five8, the codec `Address` decodes with."""
    key, address = _FIVE8
    for spelling in (
        key,
        bytearray(key),
        memoryview(key),
        key.hex(),
        key.hex().upper(),
    ):
        assert address_from_pub_key(spelling) == address
    assert_valid_address(address)


@pytest.mark.parametrize("address, reason", _FIVE8_INVALID)
def test_a_string_five8_refuses_is_refused(address: str, reason: str) -> None:
    """Each string five8 refuses, with the reason it is refused here.

    The reason is compared whole, so it is known to quote no address.
    """
    assert not is_valid_address(address)
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    assert str(caught.value) == reason
    assert caught.value.__context__ is None


def test_the_system_program_is_the_address_of_zero_bytes() -> None:
    """Each leading zero byte is a leading 1."""
    assert address_from_pub_key(bytes(32)) == _SYSTEM_PROGRAM
    assert is_valid_address(_SYSTEM_PROGRAM)


@pytest.mark.parametrize("address", _PROGRAM_IDS + _PROGRAM_DERIVED)
def test_a_program_address_is_valid(address: str) -> None:
    """A program id, and a program derived address, off the curve."""
    assert is_valid_address(address)
    assert address_from_pub_key(b58decode(address)) == address


@pytest.mark.parametrize("pub_key, address", _BIP_UTILS)
def test_a_key_gives_the_address_another_library_derives(
    pub_key: str, address: str
) -> None:
    """The derivation, against an independent one, and the decoding."""
    assert address_from_pub_key(pub_key) == address
    assert b58decode(address) == bytes.fromhex(pub_key)
    assert_valid_address(address)


def test_an_address_off_the_curve_is_valid() -> None:
    """bip_utils refuses these 32 bytes as no ed25519 key; `Address` does not.

    An address is any 32 bytes, as a program derived address shows.
    """
    assert is_valid_address(_BIP_UTILS_OFF_CURVE)


@pytest.mark.parametrize("address, reason", _BIP_UTILS_INVALID)
def test_an_invalid_string_of_another_library_is_refused(
    address: str, reason: str
) -> None:
    """Each string of another size is refused, unquoted."""
    assert not is_valid_address(address)
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    assert str(caught.value) == reason
    assert_secret_free(caught.value, [address])


def test_the_longest_address_is_valid_and_one_more_character_is_not() -> None:
    """44 characters are decoded; 45 are refused before decoding."""
    assert address_from_pub_key(b"\xff" * 32) == _LONGEST
    assert is_valid_address(_LONGEST)
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(f"{_LONGEST}1")
    assert str(caught.value) == "too many base58 characters: 45, max is 44"


def test_the_derivation_holds_over_generated_keys() -> None:
    """A property over keys from a fixed seed.

    Each address is valid, has 32 to 44 characters and decodes to the key,
    and every spelling of the key gives it.
    """
    rng = random.Random(_SEED)
    for _ in range(64):
        key = rng.randbytes(32)
        address = address_from_pub_key(key)
        assert 32 <= len(address) <= 44
        assert is_valid_address(address)
        assert b58decode(address) == key
        for spelling in (bytearray(key), memoryview(key), key.hex()):
            assert address_from_pub_key(spelling) == address


@pytest.mark.parametrize(
    "address", [f" {_SYSTEM_PROGRAM}", f"{_SYSTEM_PROGRAM}\n", "", f"0x{'1' * 32}"]
)
def test_an_address_of_another_shape_is_refused(address: str) -> None:
    """Whitespace, the empty string and a prefix are refused."""
    assert not is_valid_address(address)


@pytest.mark.parametrize(
    "pub_key",
    [
        bytes(31),
        # the 0x00 byte bip_utils writes before a key
        b"\x00" + bytes.fromhex(_BIP_UTILS[0][0]),
        "not hex",
        _BIP_UTILS[0][0][:-1],
        memoryview(bytes(64))[::2],
        memoryview(array("I", bytes(32))),
        memoryview(bytes(32)).cast("b"),
    ],
)
def test_a_value_that_is_no_key_is_refused(pub_key: object) -> None:
    """A value of a key's type that is not 32 plain bytes is a value error."""
    with pytest.raises(CoinAddressesValueError, match="^not a public key$") as caught:
        address_from_pub_key(pub_key)  # type: ignore[arg-type]
    assert caught.value.__context__ is None


@pytest.mark.parametrize(
    "view",
    [memoryview(bytes(32)), memoryview(bytes(64))[::2]],
    ids=["plain", "strided"],
)
def test_a_released_view_is_refused_by_the_package(view: memoryview) -> None:
    """A released view, which answers every read with a bare ValueError."""
    view.release()
    with pytest.raises(CoinAddressesValueError, match="^not a public key$") as caught:
        address_from_pub_key(view)
    assert caught.value.__context__ is None


@pytest.mark.parametrize("pub_key", [None, 1, [1, 2], (1, 2)])
def test_a_value_of_no_key_type_is_refused(pub_key: object) -> None:
    """A value of no type a key has is a type error."""
    with pytest.raises(CoinAddressesTypeError, match="not a public key"):
        address_from_pub_key(pub_key)  # type: ignore[arg-type]


def test_a_refused_key_is_not_quoted() -> None:
    """A refusal of a would-be key prints none of it."""
    key = bytes.fromhex(_BIP_UTILS[1][0]) + b"\x01"
    for spelling in (key, key.hex()):
        with pytest.raises(CoinAddressesValueError) as caught:
            address_from_pub_key(spelling)
        assert_secret_free(caught.value, [key, key.hex()])


@pytest.mark.parametrize("address", [None, b"1" * 32, 0, ["1"]])
def test_an_address_of_no_string_type_is_refused(address: object) -> None:
    """A non-string is a caller's mistake, not an invalid address."""
    for check in (assert_valid_address, is_valid_address):
        with pytest.raises(CoinAddressesTypeError, match="not a string"):
            check(address)  # type: ignore[arg-type]
