# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for Tron addresses: the derivation, the validation."""

from __future__ import annotations

import random

import pytest
from base58_bech32.base58 import b58decode_check
from ecc.curves import PreparedPoint, bytes_from_point, mult, secp256k1

from coin_addresses import evm
from coin_addresses._bitcoin import base58_address
from coin_addresses.exceptions import CoinAddressesTypeError, CoinAddressesValueError
from coin_addresses.tron import (
    address_from_pub_key,
    assert_valid_address,
    is_valid_address,
)

from .secret_free import assert_secret_free

# a public key, uncompressed and compressed, and the 20 bytes of its
# address after the prefix, `pubString`, `compressedPubString` and
# `address`:
#
# repo    tronprotocol/java-tron
# path    framework/src/test/java/org/tron/common/crypto/ECKeyTest.java
# commit  b33eed89a6a424c498d4fb1b03ca2c86eddf4840
# blob    273672e8342239c96a90c750c1ef5501e85e0d3d
_JAVA_TRON_KEY = (
    "04e90c7d3640a1568839c31b70a893ab6714ef8415b9de90cedfc1c8f353a6983e62"
    "5529392df7fa514bdd65a2003f6619567d79bee89830e63e932dbd42362d34"
)
_JAVA_TRON_COMPRESSED_KEY = (
    "02e90c7d3640a1568839c31b70a893ab6714ef8415b9de90cedfc1c8f353a6983e"
)
_JAVA_TRON_HASH = "2e988a386a799f506693793c6a5af6b54dfaabfb"

# an address, its hex form and the Ethereum address of the same 20 bytes,
# the `TRON`, `TRON hex` and `EVM` lines of the first example:
#
# repo    tronprotocol/documentation-en
# path    docs/clients/wallet-cli/typescript/commands/encoding/convert.md
# commit  43931c1dfb7b824da32976ace8dad71f5bbb42d6
# blob    9a47759e1d6163fd568b7c61eb05617b4617a44c
_DOCS = (
    "TBhCfAytTEh52WFL6HYr64i2nmc3u3TCUp",
    "4112e94f5a3c88b17d2f6e0b9a45cd310f8e7a6d29",
    "0x12E94f5a3c88b17d2F6E0b9a45Cd310f8E7a6D29",
)

# public keys, the 20 bytes of each one's address and the address, from
# a library outside Tron's own, which derives them end to end: `TEST_VECT`
# and `TEST_VECT_DEC_INVALID` of
#
# repo    ebellocchia/bip_utils
# commit  286f03d36c80e1a7229d9586dd3651f5f73ba9b4
# path    tests/addr/test_trx_addr.py
# blob    5daaacfb2a384c67cc63a1a6c77bf65d1ecf31ef
_BIP_UTILS = (
    (
        "033d77bf3f63edd7aad3163c6f04eb48e968a76c3043def375c21a8414675e11ae",
        "2b6e3782fbedade9e4c05078f46a9e29841f0bbe",
        "TDvr6Jpwfp1wDiV7PhaB19YMsMHRSXmY7p",
    ),
    (
        "03436c3e77f7738dcbfc2cfbb6e12e1509979cde41f216eed86c82ab661b5b3fc0",
        "e9e9d3001799a9fa785bed8cf3a7995e8aebb8bd",
        "TXJ2Z9VAwDpQ4W6zwTpXxRUpwFVDetPQuC",
    ),
    (
        "02f6cd3a2761360cd7e8c183aca501ee0ce0e42fc270a68aafd153dd06c857a8c4",
        "8ae776b9997f92f90a25a156423918e751496db5",
        "TNdfXv6WTTyS2ohkTu8YA62WmLTNWqK46i",
    ),
    (
        "0360e11323f918ade5a53bd5ac7171712f019f62e9ad8e0e18ec2b8ca01d4daba4",
        "386fd4b1ad845ca6495e45544acf2b32f25f45d2",
        "TF7cowibxyJdMyGtjP2yP7oyN5ZmSMPnWd",
    ),
    (
        "034767fb943ddb893377754ba71e4f82ec15134c7fe4240529d3d0ff473650b210",
        "f616473322599b7cb664e438e7264dbb06996336",
        "TYQPvAG6AuzQed8RPuH62pcbZBKj9TkPk1",
    ),
)
_BIP_UTILS_INVALID = (
    ("T94nw3xoTjXXqBzLNUwmYhLovg4nNVZKB6", "unknown version byte: 64"),
    ("TLc6WnRN9DxA4uygPrHGr9A1DhVMxx2w45", "invalid checksum"),
    ("6w9cP3taF7zAsCtmViHprBoiiK68GnrsC", "19-byte hash for version byte 65"),
    ("319DKUdrbDY8tXmD2xWfQW5aJ3akX7ytypnG", "21-byte hash for version byte 65"),
)

# the prefix, `ADD_PRE_FIX_BYTE_MAINNET` of the Constant.java the module's
# docstring cites
_PREFIX = 0x41

# the seed of the generated keys, fixed so that two runs ask the same
_SEED = 2018


@pytest.mark.parametrize("pub_key", [_JAVA_TRON_KEY, _JAVA_TRON_COMPRESSED_KEY])
def test_a_key_of_java_tron_gives_its_address(pub_key: str) -> None:
    """java-tron's test key, in either encoding, gives java-tron's bytes."""
    address = address_from_pub_key(pub_key)
    assert b58decode_check(address) == bytes([_PREFIX]) + bytes.fromhex(_JAVA_TRON_HASH)
    assert is_valid_address(address)


def test_an_address_of_trons_documentation_is_valid() -> None:
    """The documentation's address carries its hex form and the EVM bytes."""
    address, hex_form, evm_address = _DOCS
    assert_valid_address(address)
    assert b58decode_check(address).hex() == hex_form
    assert hex_form[2:] == evm_address[2:].lower()
    assert evm.is_valid_address(evm_address)


@pytest.mark.parametrize("pub_key, digest, address", _BIP_UTILS)
def test_a_key_gives_the_address_another_library_derives(
    pub_key: str, digest: str, address: str
) -> None:
    """The derivation, against an independent one, and the decoding."""
    assert address_from_pub_key(pub_key) == address
    assert base58_address(_PREFIX, bytes.fromhex(digest)) == address
    assert_valid_address(address)


@pytest.mark.parametrize("address, reason", _BIP_UTILS_INVALID)
def test_an_invalid_string_of_another_library_is_refused(
    address: str, reason: str
) -> None:
    """Each invalid string is refused, and the refusal does not quote it."""
    assert not is_valid_address(address)
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    assert str(caught.value) == reason
    assert_secret_free(caught.value, [address])


def test_the_derivation_holds_over_generated_keys() -> None:
    """A property over keys from a fixed seed.

    Each address is valid, 34 characters with a leading T as Tron's
    documentation says, carries the bytes of the key's Ethereum address,
    and every spelling of the key gives it.
    """
    rng = random.Random(_SEED)
    for _ in range(16):
        point = mult(rng.randrange(1, secp256k1.n), secp256k1.G, secp256k1)
        address = address_from_pub_key(point)
        assert len(address) == 34
        assert address.startswith("T")
        assert is_valid_address(address)
        evm_bytes = bytes.fromhex(evm.address_from_pub_key(point)[2:])
        assert b58decode_check(address) == bytes([_PREFIX]) + evm_bytes
        compressed = bytes_from_point(point, secp256k1)
        uncompressed = bytes_from_point(point, secp256k1, compressed=False)
        for spelling in (
            compressed,
            compressed.hex(),
            uncompressed,
            uncompressed.hex(),
            PreparedPoint(point),
        ):
            assert address_from_pub_key(spelling) == address


@pytest.mark.parametrize(
    "address, reason",
    [
        (base58_address(_PREFIX, bytes(32)), "32-byte hash for version byte 65"),
        # bitcoin's P2PKH version byte, before the 20 bytes of an address
        (base58_address(0, bytes(20)), "unknown version byte: 0"),
        ("0OIl", "Base58 string contains invalid characters"),
    ],
)
def test_an_address_of_another_shape_is_refused(address: str, reason: str) -> None:
    """Each way a Base58Check string is not a Tron address."""
    assert not is_valid_address(address)
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    assert str(caught.value) == reason


@pytest.mark.parametrize("pub_key", [(1, 2), b"\x02" + bytes(32), "not hex"])
def test_a_value_that_is_no_key_is_refused(pub_key: object) -> None:
    """A value of a key's type that is no point is a value error."""
    with pytest.raises(CoinAddressesValueError, match="not a public key") as caught:
        address_from_pub_key(pub_key)  # type: ignore[arg-type]
    assert caught.value.__context__ is None


@pytest.mark.parametrize("pub_key", [None, 1, [1, 2]])
def test_a_value_of_no_key_type_is_refused(pub_key: object) -> None:
    """A value of no type a key has is a type error, ecc's not chained."""
    with pytest.raises(CoinAddressesTypeError, match="not a public key") as caught:
        address_from_pub_key(pub_key)  # type: ignore[arg-type]
    assert caught.value.__context__ is None


def test_a_refused_key_is_not_quoted() -> None:
    """A refusal of a would-be key prints none of it."""
    key = bytes.fromhex(
        "001d2f3e4d5c6b7a8998a7b6c5d4e3f20112233445566778899aabbccddeeff0a1"
    )
    for spelling in (key, key.hex()):
        with pytest.raises(CoinAddressesValueError) as caught:
            address_from_pub_key(spelling)
        assert_secret_free(caught.value, [key, key.hex()])


@pytest.mark.parametrize("address", [None, b"T", 0, ["T"]])
def test_an_address_of_no_string_type_is_refused(address: object) -> None:
    """A non-string is a caller's mistake, not an invalid address."""
    for check in (assert_valid_address, is_valid_address):
        with pytest.raises(CoinAddressesTypeError, match="not a string"):
            check(address)  # type: ignore[arg-type]
