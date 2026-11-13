# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for Stellar account addresses: the derivation, the validation."""

from __future__ import annotations

import random
from array import array

import pytest
from base58_bech32.strkey import strkey_decode

from coin_addresses.exceptions import CoinAddressesTypeError, CoinAddressesValueError
from coin_addresses.stellar import (
    address_from_pub_key,
    assert_valid_address,
    is_valid_address,
)

from .secret_free import assert_secret_free

# SEP-0023's tests: the key of its first valid case and that case, its
# other valid cases, each with the version byte it is refused for here,
# then its invalid cases, each with the reason it is refused here:
#
# repo    stellar/stellar-protocol
# path    ecosystem/sep-0023.md
# commit  f2d364902615af726b3533021403c8b225aa6e5d
# blob    743ee270df82d2138d43c99f6c7849f76ab82339
_SEP_KEY = "3f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a"
_SEP_ACCOUNT = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"
_SEP_MUXED = (
    "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ",
    "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK",
)
_SEP_OTHER = (
    ("PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAQACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6IBZGM", 120),
    ("PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAOQCAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUAAAAFGBU", 120),
    ("CA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUWDA", 16),
    ("LA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUPJN", 88),
    ("BAAD6DBUX6J22DMZOHIEZTEQ64CVCHEDRKWZONFEUL5Q26QD7R76RGR4TU", 8),
    ("WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAWWC", 176),
    ("WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAACWJY", 176),
)  # fmt: skip
_SEP_INVALID = (
    ("GAAAAAAAACGC6", "5-byte key, not 32"),
    ("MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUR", "invalid strkey: unused bits not zero"),
    ("GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZA", "invalid strkey length: 57 characters"),
    ("GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUACUSI", "33-byte key, not 32"),
    ("G47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVP2I", "not an account's version byte: 55"),
    ("MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLKA", "invalid strkey length: 70 characters"),
    ("MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAAV75I", "muxed account, not supported"),
    ("M47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ", "invalid strkey checksum"),
    ("MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUK===", "invalid strkey character"),
    ("MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUO", "invalid strkey checksum"),
    ("PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAQACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6IAAAAAAAAPM", "not an account's version byte: 120"),
    ("PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAOQCAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4Z2PQ", "not an account's version byte: 120"),
    ("PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAOQCAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DXFH6", "not an account's version byte: 120"),
    ("BAAD6DBUX6J22DMZOHIEZTEQ64CVCHEDRKWZONFEUL5Q26QD7R76RGR4TV", "invalid strkey: unused bits not zero"),
    ("BAAT6DBUX6J22DMZOHIEZTEQ64CVCHEDRKWZONFEUL5Q26QD7R76RGXACA", "not an account's version byte: 8"),
    ("WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAWWD", "invalid strkey: unused bits not zero"),
    ("WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAWWCA", "invalid strkey length: 70 characters"),
    ("WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAAIOUI", "not an account's version byte: 176"),
    ("W47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAADXHW", "not an account's version byte: 183"),
    ("WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAWWA", "invalid strkey checksum"),
)  # fmt: skip

# a key and its account, derived end to end from a seed by
# `Keypair.fromRawEd25519Seed`, then read back by `Keypair.fromPublicKey`:
#
# repo    stellar/js-stellar-base
# path    test/unit/keypair_test.js
# commit  6ad55f781139898ade2bbb54987c268af0d6ecb6
# blob    a195615e09c4bc23e54d2607b5f05c8bc7b5a6f0
_JS_KEYPAIR = (
    "2e3c35010749c1de3d9a5bdd6a31c12458768da5ce87cca6aad63ebbaaef7432",
    "GAXDYNIBA5E4DXR5TJN522RRYESFQ5UNUXHIPTFGVLLD5O5K552DF5ZH",
)

# the accounts `isValidEd25519PublicKey` takes, then the strings it
# refuses but `null`, each with the reason it is refused here. The
# secret seed among them is the first key `isValidSecretKey` takes:
#
# repo    stellar/js-stellar-base
# path    test/unit/strkey_test.js
# commit  6ad55f781139898ade2bbb54987c268af0d6ecb6
# blob    91c5998e40f2720f807617f14f4b3c5ede84e495
_JS_VALID = (
    "GBBM6BKZPEHWYO3E3YKREDPQXMS4VK35YLNU7NFBRI26RAN7GI5POFBB",
    "GB7KKHHVYLDIZEKYJPAJUOTBE5E3NJAXPSDZK7O6O44WR3EBRO5HRPVT",
    "GD6WVYRVID442Y4JVWFWKWCZKB45UGHJAABBJRS22TUSTWGJYXIUR7N2",
    "GBCG42WTVWPO4Q6OZCYI3D6ZSTFSJIXIS6INCIUF23L6VN3ADE4337AP",
    "GDFX463YPLCO2EY7NGFMI7SXWWDQAMASGYZXCG2LATOF3PP5NQIUKBPT",
    "GBXEODUMM3SJ3QSX2VYUWFU3NRP7BQRC2ERWS7E2LZXDJXL2N66ZQ5PT",
    "GAJHORKJKDDEPYCD6URDFODV7CVLJ5AAOJKR6PG2VQOLWFQOF3X7XLOG",
    "GACXQEAXYBEZLBMQ2XETOBRO4P66FZAJENDHOQRYPUIXZIIXLKMZEXBJ",
    "GDD3XRXU3G4DXHVRUDH7LJM4CD4PDZTVP4QHOO4Q6DELKXUATR657OZV",
    "GDTYVCTAUQVPKEDZIBWEJGKBQHB4UGGXI2SXXUEW7LXMD4B7MK37CWLJ",
)
_JS_SEED = "SAB5556L5AN5KSR5WF7UOEFDCIODEWEO7H2UR4S5R62DFTQOGLKOVZDY"
_JS_INVALID = (
    ("GBPXX0A5N4JYPESHAADMQKBPWZWQDQ64ZV6ZL2S3LAGW4SY7NTCMWIVL", "invalid strkey character"),
    ("GCFZB6L25D26RQFDWSSBDEYQ32JHLRMTT44ZYE3DZQUTYOL7WY43PLBG++", "invalid strkey character"),
    ("GADE5QJ2TY7S5ZB65Q43DFGWYWCPHIYDJ2326KZGAGBN7AE5UY6JVDRRA", "invalid strkey length: 57 characters"),
    ("GB6OWYST45X57HCJY5XWOHDEBULB6XUROWPIKW77L5DSNANBEQGUPADT2", "invalid strkey length: 57 characters"),
    ("GB6OWYST45X57HCJY5XWOHDEBULB6XUROWPIKW77L5DSNANBEQGUPADT2T", "invalid strkey: unused bits not zero"),
    ("GDXIIZTKTLVYCBHURXL2UPMTYXOVNI7BRAEFQCP6EZCY4JLKY4VKFNLT", "invalid strkey checksum"),
    (_JS_SEED, "not an account's version byte: 144"),
    ("gWRYUerEKuz53tstxEuR3NCkiQDcV4wzFHmvLnZmj7PUqxW2wt", "invalid strkey character"),
    ("test", "invalid strkey character"),
    ("g4VPBPrHZkfE8CsjuG2S4yBQNd455UWmk", "invalid strkey character"),
)  # fmt: skip

# the strkeys of 32 zero bytes and of 32 bytes of 0xFF
_ZERO = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
_ONES = "GD7777777777777777777777777777777777777777777777777773DB"

# the seed of the generated keys, fixed so that two runs ask the same
_SEED = 2020


def test_the_key_of_sep_0023_gives_its_account() -> None:
    """SEP-0023's valid account, from every spelling of its key."""
    key = bytes.fromhex(_SEP_KEY)
    for spelling in (key, bytearray(key), memoryview(key), _SEP_KEY, _SEP_KEY.upper()):
        assert address_from_pub_key(spelling) == _SEP_ACCOUNT
    assert_valid_address(_SEP_ACCOUNT)


@pytest.mark.parametrize("address", _SEP_MUXED)
def test_a_muxed_account_is_refused(address: str) -> None:
    """SEP-0023's valid muxed accounts are out of scope, refused by name.

    Each writes SEP-0023's account key, then its 64-bit id.
    """
    version, payload = strkey_decode(address)
    assert version == 12 << 3
    assert payload[:32].hex() == _SEP_KEY
    assert not is_valid_address(address)
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    assert str(caught.value) == "muxed account, not supported"


@pytest.mark.parametrize("address, version", _SEP_OTHER)
def test_a_strkey_of_another_type_is_refused(address: str, version: int) -> None:
    """Each other valid strkey of SEP-0023 is refused for its version byte."""
    assert not is_valid_address(address)
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    assert str(caught.value) == f"not an account's version byte: {version}"


@pytest.mark.parametrize("address, reason", _SEP_INVALID)
def test_a_strkey_sep_0023_refuses_is_refused(address: str, reason: str) -> None:
    """Each invalid case of SEP-0023, with the reason it is refused here.

    The reason is compared whole, so it is known to quote no address.
    """
    assert not is_valid_address(address)
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    assert str(caught.value) == reason
    assert caught.value.__context__ is None


def test_a_key_gives_the_account_js_stellar_base_derives() -> None:
    """The derivation, against js-stellar-base's keypair, and the decoding."""
    key, address = _JS_KEYPAIR
    assert address_from_pub_key(key) == address
    assert strkey_decode(address) == (6 << 3, bytes.fromhex(key))
    assert_valid_address(address)


@pytest.mark.parametrize("address", _JS_VALID)
def test_an_account_js_stellar_base_takes_is_valid(address: str) -> None:
    """Each account `isValidEd25519PublicKey` takes, re-derived from its key."""
    assert is_valid_address(address)
    assert address_from_pub_key(strkey_decode(address)[1]) == address


@pytest.mark.parametrize("address, reason", _JS_INVALID)
def test_a_string_js_stellar_base_refuses_is_refused(address: str, reason: str) -> None:
    """Each string `isValidEd25519PublicKey` refuses, unquoted."""
    assert not is_valid_address(address)
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    assert str(caught.value) == reason
    assert_secret_free(caught.value, [address])


def test_the_extreme_keys_give_their_accounts() -> None:
    """32 zero bytes and 32 bytes of 0xFF, the first and the last key."""
    assert address_from_pub_key(bytes(32)) == _ZERO
    assert address_from_pub_key(b"\xff" * 32) == _ONES
    assert is_valid_address(_ZERO)
    assert is_valid_address(_ONES)


def test_the_derivation_holds_over_generated_keys() -> None:
    """A property over keys from a fixed seed.

    Each address is valid, has 56 characters, starts with `G` and decodes
    to the key, and every spelling of the key gives it.
    """
    rng = random.Random(_SEED)
    for _ in range(64):
        key = rng.randbytes(32)
        address = address_from_pub_key(key)
        assert len(address) == 56
        assert address.startswith("G")
        assert is_valid_address(address)
        assert strkey_decode(address) == (6 << 3, key)
        for spelling in (bytearray(key), memoryview(key), key.hex()):
            assert address_from_pub_key(spelling) == address


@pytest.mark.parametrize(
    "address",
    [
        f" {_SEP_ACCOUNT}",
        f"{_SEP_ACCOUNT}\n",
        "",
        _SEP_ACCOUNT.lower(),
        f"{_SEP_ACCOUNT}=",
    ],
)
def test_an_address_of_another_shape_is_refused(address: str) -> None:
    """Whitespace, the empty string, lowercase and padding are refused."""
    assert not is_valid_address(address)


@pytest.mark.parametrize(
    "pub_key",
    [
        bytes(31),
        bytes(33),
        "not hex",
        _SEP_KEY[:-1],
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


def test_a_released_view_is_refused_by_the_package() -> None:
    """A released view, which answers every read with a bare ValueError."""
    view = memoryview(bytes(32))
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
    key = bytes.fromhex(_JS_KEYPAIR[0]) + b"\x01"
    for spelling in (key, key.hex()):
        with pytest.raises(CoinAddressesValueError) as caught:
            address_from_pub_key(spelling)
        assert_secret_free(caught.value, [key, key.hex()])


@pytest.mark.parametrize("address", [None, _SEP_ACCOUNT.encode(), 0, ["G"]])
def test_an_address_of_no_string_type_is_refused(address: object) -> None:
    """A non-string is a caller's mistake, not an invalid address."""
    for check in (assert_valid_address, is_valid_address):
        with pytest.raises(CoinAddressesTypeError, match="not a string"):
            check(address)  # type: ignore[arg-type]
