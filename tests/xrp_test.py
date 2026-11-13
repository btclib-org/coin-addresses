# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for XRP Ledger classic addresses: the derivation, the validation."""

from __future__ import annotations

import random

import pytest
from base58_bech32.base58 import (
    BITCOIN_ALPHABET,
    RIPPLE_ALPHABET,
    b58decode_check,
    b58encode_check,
)
from ecc.curves import PreparedPoint, bytes_from_point, mult, secp256k1

from coin_addresses._bitcoin import base58_address
from coin_addresses._hashes import hash160
from coin_addresses.exceptions import CoinAddressesTypeError, CoinAddressesValueError
from coin_addresses.xrp import (
    address_from_pub_key,
    assert_valid_address,
    is_valid_address,
)

from .secret_free import assert_secret_free

# the key and the address of the genesis account, `public_key_hex` and
# `account_id` of the response example:
#
# repo    XRPLF/xrpl-dev-portal
# path    docs/references/http-websocket-apis/admin-api-methods/
#         key-generation-methods/wallet_propose.md
# commit  182f8d20b157aa791433ff399a0f30dbed74a5eb
# blob    c2e5edd0cfadedb086c1b7bd8b4f399b81016e21
_GENESIS_KEY = "0330E7FC9D56BB25D6893BA3F317AE5BCF33B3291BD63DB32654A313222F7FD020"
_GENESIS = "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh"

# the same account's key, in the XRP Ledger's base58 `AccountPublic`
# encoding, and its address, both of the secp256k1 account keypair of
# `masterpassphrase`; then the Ed25519 keypair's key:
#
# repo    XRPLF/rippled
# path    src/test/protocol/Seed_test.cpp
# commit  00e640751460c137636fdb6dae6b4280de355d81
# blob    ef4719fd3eb2ddb963db4ce0d91600bb4b4bd93b
_RIPPLED_KEY = "aBQG8RQAzjs1eTKFEAQXr2gS4utcDiEC9wmi7pfUPTi27VCahwgw"
_RIPPLED_ED25519_KEY = "aKGheSBjmCsKJVuLNKRAKpZXT6wpk2FCuEZAXJupXgdAxX5THCqR"
# `TokenType::AccountPublic`, the type prefix of that encoding
_ACCOUNT_PUBLIC = 0x23

# the Ed25519 key of the address encoding example and the address the
# example prints, then the blackhole addresses of the table, each with
# the number it decodes to:
#
# repo    XRPLF/xrpl-dev-portal
# path    docs/concepts/accounts/addresses.md
# commit  182f8d20b157aa791433ff399a0f30dbed74a5eb
# blob    cbf6b694f3b45d5a50a55670501badf6243662ba
_DOCS_ED25519_KEY = "ED9434799226374926EDA3B54B1B461B4ABF7237962EAE18528FEA67595397FA32"
_DOCS_ED25519 = "rDTXLQ7ZKZVKz33zJbHjgVShjsBnqMBhmN"
_DOCS_SPECIAL = (
    ("rrrrrrrrrrrrrrrrrrrrrhoLvTp", 0),
    ("rrrrrrrrrrrrrrrrrrrrBZbvji", 1),
    ("rrrrrrrrrrrrrrrrrNAMEtxvNvQ", 0x16FC69D),
    ("rrrrrrrrrrrrrrrrrrrn5RM1rHd", 0x977),
)

# a secp256k1 key and its address, and an Ed25519 key, of
#
# repo    XRPLF/xrpl.js
# path    packages/ripple-keypairs/test/fixtures/api.json
# commit  0ce90e29186139036018bac23b7b3ef2596dd990
# blob    13c81652b9f0881d727b9630c834d9c56c711c01
_XRPL_JS = (
    "030D58EB48B4420B1F7B9DF55087E0E29FEF0E8468F9A6825B01CA2C361042D435",
    "rU6K7V3Po4snVhBBaU29sesqs2qTQJWDw1",
)
_XRPL_JS_ED25519_KEY = (
    "ED01FA53FA5A7E77798F882ECE20B1ABC00BB358A9E55A202D0D0676BD0CE37A63"
)

# a classic address, then its X-address on the main network and on the
# test network, of the first case of
#
# repo    XRPLF/xrpl-py
# path    tests/unit/core/addresscodec/test_main_test_cases.py
# commit  45dfa3b8624579caa9b0e4d9c3544cca283a208c
# blob    8be698a9f7615c6865712a301e111c8d0b90b105
_XRPL_PY = (
    "r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59",
    "X7AcgcsBL6XDcUb289X4mJ8djcdyKaB5hJDWMArnXr61cqZ",
    "T719a5UwUCnEs54UsxG9CJYYDhwmFCqkr7wxCcNcfZ6p5GZ",
)

# public keys, the 20 bytes of each one's address and the address, from
# a library outside the XRP Ledger's own, which derives them end to end:
# `TEST_VECT` and `TEST_VECT_DEC_INVALID` of
#
# repo    ebellocchia/bip_utils
# commit  286f03d36c80e1a7229d9586dd3651f5f73ba9b4
# path    tests/addr/test_xrp_addr.py
# blob    07d7ed974f7c351cb28ab45df820835499bfb0ad
_BIP_UTILS = (
    (
        "03db0da69187edd94aba300f1b2e7a09f407a8301d6fff54322a6ee4dde9842681",
        "6d52060b65ae90a77e6d00b98ce4a3773767573d",
        "rwypvr27pYpzYQyDrFQBjDUhRDkHiecTHo",
    ),
    (
        "03333f37539bf526280cea9dda98758de4feb15910218e3e0a99ac17d1f5fac406",
        "db05b585a44a1f3421facdf2aee1985c655513f2",
        "rLynFggnosDyDmoLzcgX6siu6X4yUBb36a",
    ),
    (
        "02553f6711f6ed3e1204dff91d9bf259ea01a2577dcc05383ce47f2cc5a98946bc",
        "c2357c3ea1e67dd76dff6d8f470362c3e0fa86b3",
        "rJ6twS2cq28qMybswjQHb6BZK7kuwSFfZo",
    ),
    (
        "03530f281debbda165f54090b930c4467842231c3bd2e547d953444c7409ad4c20",
        "21739c244b9ce0e243e8bc2686b2b94565cdd771",
        "rhs1osifPgg35Ff8pRk23vRtn6rhivVuTq",
    ),
    (
        "021cf750242895325d49efa12859369f7a45e9c3f5639172e4f2f5df4ae23301cf",
        "17149e5478f9df3f45b3f6d33e21333943fc2b31",
        "rsfsErX3u9GRrMH1Nr6Qa4TAyWa53bx48D",
    ),
)
_BIP_UTILS_INVALID = (
    ("RGdwNmqegTAkWXoRparJCuCyEB1y91Dex", "unknown version byte: 1"),
    ("rApB37YAWrhAnP5PbkgFYdtLjvAGTie8d", "invalid checksum"),
    ("rp9RDD4mjenCdVHjpdbf2wXyq32y8pJeV", "19-byte hash for version byte 0"),
    ("rnfSB6zbyZrJMgPEgkPFkidoc3VhNwy6mxS", "21-byte hash for version byte 0"),
)

# `TokenType::AccountID`, of the tokens.h the module's docstring cites
_PREFIX = 0x00

# the seed of the generated keys, fixed so that two runs ask the same
_SEED = 2012


def _ripple(digest: bytes) -> str:
    """Return the classic address of a hash, written apart from the module."""
    payload = bytes([_PREFIX]) + digest
    return b58encode_check(payload, alphabet=RIPPLE_ALPHABET).decode("ascii")


def _bitcoin(address: str) -> str:
    """Return the Bitcoin P2PKH address of a classic address's bytes."""
    payload = b58decode_check(address, alphabet=RIPPLE_ALPHABET)
    return b58encode_check(payload, alphabet=BITCOIN_ALPHABET).decode("ascii")


@pytest.mark.parametrize("pub_key", [_GENESIS_KEY, _GENESIS_KEY.lower()])
def test_the_key_of_the_documentation_gives_its_address(pub_key: str) -> None:
    """wallet_propose's genesis key gives the genesis address."""
    assert address_from_pub_key(pub_key) == _GENESIS
    assert address_from_pub_key(bytes.fromhex(pub_key)) == _GENESIS
    assert is_valid_address(_GENESIS)


def test_the_key_of_rippled_gives_its_address() -> None:
    """The test key of rippled is the documentation's: same address."""
    payload = b58decode_check(_RIPPLED_KEY, alphabet=RIPPLE_ALPHABET)
    assert payload[0] == _ACCOUNT_PUBLIC
    assert payload[1:] == bytes.fromhex(_GENESIS_KEY)
    assert address_from_pub_key(payload[1:]) == _GENESIS


def test_the_key_of_xrpl_js_gives_its_address() -> None:
    """xrpl.js's secp256k1 fixture, which xrpl-py's tests share."""
    pub_key, address = _XRPL_JS
    assert address_from_pub_key(pub_key) == address


@pytest.mark.parametrize("address, number", _DOCS_SPECIAL)
def test_a_special_address_of_the_documentation_is_valid(
    address: str, number: int
) -> None:
    """Each blackhole address is valid, and decodes to its number.

    The table gives the numbers of ACCOUNT_ZERO and ACCOUNT_ONE, 0 and 1;
    the others' are the ones they decode to.
    """
    assert_valid_address(address)
    assert address == _ripple(number.to_bytes(20, "big"))


def test_the_ed25519_example_of_the_documentation() -> None:
    """Its address is valid, and is the hash of the key's 33 bytes.

    rippled's `calcAccountID` hashes an Ed25519 key with its 0xED byte, as
    the example does; the module refuses that key, which the next test
    asserts.
    """
    key = bytes.fromhex(_DOCS_ED25519_KEY)
    assert_valid_address(_DOCS_ED25519)
    assert _ripple(hash160(key)) == _DOCS_ED25519


@pytest.mark.parametrize(
    "pub_key",
    [
        _DOCS_ED25519_KEY,
        _DOCS_ED25519_KEY.lower(),
        bytes.fromhex(_DOCS_ED25519_KEY),
        bytearray.fromhex(_XRPL_JS_ED25519_KEY),
        memoryview(bytes.fromhex(_XRPL_JS_ED25519_KEY)),
        b58decode_check(_RIPPLED_ED25519_KEY, alphabet=RIPPLE_ALPHABET)[1:],
    ],
)
def test_an_ed25519_key_is_refused(pub_key: str | bytes) -> None:
    """An Ed25519 key is refused by name, unquoted and unchained."""
    with pytest.raises(CoinAddressesValueError, match="Ed25519") as caught:
        address_from_pub_key(pub_key)
    assert caught.value.__context__ is None
    octets = bytes.fromhex(pub_key) if isinstance(pub_key, str) else bytes(pub_key)
    assert_secret_free(caught.value, [octets, octets.hex()])


@pytest.mark.parametrize("pub_key, digest, address", _BIP_UTILS)
def test_a_key_gives_the_address_another_library_derives(
    pub_key: str, digest: str, address: str
) -> None:
    """The derivation, against an independent one, and the decoding."""
    assert address_from_pub_key(pub_key) == address
    assert _ripple(bytes.fromhex(digest)) == address
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
    assert caught.value.__context__ is None
    assert_secret_free(caught.value, [address])


def test_an_x_address_is_refused() -> None:
    """Both networks' X-addresses of a valid classic address are refused."""
    classic, main_net, test_net = _XRPL_PY
    assert is_valid_address(classic)
    for address, version in ((main_net, 5), (test_net, 4)):
        assert not is_valid_address(address)
        with pytest.raises(CoinAddressesValueError) as caught:
            assert_valid_address(address)
        assert str(caught.value) == f"unknown version byte: {version}"


def test_the_derivation_holds_over_generated_keys() -> None:
    """A property over keys from a fixed seed.

    Each address is valid, starts with r and has at most 35 characters, as
    the documentation's base58 encodings table says, carries the HASH160 of
    the compressed encoding, and is the Bitcoin P2PKH address of the same
    bytes, each character carried to Ripple's alphabet. Every spelling of
    the key but the uncompressed one gives it.
    """
    to_ripple = str.maketrans(BITCOIN_ALPHABET.decode(), RIPPLE_ALPHABET.decode())
    rng = random.Random(_SEED)
    for _ in range(16):
        point = mult(rng.randrange(1, secp256k1.n), secp256k1.G, secp256k1)
        compressed = bytes_from_point(point, secp256k1)
        address = address_from_pub_key(point)
        assert address == _ripple(hash160(compressed))
        assert address.startswith("r")
        assert len(address) <= 35
        assert is_valid_address(address)
        assert address == base58_address(
            0, hash160(compressed), alphabet=BITCOIN_ALPHABET
        ).translate(to_ripple)
        for spelling in (compressed, compressed.hex(), PreparedPoint(point)):
            assert address_from_pub_key(spelling) == address


@pytest.mark.parametrize(
    "address, reason",
    [
        (_ripple(bytes(32)), "32-byte hash for version byte 0"),
        # the genesis account's bytes, in Bitcoin's alphabet
        (_bitcoin(_GENESIS), "invalid checksum"),
        # rippled's `AccountPublic` encoding of a key is not an address
        (_RIPPLED_KEY, "unknown version byte: 35"),
        ("0OIl", "Base58 string contains invalid characters"),
    ],
)
def test_an_address_of_another_shape_is_refused(address: str, reason: str) -> None:
    """Each way a string is not a classic address."""
    assert not is_valid_address(address)
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    assert str(caught.value) == reason


def test_an_uncompressed_key_is_refused() -> None:
    """The XRP Ledger's secp256k1 key is the compressed encoding alone."""
    point = mult(1, secp256k1.G, secp256k1)
    uncompressed = bytes_from_point(point, secp256k1, compressed=False)
    for spelling in (uncompressed, uncompressed.hex()):
        with pytest.raises(CoinAddressesValueError, match="uncompressed public key"):
            address_from_pub_key(spelling)


@pytest.mark.parametrize(
    "pub_key", [(1, 2), b"\x02" + bytes(32), "not hex", b"\xed" + bytes(31)]
)
def test_a_value_that_is_no_key_is_refused(pub_key: object) -> None:
    """A value of a key's type that is no point is a value error.

    0xED before 31 bytes is no Ed25519 key, and is refused as no key.
    """
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


@pytest.mark.parametrize("address", [None, b"r", 0, ["r"]])
def test_an_address_of_no_string_type_is_refused(address: object) -> None:
    """A non-string is a caller's mistake, not an invalid address."""
    for check in (assert_valid_address, is_valid_address):
        with pytest.raises(CoinAddressesTypeError, match="not a string"):
            check(address)  # type: ignore[arg-type]
