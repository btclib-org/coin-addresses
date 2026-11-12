# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for Cosmos Hub addresses: the derivation, the validation."""

from __future__ import annotations

import random

import pytest
from base58_bech32.base58 import b58decode_check
from base58_bech32.bech32 import (
    BECH32_1_CONST,
    BECH32_M_CONST,
    bech32_decode_bytes,
    bech32_encode_bytes,
)
from ecc.curves import PreparedPoint, bytes_from_point, mult, secp256k1

from coin_addresses._hashes import hash160
from coin_addresses.cosmos import (
    address_from_pub_key,
    assert_valid_address,
    is_valid_address,
)
from coin_addresses.exceptions import CoinAddressesTypeError, CoinAddressesValueError

from .secret_free import assert_secret_free

# public keys of the SDK's test mnemonic and the address of each,
# `expectedPubKeys` and `expectedAddrs` of `TestPublicKeyHDPath`:
#
# repo    cosmos/cosmos-sdk
# path    crypto/ledger/ledger_test.go
# commit  102db7cd8c9ade54b770e0f2eea1ca597fa97ed3
# blob    4ef44ab59cc6c9a5418a2fb5375ee391c721615b
_LEDGER = (
    (
        "034FEF9CD7C4C63588D3B03FEB5281B9D232CBA34D6F3D71AEE59211FFBFE1FE87",
        "cosmos1w34k53py5v5xyluazqpq65agyajavep2rflq6h",
    ),
    (
        "0260D0487A3DFCE9228EEE2D0D83A40F6131F551526C8E52066FE7FE1E4A509666",
        "cosmos19ewxwemt6uahejvwf44u7dh6tq859tkyvarh2q",
    ),
    (
        "03A2670393D02B162D0ED06A08041E80D86BE36C0564335254DF7462447EB69AB3",
        "cosmos1a07dzdjgjsntxpp75zg7cgatgq0udh3pcdcxm3",
    ),
    (
        "033222FC61795077791665544A90740E8EAD638A391A3B8F9261F4A226B396C042",
        "cosmos1qvw52lmn9gpvem8welghrkc52m3zczyhlqjsl7",
    ),
    (
        "03F577473348D7B01E7AF2F245E36B98D181BC935EC8B552CDE5932B646DC7BE04",
        "cosmos17m78ka80fqkkw2c4ww0v4xm5nsu2drgrlm8mn2",
    ),
    (
        "0222B1A5486BE0A2D5F3C5866BE46E05D1BDE8CDA5EA1C4C77A9BC48D2FA2753BC",
        "cosmos1ferh9ll9c452d2p8k2v7heq084guygkn43up9e",
    ),
    (
        "0377A1C826D3A03CA4EE94FC4DEA6BCCB2BAC5F2AC0419A128C29F8E88F1FF295A",
        "cosmos10vf3sxmjg96rqq36axcphzfsl74dsntuehjlw5",
    ),
    (
        "031B75C84453935AB76F8C8D0B6566C3FCC101CC5C59D7000BFC9101961E9308D9",
        "cosmos1cq83av8cmnar79h0rg7duh9gnr7wkh228a7fxg",
    ),
    (
        "038905A42433B1D677CC8AFD36861430B9A8529171B0616F733659F131C3F80221",
        "cosmos1dszhfrt226jy5rsre7e48vw9tgwe90uerfyefa",
    ),
    (
        "038BE7F348902D8C20BC88D32294F4F3B819284548122229DECD1ADF1A7EB0848B",
        "cosmos1734d7qsylzrdt05muhqqtpd90j8mp4y6rzch8l",
    ),
)

# public keys and the bytes of each one's address, which the SDK's test
# writes in Base58Check, `pub` and `addr` of `secpDataTable`. Its test
# reads the 20 bytes after the first, and so does this one: the first,
# a version byte, is not the same in every entry
#
# repo    cosmos/cosmos-sdk
# path    crypto/keys/secp256k1/secp256k1_test.go
# commit  102db7cd8c9ade54b770e0f2eea1ca597fa97ed3
# blob    e20df03da12ce0cb6604d80728205b0413245770
_SECP_DATA = (
    (
        "02950e1cdfcb133d6024109fd489f734eeb4502418e538c28481f22bce276f248c",
        "1CKZ9Nx4zgds8tU7nJHotKSDr4a9bYJCa3",
    ),
    (
        "0285592121e2a5e0eb970a1a9d1879c5fa7b33badf7dbb61c44b1bfced94649efb",
        "1Q4mWVk2hotRVDEdGGtGf6waz622rEwvib",
    ),
    (
        "02f5bf88d72172cc2f9a52919b6b1b74a01ca606cad75d5f4f93aa1a6ff0374aaf",
        "1KtiSApteeKdLi5cdZVpnkNW1t5Eteksvf",
    ),
    (
        "028f3003b3e6cb40897138dba5858207357a6d116cc5bf556c942cf6081b58d5fe",
        "RnM1o5grgCHAmm45wt5vzGsQoCJdPK2n2",
    ),
    (
        "022f8e4e07ae2705a3c425eafea16027041bcdc87a193b01ea6c36c1c7a0bfc300",
        "16MpKTksSpGABuHqMqU9RPBz26DfwY8cLY",
    ),
    (
        "033c2f6ea7a678f0afbb43d0fe7a2b2706a75c2fdea08c3b90fd038c8219b42959",
        "18iz5wdTdwzq6cGzoVhooZCPRAx61GfUMR",
    ),
    (
        "03ad9e97842d0f6f57804f29f55aac9bba207d2b24b98aaabc7d106250389e6d46",
        "1K31NqmdMBZiLeUiP4kfjLNnWSmx17a9aE",
    ),
    (
        "03d681bb11e5ebc14d5d2f72881cb0b2a693ef12bc72fe863f980fc6542eafbd40",
        "1K29nsfH6qwmE3MzsoHpLcWLA4mQLstGgx",
    ),
)

# public keys, the bytes of each one's address and the address, from a
# library outside Cosmos's own, which derives them end to end: `TEST_VECT`
# and `TEST_VECT_DEC_INVALID` of
#
# repo    ebellocchia/bip_utils
# commit  286f03d36c80e1a7229d9586dd3651f5f73ba9b4
# path    tests/addr/test_atom_addr.py
# blob    fb1b2f973ab4b44e0d90da310df6f3024b31a3b8
_BIP_UTILS = (
    (
        "039cb22e5c6ce15e06b76d5725dcf084b87357d926dcdfeeb20d628d3d11ff543b",
        "165c9dab1586b8ca42a323ad0037333b584ed5db",
        "cosmos1zewfm2c4s6uv5s4rywksqden8dvya4wmqyyvek",
    ),
    (
        "02dc27af24c0fc6b448519e17d4ac6078f158a766bbf8446cb16c61a9e53835c3c",
        "9eb88dffa323736f58ee87c5c25290ca569cf90a",
        "cosmos1n6ugmlarydek7k8wslzuy55seftfe7g2aqncw3",
    ),
)
# the entries of other chains, each the key's hash with that chain's HRP
_BIP_UTILS_OTHER_HRPS = (
    (
        "0356ab0a0717738c794caf972ee2091762525a35d062c881b863733f06f445c585",
        "d4f22d7dab7883aa9c48b1d0aea68f55684792d2",
        "band16nez6ldt0zp648zgk8g2af50245y0ykjutc2k9",
    ),
    (
        "02b19f4692195f95a8d919edf245d64993bce60bb3c50e4226ba5311686ccf60da",
        "d762167cf2da4f5e3079cdbc5dafb490cfffef13",
        "band16a3pvl8jmf84uvreek79mta5jr8llmcn4ptgy2",
    ),
    (
        "0356ab0a0717738c794caf972ee2091762525a35d062c881b863733f06f445c585",
        "d4f22d7dab7883aa9c48b1d0aea68f55684792d2",
        "kava16nez6ldt0zp648zgk8g2af50245y0ykje3v4c2",
    ),
    (
        "02b19f4692195f95a8d919edf245d64993bce60bb3c50e4226ba5311686ccf60da",
        "d762167cf2da4f5e3079cdbc5dafb490cfffef13",
        "kava16a3pvl8jmf84uvreek79mta5jr8llmcnsmlh29",
    ),
    (
        "02ec5dc71723f11e8ed7ae054f1c09110e849edfa491118d161473b78d72cc4813",
        "e191b92395ce7fa4ed5f99ce8cc744792a22bf0a",
        "iaa1uxgmjgu4eel6fm2ln88ge36y0y4z90c2knr3d6",
    ),
    (
        "02dc27af24c0fc6b448519e17d4ac6078f158a766bbf8446cb16c61a9e53835c3c",
        "9eb88dffa323736f58ee87c5c25290ca569cf90a",
        "iaa1n6ugmlarydek7k8wslzuy55seftfe7g2gznfvq",
    ),
    (
        "03de159b5635abfdb91b6ae3bf57317d3ecc4eb7a734ef72cc18f307e83359b854",
        "5811db8a383d0d589d88cde9e16a2383eb885ff8",
        "terra1tqgahz3c85x438vgeh57z63rs04cshlcx5ga4z",
    ),
    (
        "033e444813a45a334240087619ffc73e626db10454738e08dbdfc71741fb44af26",
        "32db6a56c4fb538b3e92c95bdcca87c9fdcc99e2",
        "terra1xtdk54kyldfck05je9daej58e87uex0zk47rz5",
    ),
    (
        "0223d645338396fdbce2d754a14568537d52deb76e1addb940994868feef9c5994",
        "fba4d69d5c95520bf0f303a8d2d0a3b92143b718",
        "bnb1lwjdd82uj4fqhu8nqw5d959rhys58dccv9aalj",
    ),
    (
        "03ebbc8a33683fa9d40f4da3b870784d7f66911eec4d464993c2b80d891d452f93",
        "d5beb4d04fb2371df8d555e3af68d9bac3f7ab10",
        "bnb16kltf5z0kgm3m7x42h3676xehtpl02csg7f3qc",
    ),
)
_BIP_UTILS_INVALID = (
    ("cosmis1pgmhz30d29akc670hkaje398hl6hvh0c5w0gly", "not the Cosmos HRP"),
    ("cosmoszewfm2c4s6uv5s4rywksqden8dvya4wmqyyvek", "no separator character"),
    ("cosmos19c3mc3hp8y624tae0mfnmxse9h49kv2pqltkj0", "invalid checksum"),
    ("cosmos1lwjdb82uj4fqhu8nqw5d959rhys58dccwpz37u", "invalid data character"),
)
# bip_utils refuses these as not 20 bytes; the SDK takes 1 to 255
_BIP_UTILS_OTHER_SIZES = (
    ("cosmos15ntf6hy42g9lpucr4rfdpgaey9pmwxq3al8gd", 19),
    ("cosmos1zx807pf53fgwnhnu6du3xvsqk6yruz7adepaaz6q0szyp57m63hqpwdtkp", 32),
)

# `Bech32MainPrefix` of the address.go the module's docstring cites
_HRP = "cosmos"

# the seed of the generated keys, fixed so that two runs ask the same
_SEED = 2019


def _bech32(hrp: str, payload: bytes, m: int = BECH32_1_CONST) -> str:
    """Return the bech32 string of an HRP and a payload."""
    return bech32_encode_bytes(hrp, payload, m=m).decode("ascii")


@pytest.mark.parametrize("pub_key, address", _LEDGER)
def test_a_key_of_the_sdk_gives_its_address(pub_key: str, address: str) -> None:
    """The SDK's test keys give the SDK's addresses."""
    assert address_from_pub_key(pub_key) == address
    assert address_from_pub_key(pub_key.lower()) == address
    assert is_valid_address(address)


@pytest.mark.parametrize("pub_key, legacy", _SECP_DATA)
def test_a_key_of_the_sdk_gives_its_bytes(pub_key: str, legacy: str) -> None:
    """The SDK's test keys give the 20 bytes its test reads."""
    hrp, payload = bech32_decode_bytes(address_from_pub_key(pub_key), m=BECH32_1_CONST)
    assert hrp == _HRP
    assert payload == b58decode_check(legacy)[1:]


@pytest.mark.parametrize("pub_key, digest, address", _BIP_UTILS)
def test_a_key_gives_the_address_another_library_derives(
    pub_key: str, digest: str, address: str
) -> None:
    """The derivation, against an independent one, and the decoding."""
    assert address_from_pub_key(pub_key) == address
    assert _bech32(_HRP, bytes.fromhex(digest)) == address
    assert_valid_address(address)


@pytest.mark.parametrize("pub_key, digest, address", _BIP_UTILS_OTHER_HRPS)
def test_another_chains_address_is_refused(
    pub_key: str, digest: str, address: str
) -> None:
    """The key gives the same bytes under `cosmos`, and the HRP is refused."""
    assert address_from_pub_key(pub_key) == _bech32(_HRP, bytes.fromhex(digest))
    assert not is_valid_address(address)
    with pytest.raises(CoinAddressesValueError, match="not the Cosmos HRP"):
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


@pytest.mark.parametrize("address, size", _BIP_UTILS_OTHER_SIZES)
def test_an_address_of_another_size_is_valid(address: str, size: int) -> None:
    """The SDK takes an address of any size from 1 to 255 bytes."""
    hrp, payload = bech32_decode_bytes(address, m=BECH32_1_CONST)
    assert (hrp, len(payload)) == (_HRP, size)
    assert is_valid_address(address)


def test_the_derivation_holds_over_generated_keys() -> None:
    """A property over keys from a fixed seed.

    Each address is valid, starts with the HRP, carries the HASH160 of the
    compressed encoding, and every spelling of the key but the
    uncompressed one gives it.
    """
    rng = random.Random(_SEED)
    for _ in range(16):
        point = mult(rng.randrange(1, secp256k1.n), secp256k1.G, secp256k1)
        compressed = bytes_from_point(point, secp256k1)
        address = address_from_pub_key(point)
        assert address == _bech32(_HRP, hash160(compressed))
        assert address.startswith("cosmos1")
        assert is_valid_address(address)
        assert is_valid_address(address.upper())
        for spelling in (compressed, compressed.hex(), PreparedPoint(point)):
            assert address_from_pub_key(spelling) == address


@pytest.mark.parametrize("size", [1, 20, 32, 255])
def test_an_address_of_1_to_255_bytes_is_valid(size: int) -> None:
    """The bounds of the SDK's `VerifyAddressFormat`, and sizes within."""
    assert is_valid_address(_bech32(_HRP, bytes(size)))


@pytest.mark.parametrize(
    "address, reason",
    [
        (_bech32(_HRP, b""), "no address bytes"),
        (_bech32(_HRP, bytes(256)), "256-byte address, more than 255"),
        (
            _bech32(_HRP, bytes(20), BECH32_M_CONST),
            "invalid checksum: BECH32_M_CONST verifies",
        ),
        # the SDK's validator operator address of the same bytes
        (_bech32("cosmosvaloper", bytes(20)), "not the Cosmos HRP"),
        ("cosmos1" + "q" * 1017, "too many bech32 characters: 1024, limit is 1023"),
        ("Cosmos1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", "mixed case"),
    ],
)
def test_an_address_of_another_shape_is_refused(address: str, reason: str) -> None:
    """Each way a string is not a Cosmos Hub address."""
    assert not is_valid_address(address)
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    assert str(caught.value) == reason


def test_an_uncompressed_key_is_refused() -> None:
    """The SDK hashes the compressed encoding alone: refused."""
    point = mult(1, secp256k1.G, secp256k1)
    uncompressed = bytes_from_point(point, secp256k1, compressed=False)
    for spelling in (uncompressed, uncompressed.hex()):
        with pytest.raises(CoinAddressesValueError, match="uncompressed public key"):
            address_from_pub_key(spelling)


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


@pytest.mark.parametrize("address", [None, b"cosmos1", 0, ["cosmos1"]])
def test_an_address_of_no_string_type_is_refused(address: object) -> None:
    """A non-string is a caller's mistake, not an invalid address."""
    for check in (assert_valid_address, is_valid_address):
        with pytest.raises(CoinAddressesTypeError, match="not a string"):
            check(address)  # type: ignore[arg-type]
