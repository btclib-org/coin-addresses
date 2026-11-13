# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for eCash addresses: CashAddr and legacy, the validation."""

from __future__ import annotations

import random

import pytest
from base58_bech32.base58 import BITCOIN_ALPHABET, b58decode_check
from base58_bech32.cashaddr import cashaddr_decode, cashaddr_encode
from ecc.curves import PreparedPoint, bytes_from_point, mult, secp256k1

from coin_addresses._bitcoin import base58_address
from coin_addresses.ecash import (
    address_from_pub_key,
    assert_valid_address,
    is_valid_address,
    legacy_address_from_pub_key,
)
from coin_addresses.exceptions import CoinAddressesTypeError, CoinAddressesValueError

from .secret_free import assert_secret_free

# two private keys, as compressed WIF, and the legacy P2PKH address of
# each one's public key, `strSecret1C`, `strSecret2C`, `addr1C` and
# `addr2C`:
#
# repo    Bitcoin-ABC/bitcoin-abc
# path    src/test/key_tests.cpp
# commit  e726999f0be7f985bf014d2284a0b95a390c9f2b
# blob    1567118e82c55a5e0979a44b9a4c6657b59011dc
_KEY_TESTS = (
    (
        "Kwr371tjA9u2rFSMZjTNun2PXXP3WPZu2afRHTcta6KxEUdm1vEw",
        "1NoJrossxPBKfCHuJXT4HadJrXRE9Fxiqs",
    ),
    (
        "L3Hq7a8FEQwJkW1M2GNKDW28546Vp5miewcCzSqUD9kCAXrJdS3g",
        "1CRj2HyM1CXWzHAXLQtiGLyggNT9WQqsDs",
    ),
)
# the version byte of an eCash WIF, `SECRET_KEY` of the chainparams the
# module's docstring cites
_WIF_VERSION = 128

# three hashes, and the CashAddr P2PKH and P2SH addresses of each, from
# `test_encode_address`:
#
# repo    Bitcoin-ABC/bitcoin-abc
# path    src/test/cashaddrenc_tests.cpp
# commit  e726999f0be7f985bf014d2284a0b95a390c9f2b
# blob    28dbba16f66c3b9f80d5676c7f6e51e78fc55a22
_ENCODE_ADDRESS = (
    (
        bytes.fromhex("76a04053bda0a88bda5177b86a15c3b29f559873"),
        "ecash:qpm2qsznhks23z7629mms6s4cwef74vcwva87rkuu2",
        "ecash:ppm2qsznhks23z7629mms6s4cwef74vcwv2zrv3l8h",
    ),
    (
        bytes.fromhex("cb481232299cd5743151ac4b2d63ae198e7bb0a9"),
        "ecash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4ykdcjcn6n",
        "ecash:pr95sy3j9xwd2ap32xkykttr4cvcu7as4ypg9alspw",
    ),
    (
        bytes.fromhex("011f28e473c95f4013d7d53ec5fbc3b42df8ed10"),
        "ecash:qqq3728yw0y47sqn6l2na30mcw6zm78dzq653y7pv5",
        "ecash:pqq3728yw0y47sqn6l2na30mcw6zm78dzqd3vtezhf",
    ),
)
# from `test_vectors` of the same file: a Bitcoin Cash address, valid
# under its own prefix and refused here
_BITCOIN_CASH = "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2"

# the mainnet legacy addresses, and the scriptPubKey of each, that are no
# private key:
#
# repo    Bitcoin-ABC/bitcoin-abc
# path    src/test/data/key_io_valid.json
# commit  e726999f0be7f985bf014d2284a0b95a390c9f2b
# blob    175b297a1cac0eb62aa4dc7ee8fad121bfb0d2f7
_KEY_IO_VALID = (
    (
        "1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i",
        "76a91465a16059864a2fdbc7c99a4723a8395bc6f188eb88ac",
    ),
    (
        "3CMNFxN1oHBc4R1EpboAL5yzHGgE611Xou",
        "a91474f209f6ea907e2ea48f74fae05782ae8a66525787",
    ),
    (
        "1Ax4gZtb7gAit2TivwejZHYtNNLT18PUXJ",
        "76a9146d23156cbbdcc82a5a47eee4c2c7c583c18b6bf488ac",
    ),
    (
        "3QjYXhTkvuj8qPaXHTTWb5wjXhdsLAAWVy",
        "a914fcc5460dd6e2487c7d75b1963625da0e8f4c597587",
    ),
    (
        "1C5bSj1iEGUgSTbziymG7Cn18ENQuT36vv",
        "76a9147987ccaa53d02c8873487ef919677cd3db7a691288ac",
    ),
    (
        "3AnNxabYGoTxYiTEZwFEnerUoeFXK2Zoks",
        "a91463bcc565f9e68ee0189dd5cc67f1b0e5f02f45cb87",
    ),
    (
        "1Gqk4Tv79P91Cc1STQtU3s1W6277M2CVWu",
        "76a914adc1cc2081a27206fae25792f28bbc55b831549d88ac",
    ),
    (
        "33vt8ViH5jsr115AGkW6cEmEz9MpvJSwDk",
        "a914188f91a931947eddd7432d6e614387e32b24470987",
    ),
    (
        "1JwMWBVLtiqtscbaRHai4pqHokhFCbtoB4",
        "76a914c4c1b72491ede1eedaca00618407ee0b772cad0d88ac",
    ),
    (
        "3QCzvfL4ZRvmJFiWWBVwxfdaNBT8EtxB5y",
        "a914f6fe69bcb548a829cce4c57bf6fff8af3a5981f987",
    ),
    (
        "19dcawoKcZdQz365WpXWMhX6QCUpR9SY4r",
        "76a9145eadaf9bb7121f0f192561a5a62f5e5f5421029288ac",
    ),
    (
        "37Sp6Rv3y4kVd1nQ1JV5pfqXccHNyZm1x3",
        "a9143f210e7277c899c3a155cc1c90f4106cbddeec6e87",
    ),
    (
        "13p1ijLwsnrcuyqcTvJXkq2ASdXqcnEBLE",
        "76a9141ed467017f043e91ed4c44b4e8dd674db211c4e688ac",
    ),
    (
        "3ALJH9Y951VCGcVZYAdpA3KchoP9McEj1G",
        "a9145ece0cadddc415b1980f001785947120acdb36fc87",
    ),
)

# every string of the file, each invalid on every network:
#
# repo    Bitcoin-ABC/bitcoin-abc
# path    src/test/data/key_io_invalid.json
# commit  e726999f0be7f985bf014d2284a0b95a390c9f2b
# blob    9839c3ea07a2caf59c8e84bfe36a0d3992d97393
_KEY_IO_INVALID = (
    "",
    "x",
    "37qgekLpCCHrQuSjvX3fs496FWTGsHFHizjJAs6NPcR47aefnnCWECAhHV6E3g4YN7u7Yuwod5Y",
    "dzb7VV1Ui55BARxv7ATxAtCUeJsANKovDGWFVgpTbhq9gvPqP3yv",
    "MuNu7ZAEDFiHthiunm7dPjwKqrVNCM3mAz6rP9zFveQu14YA8CxExSJTHcVP9DErn6u84E6Ej7S",
    "rPpQpYknyNQ5AEHuY6H8ijJJrYc2nDKKk9jjmKEXsWzyAQcFGpDLU2Zvsmoi8JLR7hAwoy3RQWf",
    "4Uc3FmN6NQ6zLBK5QQBXRBUREaaHwCZYsGCueHauuDmJpZKn6jkEskMB2Zi2CNgtb5r6epWEFfUJq",
    "7aQgR5DFQ25vyXmqZAWmnVCjL3PkBcdVkBUpjrjMTcghHx3E8wb",
    "17QpPprjeg69fW1DV8DcYYCKvWjYhXvWkov6MJ1iTTvMFj6weAqW7wybZeH57WTNxXVCRH4veVs",
    "KxuACDviz8Xvpn1xAh9MfopySZNuyajYMZWz16Dv2mHHryznWUp3",
    "7nK3GSmqdXJQtdohvGfJ7KsSmn3TmGqExug49583bDAL91pVSGq5xS9SHoAYL3Wv3ijKTit65th",
    "cTivdBmq7bay3RFGEBBuNfMh2P1pDCgRYN2Wbxmgwr4ki3jNUL2va",
    "gjMV4vjNjyMrna4fsAr8bWxAbwtmMUBXJS3zL4NJt5qjozpbQLmAfK1uA3CquSqsZQMpoD1g2nk",
    "emXm1naBMoVzPjbk7xpeTVMFy4oDEe25UmoyGgKEB1gGWsK8kRGs",
    "7VThQnNRj1o3Zyvc7XHPRrjDf8j2oivPTeDXnRPYWeYGE4pXeRJDZgf28ppti5hsHWXS2GSobdqyo",
    "1G9u6oCVCPh2o8m3t55ACiYvG1y5BHewUkDSdiQarDcYXXhFHYdzMdYfUAhfxn5vNZBwpgUNpso",
    "31QQ7ZMLkScDiB4VyZjuptr7AEc9j1SjstF7pRoLhHTGkW4Q2y9XELobQmhhWxeRvqcukGd1XCq",
    "DHqKSnpxa8ZdQyH8keAhvLTrfkyBMQxqngcQA5N8LQ9KVt25kmGN",
    "2LUHcJPbwLCy9GLH1qXmfmAwvadWw4bp4PCpDfduLqV17s6iDcy1imUwhQJhAoNoN1XNmweiJP4i",
    "7USRzBXAnmck8fX9HmW7RAb4qt92VFX6soCnts9s74wxm4gguVhtG5of8fZGbNPJA83irHVY6bCos",
    "1DGezo7BfVebZxAbNT3XGujdeHyNNBF3vnficYoTSp4PfK2QaML9bHzAMxke3wdKdHYWmsMTJVu",
    "2D12DqDZKwCxxkzs1ZATJWvgJGhQ4cFi3WrizQ5zLAyhN5HxuAJ1yMYaJp8GuYsTLLxTAz6otCfb",
    "8AFJzuTujXjw1Z6M3fWhQ1ujDW7zsV4ePeVjVo7D1egERqSW9nZ",
    "163Q17qLbTCue8YY3AvjpUhotuaodLm2uqMhpYirsKjVqnxJRWTEoywMVY3NbBAHuhAJ2cF9GAZ",
    "2MnmgiRH4eGLyLc9eAqStzk7dFgBjFtUCtu",
    "461QQ2sYWxU7H2PV4oBwJGNch8XVTYYbZxU",
    "2UCtv53VttmQYkVU4VMtXB31REvQg4ABzs41AEKZ8UcB7DAfVzdkV9JDErwGwyj5AUHLkmgZeobs",
    "cSNjAsnhgtiFMi6MtfvgscMB2Cbhn2v1FUYfviJ1CdjfidvmeW6mn",
    "gmsow2Y6EWAFDFE1CE4Hd3Tpu2BvfmBfG1SXsuRARbnt1WjkZnFh1qGTiptWWbjsq2Q6qvpgJVj",
    "nksUKSkzS76v8EsSgozXGMoQFiCoCHzCVajFKAXqzK5on9ZJYVHMD5CKwgmX3S3c7M1U3xabUny",
    "L3favK1UzFGgdzYBF2oBT5tbayCo4vtVBLJhg2iYuMeePxWG8SQc",
    "7VxLxGGtYT6N99GdEfi6xz56xdQ8nP2dG1CavuXx7Rf2PrvNMTBNevjkfgs9JmkcGm6EXpj8ipyPZ",
    "2mbZwFXF6cxShaCo2czTRB62WTx9LxhTtpP",
    "dB7cwYdcPSgiyAwKWL3JwCVwSk6epU2txw",
    "HPhFUhUAh8ZQQisH8QQWafAxtQYju3SFTX",
    "4ctAH6AkHzq5ioiM1m9T3E2hiYEev5mTsB",
    "Hn1uFi4dNexWrqARpjMqgT6cX1UsNPuV3cHdGg9ExyXw8HTKadbktRDtdeVmY3M1BxJStiL4vjJ",
    "Sq3fDbvutABmnAHHExJDgPLQn44KnNC7UsXuT7KZecpaYDMU9Txs",
    "6TqWyrqdgUEYDQU1aChMuFMMEimHX44qHFzCUgGfqxGgZNMUVWJ",
    "giqJo7oWqFxNKWyrgcBxAVHXnjJ1t6cGoEffce5Y1y7u649Noj5wJ4mmiUAKEVVrYAGg2KPB3Y4",
    "cNzHY5e8vcmM3QVJUcjCyiKMYfeYvyueq5qCMV3kqcySoLyGLYUK",
    "37uTe568EYc9WLoHEd9jXEvUiWbq5LFLscNyqvAzLU5vBArUJA6eydkLmnMwJDjkL5kXc2VK7ig",
    "EsYbG4tWWWY45G31nox838qNdzksbPySWc",
    "nbuzhfwMoNzA3PaFnyLcRxE9bTJPDkjZ6Rf6Y6o2ckXZfzZzXBT",
    "cQN9PoxZeCWK1x56xnz6QYAsvR11XAce3Ehp3gMUdfSQ53Y2mPzx",
    "1Gm3N3rkef6iMbx4voBzaxtXcmmiMTqZPhcuAepRzYUJQW4qRpEnHvMojzof42hjFRf8PE2jPde",
    "2TAq2tuN6x6m233bpT7yqdYQPELdTDJn1eU",
    "ntEtnnGhqPii4joABvBtSEJG6BxjT2tUZqE8PcVYgk3RHpgxgHDCQxNbLJf7ardf1dDk2oCQ7Cf",
    "Ky1YjoZNgQ196HJV3HpdkecfhRBmRZdMJk89Hi5KGfpfPwS2bUbfd",
    "2A1q1YsMZowabbvta7kTy2Fd6qN4r5ZCeG3qLpvZBMzCixMUdkN2Y4dHB1wPsZAeVXUGD83MfRED",
)

# the seed of the generated keys, fixed so that two runs ask the same
_SEED = 2020


def _point_of_wif(wif: str) -> tuple[int, int]:
    """Return the public key of a compressed eCash WIF."""
    payload = b58decode_check(wif)
    assert payload[0] == _WIF_VERSION
    assert len(payload) == 34
    assert payload[-1] == 1
    return mult(int.from_bytes(payload[1:33], "big"), secp256k1.G, secp256k1)


@pytest.mark.parametrize("wif, address", _KEY_TESTS)
def test_a_key_of_bitcoin_abc_gives_its_address(wif: str, address: str) -> None:
    """Bitcoin ABC's test keys give its legacy addresses.

    The CashAddr address of each key carries the same hash.
    """
    point = _point_of_wif(wif)
    assert legacy_address_from_pub_key(point) == address
    cashaddr = address_from_pub_key(point)
    assert cashaddr_decode(cashaddr) == ("ecash", 0, b58decode_check(address)[1:])
    assert is_valid_address(address)
    assert is_valid_address(cashaddr)


@pytest.mark.parametrize("digest, p2pkh, p2sh", _ENCODE_ADDRESS)
def test_a_cashaddr_of_bitcoin_abc_is_valid(
    digest: bytes, p2pkh: str, p2sh: str
) -> None:
    """Each address is valid, and encodes its hash and type."""
    for kind, address in ((0, p2pkh), (1, p2sh)):
        assert_valid_address(address)
        assert cashaddr_encode("ecash", kind, digest).decode("ascii") == address


def test_the_prefix_is_in_the_checksum() -> None:
    """The prefix may be left out, and is verified as `ecash`.

    In upper case the address is valid, and in mixed case it is refused.
    Under `bitcoincash` it is refused for its prefix, and so is a Bitcoin
    Cash address, whose payload alone, verified as `ecash`, fails the
    checksum.
    """
    address = _ENCODE_ADDRESS[0][1]
    payload = address.partition(":")[2]
    assert is_valid_address(payload)
    assert is_valid_address(address.upper())
    assert not is_valid_address(f"ecash:{payload[0].upper()}{payload[1:]}")
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(f"bitcoincash:{payload}")
    assert str(caught.value).startswith(
        "neither a CashAddr address (CashAddr prefix is not the one given)"
    )
    assert cashaddr_decode(_BITCOIN_CASH)[0] == "bitcoincash"
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(_BITCOIN_CASH)
    assert str(caught.value).startswith(
        "neither a CashAddr address (CashAddr prefix is not the one given)"
    )
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(_BITCOIN_CASH.partition(":")[2])
    assert str(caught.value).startswith("neither a CashAddr address (invalid checksum)")


@pytest.mark.parametrize("address, script", _KEY_IO_VALID)
def test_a_legacy_address_of_bitcoin_abc_is_valid(address: str, script: str) -> None:
    """Each mainnet legacy address is valid, and encodes its script's hash."""
    assert_valid_address(address)
    octets = bytes.fromhex(script)
    if octets[:3] == b"\x76\xa9\x14":
        assert base58_address(0, octets[3:23], alphabet=BITCOIN_ALPHABET) == address
    else:
        assert octets[:2] == b"\xa9\x14"
        assert base58_address(5, octets[2:22], alphabet=BITCOIN_ALPHABET) == address


@pytest.mark.parametrize("address", _KEY_IO_INVALID)
def test_an_invalid_string_of_bitcoin_abc_is_refused(address: str) -> None:
    """Each invalid string is refused, and the refusal does not quote it."""
    assert not is_valid_address(address)
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    if len(address) > 12:
        assert_secret_free(caught.value, [address])


def test_the_derivation_holds_over_generated_keys() -> None:
    """A property over keys from a fixed seed.

    The CashAddr and legacy addresses of each key are valid and carry one
    hash, and a point, its compressed encoding and a prepared point give
    the same addresses.
    """
    rng = random.Random(_SEED)
    for _ in range(16):
        point = mult(rng.randrange(1, secp256k1.n), secp256k1.G, secp256k1)
        compressed = bytes_from_point(point, secp256k1)
        cashaddr = address_from_pub_key(point)
        legacy = legacy_address_from_pub_key(point)
        assert cashaddr.startswith("ecash:q")
        assert legacy.startswith("1")
        assert is_valid_address(cashaddr)
        assert is_valid_address(legacy)
        assert cashaddr_decode(cashaddr)[2] == b58decode_check(legacy)[1:]
        for spelling in (compressed, compressed.hex(), PreparedPoint(point)):
            assert address_from_pub_key(spelling) == cashaddr
            assert legacy_address_from_pub_key(spelling) == legacy


@pytest.mark.parametrize(
    "address, reason",
    [
        # Bitcoin Cash's token-aware P2PKH, a type Bitcoin ABC does not know
        (
            cashaddr_encode("ecash", 2, bytes(20)).decode("ascii"),
            "unknown CashAddr type: 2",
        ),
        # `DecodeCashAddrDestination` takes a 20-byte hash only
        (
            cashaddr_encode("ecash", 1, bytes(32)).decode("ascii"),
            "32-byte hash for CashAddr type 1",
        ),
        (
            cashaddr_encode("ecash", 0, bytes(24)).decode("ascii"),
            "24-byte hash for CashAddr type 0",
        ),
    ],
)
def test_a_cashaddr_of_another_shape_is_refused(address: str, reason: str) -> None:
    """A type Bitcoin ABC does not know, a size it does not take."""
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    assert str(caught.value).startswith(f"neither a CashAddr address ({reason})")


@pytest.mark.parametrize(
    "address, reason",
    [
        # Bitcoin Cash's P2SH32, which `DecodeLegacyDestination` does not read
        (
            base58_address(5, bytes(32), alphabet=BITCOIN_ALPHABET),
            "32-byte hash for version byte 5",
        ),
        # Litecoin's P2PKH version byte
        (
            base58_address(48, bytes(20), alphabet=BITCOIN_ALPHABET),
            "unknown version byte: 48",
        ),
    ],
)
def test_a_legacy_address_of_another_shape_is_refused(
    address: str, reason: str
) -> None:
    """A size P2SH does not take, and another coin's version byte."""
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    assert str(caught.value).endswith(f"nor a legacy one ({reason})")


def test_an_uncompressed_key_is_refused() -> None:
    """A key written uncompressed hashes to another address: refused."""
    point = _point_of_wif(_KEY_TESTS[0][0])
    uncompressed = bytes_from_point(point, secp256k1, compressed=False)
    for derive in (address_from_pub_key, legacy_address_from_pub_key):
        with pytest.raises(CoinAddressesValueError, match="uncompressed public key"):
            derive(uncompressed)


@pytest.mark.parametrize("address", [None, b"ecash:", 0, ["q"]])
def test_an_address_of_no_string_type_is_refused(address: object) -> None:
    """A non-string is a caller's mistake, not an invalid address."""
    for check in (assert_valid_address, is_valid_address):
        with pytest.raises(CoinAddressesTypeError, match="not a string"):
            check(address)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "before, after",
    [(" ", ""), ("", " "), ("\t", "\n")],
    ids=["leading space", "trailing space", "tab and newline"],
)
@pytest.mark.parametrize("address", [_KEY_TESTS[0][1], _ENCODE_ADDRESS[0][1]])
def test_whitespace_around_an_address_is_refused(
    before: str, after: str, address: str
) -> None:
    """An address with whitespace around it is refused.

    Bitcoin ABC skips whitespace around a legacy address, and
    `coin_addresses._bitcoin` says why this package does not.
    """
    assert is_valid_address(address)
    padded = f"{before}{address}{after}"
    with pytest.raises(CoinAddressesValueError):
        assert_valid_address(padded)
    assert not is_valid_address(padded)
