# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for Dogecoin addresses: the derivation, the validation."""

from __future__ import annotations

import random

import pytest
from base58_bech32.base58 import b58decode_check
from ecc.curves import PreparedPoint, bytes_from_point, mult, secp256k1

from coin_addresses._bitcoin import base58_address
from coin_addresses.dogecoin import (
    address_from_pub_key,
    assert_valid_address,
    is_valid_address,
)
from coin_addresses.exceptions import CoinAddressesTypeError, CoinAddressesValueError

from .secret_free import assert_secret_free

# two private keys, as compressed WIF, and the P2PKH address of each one's
# public key, `strSecret1C`, `strSecret2C`, `addr1C` and `addr2C`:
#
# repo    dogecoin/dogecoin
# path    src/test/key_tests.cpp
# commit  b38c83fbf10302b23ac6e7ad89bc83068efe2fd8
# blob    765e7f6e6505bed651a065cf188359ad92bf1115
_KEY_TESTS = (
    (
        "QP8WvtVMV2iU6y7LE27ksRspp4MAJizPWYovx88W71g1nfSdAhkV",
        "D8jZ6R8uuyQwiybupiVs3eDCedKdZ5bYV3",
    ),
    (
        "QTuro8Pwx5yaonvJmU4jbBfwuEmTViyAGNeNyfnG82o7HWJmnrLj",
        "DP7rGcDbpAvMb1dKup981zNt1heWUuVLP7",
    ),
)
# the version byte of a Dogecoin WIF, `SECRET_KEY` of the chainparams
# the module's docstring cites
_WIF_VERSION = 158

# the mainnet addresses that are no private key, with the hash each
# carries and its `addrType`:
#
# repo    dogecoin/dogecoin
# path    src/test/data/base58_keys_valid.json
# commit  b38c83fbf10302b23ac6e7ad89bc83068efe2fd8
# blob    f3dd97a234f8703756854406bcc19727facf8c09
_KEYS_VALID = (
    (
        "DD4KSSuBJqcjuTcvUg1CgUKeurPUFeEZkE",
        "56d9b1d684d5abef32134ebc6883d75d3a53e9be",
        "pubkey",
    ),
    (
        "A7HRQk3GFCW2QasvdZxXuYj8kkQK5QrYLs",
        "a2dd71f34fe73314d6e37c44035513f203aa400b",
        "script",
    ),
    (
        "DBjW6kna7rUPE4Mj9j4B3oK3xVA1SDHrdt",
        "485290865b407657e0aedbdbb4aa6618310af50d",
        "pubkey",
    ),
    (
        "A3RHoAQLPDSuBewbuvt5NMqEKasqs9ty3C",
        "7879ea0f1053bcbd4c60c88f922f76d27e622e1e",
        "script",
    ),
    (
        "D77Z1nmgSZxJTmtN65n2MVF9yvLSB4MpiC",
        "15a585042e96300b5ad4f9d7c7c6cba2d56a0989",
        "pubkey",
    ),
    (
        "9zYnVRaekPtdKBYuPw5QiBtv3NNrzD2LLW",
        "58fc66bf64b3c8d8accd80110bb6df6c13735937",
        "script",
    ),
    (
        "DGYdw7jC17b9SappjsrAsaghhDTS8sV5Mx",
        "7d1d283ff32f3a425ea22d21032e1bca7d14efaa",
        "pubkey",
    ),
    (
        "A3YUuiZjn3FzW2i6KqFVgHaN5r5fjvwEJ1",
        "79d61a4a63956139414b4e0698588cfb2c3466bf",
        "script",
    ),
    (
        "DExWunrSkF2P9NAzW4JpEeC38uC3z36cCk",
        "6bb106bf7cc3f80e5cfeb3eacdd8f7dd9201fa09",
        "pubkey",
    ),
    (
        "AFVkW8WgPP2rsTdAeyogFK9k8gXJ1LZwrb",
        "fcf36180b62ef220a182b1b246571bb2fce30ec8",
        "script",
    ),
    (
        "DMYFDsuFamS4kogsiqxQRXK9diCfmJzNLh",
        "b3e2d3f49932081bd0a9936d0cc239aafed51a64",
        "pubkey",
    ),
    (
        "A2CUbyEtqGUjngAjxpGmM5Nwhrz72gh23v",
        "6b1566fa4c70a69df12bacc138efffd9b9cb0e72",
        "script",
    ),
    (
        "DQJXChtyuN3aiU3W6pG4mgnykisHH5hqst",
        "d232b89955f8f77e27eea5b818c459aa8f8d364d",
        "pubkey",
    ),
    (
        "AD21pKoCWcrqrUW4oRv5xUaGwCfXhiyx6y",
        "e1c443feb1eede60962dc808899086f8dc589336",
        "script",
    ),
)

# every string of the file:
#
# repo    dogecoin/dogecoin
# path    src/test/data/base58_keys_invalid.json
# commit  b38c83fbf10302b23ac6e7ad89bc83068efe2fd8
# blob    9839c3ea07a2caf59c8e84bfe36a0d3992d97393
_KEYS_INVALID = (
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

# public keys and the P2PKH address of each, from a library outside the
# coin's own, which derives them end to end: the Dogecoin mainnet entries
# of
#
# repo    ebellocchia/bip_utils
# commit  286f03d36c80e1a7229d9586dd3651f5f73ba9b4
# path    tests/addr/test_P2PKH.py
# blob    35e7992add30de07be9b4e9478fa317d5c9787c4
_BIP_UTILS = (
    (
        "025a8ad8881f6facdc949c4a4d03257414153faea67e96acf57344660080610788",
        "DAcDAtJRztxBHyA6D6h8du1HguyTR43Mas",
    ),
    (
        "03b4b21789f999f8c268d77ff0f6ed80884ec088ddd1b2d10055981d6bc393308a",
        "DTdrvUHbk5oMyi62tM7LqrjAcXfqB7eaad",
    ),
)

# the version byte of each `addrType`, the chainparams the module's
# docstring cites
_VERSIONS = {"pubkey": 30, "script": 22}

# the seed of the generated keys, fixed so that two runs ask the same
_SEED = 2013


def _point_of_wif(wif: str) -> tuple[int, int]:
    """Return the public key of a compressed Dogecoin WIF."""
    payload = b58decode_check(wif)
    assert payload[0] == _WIF_VERSION
    assert len(payload) == 34
    assert payload[-1] == 1
    return mult(int.from_bytes(payload[1:33], "big"), secp256k1.G, secp256k1)


@pytest.mark.parametrize("wif, address", _KEY_TESTS)
def test_a_key_of_dogecoin_core_gives_its_address(wif: str, address: str) -> None:
    """Dogecoin Core's test keys give Dogecoin Core's addresses."""
    assert address_from_pub_key(_point_of_wif(wif)) == address
    assert is_valid_address(address)


@pytest.mark.parametrize("pub_key, address", _BIP_UTILS)
def test_a_key_gives_the_address_another_library_derives(
    pub_key: str, address: str
) -> None:
    """The derivation, against an independent one."""
    assert address_from_pub_key(pub_key) == address


@pytest.mark.parametrize("address, digest, kind", _KEYS_VALID)
def test_an_address_of_dogecoin_core_is_valid(
    address: str, digest: str, kind: str
) -> None:
    """Each mainnet address is valid, and encodes its hash and version."""
    assert_valid_address(address)
    assert base58_address(_VERSIONS[kind], bytes.fromhex(digest)) == address


@pytest.mark.parametrize("address", _KEYS_INVALID)
def test_an_invalid_string_of_dogecoin_core_is_refused(address: str) -> None:
    """Each invalid string is refused, and the refusal does not quote it."""
    assert not is_valid_address(address)
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    if len(address) > 12:
        assert_secret_free(caught.value, [address])


def test_the_derivation_holds_over_generated_keys() -> None:
    """A property over keys from a fixed seed.

    Each address is valid and has a leading D, and a point, its
    compressed encoding and a prepared point give the same address.
    """
    rng = random.Random(_SEED)
    for _ in range(16):
        point = mult(rng.randrange(1, secp256k1.n), secp256k1.G, secp256k1)
        compressed = bytes_from_point(point, secp256k1)
        address = address_from_pub_key(point)
        assert address.startswith("D")
        assert is_valid_address(address)
        for spelling in (compressed, compressed.hex(), PreparedPoint(point)):
            assert address_from_pub_key(spelling) == address


@pytest.mark.parametrize(
    "address, reason",
    [
        (base58_address(30, bytes(32)), "32-byte hash for version byte 30"),
        # Litecoin's P2PKH version byte
        (base58_address(48, bytes(20)), "unknown version byte: 48"),
        ("0OIl", "Base58 string contains invalid characters"),
    ],
)
def test_an_address_of_another_shape_is_refused(address: str, reason: str) -> None:
    """Each way a Base58Check string is not a Dogecoin address."""
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    assert str(caught.value) == reason


def test_an_uncompressed_key_is_refused() -> None:
    """A key written uncompressed hashes to another address: refused."""
    point = _point_of_wif(_KEY_TESTS[0][0])
    uncompressed = bytes_from_point(point, secp256k1, compressed=False)
    with pytest.raises(CoinAddressesValueError, match="uncompressed public key"):
        address_from_pub_key(uncompressed)


@pytest.mark.parametrize("address", [None, b"D", 0, ["D"]])
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
@pytest.mark.parametrize("address", [_KEY_TESTS[0][1]])
def test_whitespace_around_an_address_is_refused(
    before: str, after: str, address: str
) -> None:
    """An address with whitespace around it is refused.

    Dogecoin Core skips whitespace around a legacy address, and
    `coin_addresses._bitcoin` says why this package does not.
    """
    assert is_valid_address(address)
    padded = f"{before}{address}{after}"
    with pytest.raises(CoinAddressesValueError):
        assert_valid_address(padded)
    assert not is_valid_address(padded)
