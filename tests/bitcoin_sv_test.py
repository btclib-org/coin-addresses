# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for Bitcoin SV addresses: the derivation, the validation."""

from __future__ import annotations

import random

import pytest
from base58_bech32.base58 import BITCOIN_ALPHABET, b58decode_check
from base58_bech32.cashaddr import cashaddr_encode
from ecc.curves import PreparedPoint, bytes_from_point, mult, secp256k1

from coin_addresses._bitcoin import base58_address
from coin_addresses.bitcoin_sv import (
    address_from_pub_key,
    assert_valid_address,
    is_valid_address,
)
from coin_addresses.exceptions import CoinAddressesTypeError, CoinAddressesValueError

from .secret_free import assert_secret_free

# two private keys, as compressed WIF, and the P2PKH address of each one's
# public key, `strSecret1C`, `strSecret2C`, `addr1C` and `addr2C`:
#
# repo    bitcoin-sv/bitcoin-sv
# path    src/test/key_tests.cpp
# commit  6504a3aff65ba97c0f6c80962b033e35ecbfed4b
# blob    5acd8bb0627c8695dd209617f27c02b02885dde9
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
# the version byte of a Bitcoin SV WIF, `SECRET_KEY` of the chainparams
# the module's docstring cites
_WIF_VERSION = 128

# the mainnet addresses that are no private key, with the hash each
# carries and its `addrType`:
#
# repo    bitcoin-sv/bitcoin-sv
# path    src/test/data/base58_keys_valid.json
# commit  6504a3aff65ba97c0f6c80962b033e35ecbfed4b
# blob    da24214855421c66488fc3f1eb7b7161ce816db8
_KEYS_VALID = (
    (
        "1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i",
        "65a16059864a2fdbc7c99a4723a8395bc6f188eb",
        "pubkey",
    ),
    (
        "3CMNFxN1oHBc4R1EpboAL5yzHGgE611Xou",
        "74f209f6ea907e2ea48f74fae05782ae8a665257",
        "script",
    ),
    (
        "1Ax4gZtb7gAit2TivwejZHYtNNLT18PUXJ",
        "6d23156cbbdcc82a5a47eee4c2c7c583c18b6bf4",
        "pubkey",
    ),
    (
        "3QjYXhTkvuj8qPaXHTTWb5wjXhdsLAAWVy",
        "fcc5460dd6e2487c7d75b1963625da0e8f4c5975",
        "script",
    ),
    (
        "1C5bSj1iEGUgSTbziymG7Cn18ENQuT36vv",
        "7987ccaa53d02c8873487ef919677cd3db7a6912",
        "pubkey",
    ),
    (
        "3AnNxabYGoTxYiTEZwFEnerUoeFXK2Zoks",
        "63bcc565f9e68ee0189dd5cc67f1b0e5f02f45cb",
        "script",
    ),
    (
        "1Gqk4Tv79P91Cc1STQtU3s1W6277M2CVWu",
        "adc1cc2081a27206fae25792f28bbc55b831549d",
        "pubkey",
    ),
    (
        "33vt8ViH5jsr115AGkW6cEmEz9MpvJSwDk",
        "188f91a931947eddd7432d6e614387e32b244709",
        "script",
    ),
    (
        "1JwMWBVLtiqtscbaRHai4pqHokhFCbtoB4",
        "c4c1b72491ede1eedaca00618407ee0b772cad0d",
        "pubkey",
    ),
    (
        "3QCzvfL4ZRvmJFiWWBVwxfdaNBT8EtxB5y",
        "f6fe69bcb548a829cce4c57bf6fff8af3a5981f9",
        "script",
    ),
    (
        "19dcawoKcZdQz365WpXWMhX6QCUpR9SY4r",
        "5eadaf9bb7121f0f192561a5a62f5e5f54210292",
        "pubkey",
    ),
    (
        "37Sp6Rv3y4kVd1nQ1JV5pfqXccHNyZm1x3",
        "3f210e7277c899c3a155cc1c90f4106cbddeec6e",
        "script",
    ),
    (
        "13p1ijLwsnrcuyqcTvJXkq2ASdXqcnEBLE",
        "1ed467017f043e91ed4c44b4e8dd674db211c4e6",
        "pubkey",
    ),
    (
        "3ALJH9Y951VCGcVZYAdpA3KchoP9McEj1G",
        "5ece0cadddc415b1980f001785947120acdb36fc",
        "script",
    ),
)

# every string of the file:
#
# repo    bitcoin-sv/bitcoin-sv
# path    src/test/data/base58_keys_invalid.json
# commit  6504a3aff65ba97c0f6c80962b033e35ecbfed4b
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

# a hash, and its P2PKH and P2SH addresses, from `test_addresses`:
#
# repo    bitcoin-sv/bitcoin-sv
# path    src/test/dstencode_tests.cpp
# commit  6504a3aff65ba97c0f6c80962b033e35ecbfed4b
# blob    6cf05175b07bfc314e95d9b3defbe2436047bc19
_DSTENCODE_HASH = bytes.fromhex("76a04053bda0a88bda5177b86a15c3b29f559873")
_DSTENCODE = (
    (0, "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu"),
    (5, "3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC"),
)

# public keys and the P2PKH address of each, from a library outside the
# coin's own, which derives them end to end: the Bitcoin SV mainnet
# entries of
#
# repo    ebellocchia/bip_utils
# commit  286f03d36c80e1a7229d9586dd3651f5f73ba9b4
# path    tests/addr/test_P2PKH.py
# blob    35e7992add30de07be9b4e9478fa317d5c9787c4
_BIP_UTILS = (
    (
        "03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e",
        "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
    ),
    (
        "02b5cbfe6ee73b7c5e968e1c515a964894f306a7c882dd18433ab4e16a66d36972",
        "1BMZTqDtNogSEs1oZoGxRqfR6jS2tVxvHX",
    ),
)

# the version byte of each `addrType`, the chainparams the module's
# docstring cites
_VERSIONS = {"pubkey": 0, "script": 5}

# the seed of the generated keys, fixed so that two runs ask the same
_SEED = 2018


def _point_of_wif(wif: str) -> tuple[int, int]:
    """Return the public key of a compressed Bitcoin SV WIF."""
    payload = b58decode_check(wif)
    assert payload[0] == _WIF_VERSION
    assert len(payload) == 34
    assert payload[-1] == 1
    return mult(int.from_bytes(payload[1:33], "big"), secp256k1.G, secp256k1)


@pytest.mark.parametrize("wif, address", _KEY_TESTS)
def test_a_key_of_the_node_gives_its_address(wif: str, address: str) -> None:
    """The node's test keys give the node's addresses."""
    assert address_from_pub_key(_point_of_wif(wif)) == address
    assert is_valid_address(address)


@pytest.mark.parametrize("pub_key, address", _BIP_UTILS)
def test_a_key_gives_the_address_another_library_derives(
    pub_key: str, address: str
) -> None:
    """The derivation, against an independent one."""
    assert address_from_pub_key(pub_key) == address


@pytest.mark.parametrize("address, digest, kind", _KEYS_VALID)
def test_an_address_of_the_node_is_valid(address: str, digest: str, kind: str) -> None:
    """Each mainnet address is valid, and encodes its hash and version."""
    assert_valid_address(address)
    assert (
        base58_address(
            _VERSIONS[kind], bytes.fromhex(digest), alphabet=BITCOIN_ALPHABET
        )
        == address
    )


@pytest.mark.parametrize("version, address", _DSTENCODE)
def test_the_destination_vectors_are_valid(version: int, address: str) -> None:
    """The hash of `test_addresses` gives both of its addresses."""
    assert (
        base58_address(version, _DSTENCODE_HASH, alphabet=BITCOIN_ALPHABET) == address
    )
    assert is_valid_address(address)
    assert not is_valid_address("notvalid")


@pytest.mark.parametrize("address", _KEYS_INVALID)
def test_an_invalid_string_of_the_node_is_refused(address: str) -> None:
    """Each invalid string is refused, and the refusal does not quote it."""
    assert not is_valid_address(address)
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    if len(address) > 12:
        assert_secret_free(caught.value, [address])


def test_the_derivation_holds_over_generated_keys() -> None:
    """A property over keys from a fixed seed.

    Each address is valid and has a leading 1, and a point, its
    compressed encoding and a prepared point give the same address.
    """
    rng = random.Random(_SEED)
    for _ in range(16):
        point = mult(rng.randrange(1, secp256k1.n), secp256k1.G, secp256k1)
        compressed = bytes_from_point(point, secp256k1)
        address = address_from_pub_key(point)
        assert address.startswith("1")
        assert is_valid_address(address)
        for spelling in (compressed, compressed.hex(), PreparedPoint(point)):
            assert address_from_pub_key(spelling) == address


@pytest.mark.parametrize(
    "address, reason",
    [
        # Bitcoin Cash's P2SH32, which `DecodeDestination` does not read
        (
            base58_address(5, bytes(32), alphabet=BITCOIN_ALPHABET),
            "32-byte hash for version byte 5",
        ),
        # Dash's P2PKH version byte
        (
            base58_address(76, bytes(20), alphabet=BITCOIN_ALPHABET),
            "unknown version byte: 76",
        ),
        # a CashAddr address: Bitcoin SV reads Base58Check alone
        (
            cashaddr_encode("bitcoincash", 0, _DSTENCODE_HASH).decode("ascii"),
            "Base58 string contains invalid characters",
        ),
    ],
)
def test_an_address_of_another_shape_is_refused(address: str, reason: str) -> None:
    """Each way a string is not a Bitcoin SV address."""
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    assert str(caught.value) == reason


def test_an_uncompressed_key_is_refused() -> None:
    """A key written uncompressed hashes to another address: refused."""
    point = _point_of_wif(_KEY_TESTS[0][0])
    uncompressed = bytes_from_point(point, secp256k1, compressed=False)
    with pytest.raises(CoinAddressesValueError, match="uncompressed public key"):
        address_from_pub_key(uncompressed)


@pytest.mark.parametrize("address", [None, b"1", 0, ["1"]])
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

    The Bitcoin SV node skips whitespace around an address, and
    `coin_addresses._bitcoin` says why this package does not.
    """
    assert is_valid_address(address)
    padded = f"{before}{address}{after}"
    with pytest.raises(CoinAddressesValueError):
        assert_valid_address(padded)
    assert not is_valid_address(padded)
