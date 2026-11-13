# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for Dash addresses: the derivation, the validation."""

from __future__ import annotations

import random

import pytest
from base58_bech32.base58 import BITCOIN_ALPHABET, b58decode_check
from ecc.curves import PreparedPoint, bytes_from_point, mult, secp256k1

from coin_addresses._bitcoin import base58_address
from coin_addresses.dash import (
    address_from_pub_key,
    assert_valid_address,
    is_valid_address,
)
from coin_addresses.exceptions import CoinAddressesTypeError, CoinAddressesValueError

from .secret_free import assert_secret_free

# two private keys, as compressed WIF, and the P2PKH address of each one's
# public key, `strSecret1C`, `strSecret2C`, `addr1C` and `addr2C`:
#
# repo    dashpay/dash
# path    src/test/key_tests.cpp
# commit  938fba502824b9d850b7c710601456dc3d71603e
# blob    007a94def8c43dfef9e88dae083b89973c74c639
_KEY_TESTS = (
    (
        "XBuxZHH6TqXUuaSjbVTFR1DQSYecxCB9QA1Koyx5tTc3ddhqEnhm",
        "XxV9h4Xmv6Pup8tVAQmH97K6grzvDwMG9F",
    ),
    (
        "XHMkZqWcY6Zkoq1j42NBijD8z5N5FtNy2Wx7WyAfXX2HZgxry8cr",
        "Xn7ZrYdExuk79Dm7CJCw7sfUWi2qWJSbRy",
    ),
)
# the version byte of a Dash WIF, `SECRET_KEY` of the chainparams the
# module's docstring cites
_WIF_VERSION = 204

# the mainnet addresses, and the scriptPubKey of each, that are no
# private key:
#
# repo    dashpay/dash
# path    src/test/data/key_io_valid.json
# commit  938fba502824b9d850b7c710601456dc3d71603e
# blob    d83bb2adaeee0d14ca86bc0cfc468ea0c52e579f
_KEY_IO_VALID = (
    (
        "XqZHYpoksmbEPtWstAEki3o8pJ8ZsPfXpK",
        "76a914a31c06bd463e3923bc1aadbde48b16976c08071788ac",
    ),
    (
        "7XShCrc5u9rZZv7j18WqbUMZMxp8k1Hq4z",
        "a914373b819a068f32b7a6b38b6b38729647cfde01c287",
    ),
    (
        "XiXge21yt5xErdLNt1V29yJX2g29Xag9VM",
        "76a9145605968d3a96380112b5a10f3a11e708dc54128388ac",
    ),
    (
        "7XuP9xVGyvkCAfW84QJkGfbiR7dX9TYaPH",
        "a9143c47ab7c368a21b9efe19293793ec879ce68301887",
    ),
    (
        "XgVUBJHMpE4QhFXkhhQbgJK84ASDya7GrU",
        "76a9143faa1a5ac78fe2df68f99ebf27ecee3cdd29f9cc88ac",
    ),
    (
        "7mJ7bHEhHRdLZeETB6aQ1v5ABRitMzRoL8",
        "a914cf2de169062dbcec55c8ee69cdabddbccf3f442887",
    ),
    (
        "Xs7iEDx8nMwJHdiQnwvCnLBTP2sjmDGTJA",
        "76a914b436106a68548a776a0f34d56b63e7c595f2b20588ac",
    ),
    (
        "7nTHC71wyAMc1rGdokAJ5wCm8KWLdaQKnR",
        "a914dbe1c393617a01f15a4cc063dae4f4d56b89bfbc87",
    ),
    (
        "XoGGRaieFVcqKme6mNNTWaXuLFvs6DkwbT",
        "76a91489f3c3b02f3137bd7b46b996fac2869848fb19d588ac",
    ),
    (
        "7WuHz4wne6YhnjEucc9mdDtWrd5u6NGhz5",
        "a914314b3a5c2d4d03b58820460bf90d8d4ab2f120a387",
    ),
)

# every string of the file, each invalid on every network:
#
# repo    dashpay/dash
# path    src/test/data/key_io_invalid.json
# commit  938fba502824b9d850b7c710601456dc3d71603e
# blob    75ca69ea23cb0a759f916946a97cb722d4789842
_KEY_IO_INVALID = (
    "",
    "x",
    "UJpnDUZhux15KckwqW1u8wratRydW8RgSfV7of9kh6S1EedTgkqawKx77AciK8x6iHVLd7jwizd",
    "72JVw2AafMBFLZ3d6T6ymErSg5s7xAFAKgMgMLLiNXCPkLm4JDjvwhc1kjmApkcVNbqoMp2Hg2v",
    "s3YeU8Q2CU2NBzkKBgya6VA39EtN9zZLi5fscPmY7iqPL2VmFXHxn8QaeYoQXF5AyzC17C1VLo3",
    "7if6g2nYRkgh46JNa8iaoUYPzrbxMQhd2FNp2kVb6QLtofd76Yf",
    "3bxKf3oSh6kRKf83AhAiED6Sp85wHo3SKXnV1igNhXXW2Y23tz2e",
    "6uuF4qfGt6sZ4TGRKs8MYmrvEarZ7xMd592mLDH1AxtWoQ8dNB2KSTAjnsFLwPzBGJQzWP6sMw9",
    "2j8t4uU1uhfsSLe1Z2ozQpce9vdHUjxnu1N",
    "869cULb66zRdpGZQ5duEfKbFrxTpFDpHYUuPjTVZMAbS2q4DgCqyozDcS9MYTyn1oHCGmSyabRQ",
    "Pm6RGQxdC2MLeBHAiwZuevgCqpf1BXHV3mgrFyqkdHdGjSNCWj",
    "cU3bonutoouxvZ1eFjeWZ9fx3m1iejyyNT5LZj7APGXdf7xrM8za",
    "24MoumSS96TbYEz7zxLQUWM6XtptPk7EVKkm5dPeNmGdU13KCePZbDPCX83Jv2RDgF7dX1ECYkxCx",
    "aXxpJ39neQAdsvQyWpfmBnchstSHhzuttM",
    "Cz22bHdzGqE9zmK5jGeTTnCLuoy8X5qRBw",
    "meYhqRj9dCsx9ZjobviAvWzzxKD4YtMzs2",
    "XDMcG9HHawbsfN2AcNjPamQtPrCNZbX3HCWcy24fw6qbb45GU4QF",
    "dqqMGb5EYH3zsKxxrgDLAgQySTbC1amEoThMeEypQ9D8252JiRVr",
    "2UAEPV9iad8nM3vmhKM3Ca2WehF9A1EacV2K1U6mh5JGmZ4L8r7fePq2CDdLnhUUZp39r3GPz1NB",
    "7VkmEHVsiwybAT47JRmPPj95iKww9aTZp3xBkQm6dBU8nv88YdpwmYqaLr17TML7uf1JgrPp1duC3",
    "SmBouAyTuApTNPEMcndUrzmk6zPtccPiGs",
    "tMYxSXg3m78N1fzNNYkT73ncYFCyag4yQB",
    "2Fod12JmMounu8JvcPRU7vcQoTmkWGa382qVr9cUrL5vPokBgU2o8buPaNfyukRqESXLJ58f7BjV",
    "6Yrq4S5f6WPJwZefp2FUB7YK3mebXuWBax5joYHbaWw8NyJXnG5esmKL2yA41yDJDJmG45TZDPWc2",
    "AiPTzbcd3AWc2cxTLFvJ2Sac5NHA48zVtJ5gFJCun6rZHgipQHjp",
    "yiLhQ2MjXvvJ77hDB9Yh94rNu6XF2tsQ9XY",
    "h252Gub658y8BeTRXJoSgxbiYPHjgAxL4H",
    "6v7e2HwCqmNQdcdXcedxAaB5EhFcmHfd8NmVgz485uYNZeMUGzKqWXgRissqxAWFK2Grv2hj1Sx",
    "4fJuZhkcDMRe6frBw8arVJZDXvW41DQBPJncf2GFGFU16qryC164",
    "41edLVs3QGta83S4Sk7Qer45eBZAEqpTzJ2YsKJyX9tMj1KLxak",
    "cNonA1fNAJ4CZpeYi4fCvW42ZXbVGuZiFSksy8kbYm6LgzxGicsY",
    "fbHnS1rzoSTiteGiAGEz4tym48S4kKfVcGpr2FEMPuyeHFZ6TSz4qJgqxHSVmQVTpEznUX6Xmz9",
    "2o6ucMbiG78JSuasuD1dzkAMNZNoV7pgn1",
    "cxG8jxnDiR5QDFSEuaiYvjgS3sShzi2nfC",
    "cW8exV1kXUQxrWrkW1LTXYPK8Vj8UyXxtfHLDACz5VFe6Wwy8a7E",
    "2UQ3i886Z21xg8pzahrG3zq8DdQnoKzSGMczG8qoL48yaxcnD7ob4M3Sxpwq4JykSedRp1MMzgmB",
    "UDPa5QS2J1xquuB4TD3TPTdULaxdDqy8hcdkXwgCmNqgSZYxPYCvvbzfVkz3nRamnvBTzfJizmC",
    "2KrxFisUvAk88XK4y8SAQxNeHQdjjLeLaYK",
    "2EpLmnuvdXBWJR5JdiCrEp4N5AcwVQ4Ckfc",
    "4qn18vELFKKBU44YJTvYgYKkrDUvfc5SJeq1BDFttQLcZCpMzTzf",
    "XDKnECKqQUp17zwQTErBzGtXYq9uPG9ybqfJjLVJZZh37VHZc3rC",
    "92c7ZpyM2KQBK8N2k1otwpGj98Ex7S8jEAnzB5hfXhBWJLFBkwc",
    "7VtmMAqgjZbpSzWQLy6j1LseRhmmgtBF45c3PrMqme5TP2ak7twfPGwivrVEVALLNnXRUdu3QB13k",
    "s3KqChhTvrQCUzbSEqbAMEVTdh84NdC1xHA8cvaXYEjohnV7xt4yNre8BMumXVeLXKTp49Sonh3",
    "ibJ6v1xJscnjqdAdqqJco864ff4W31Jh91",
    "sAyhi4v9VWr6JxTofdk8FhUUw88BmEbTsMvspzxQ6BN1mExDpWPZi9cF9RGgdFzsMDkFPfnykiCk",
    "2bqgYSiSL7bCzXWk98UBUrRiCALgRyUWRWk",
    "2UDoz44DrDa2uqVdVQEFKEhuM9AvpFSE3N8iNhc5V5bQ4ezAMdZfNoEGZKVSs7uNs8JLQX96xzDm",
    "eXDPBkXCpUQA4ZRfduqyDDtcHnoGSaC1d2BN3B6dWREUaqusqnG4",
    "29LjxDzmddtZy3odqFeu4DTFhF7ALC9hY2Vu8yPD5DzCrBMB4rbDq5b7Vh26thgfXzMXRsPtZhit",
)

# the mainnet DIP-18 Platform addresses of `dip18_platform_roundtrip`,
# with the hash each carries:
#
# repo    dashpay/dash
# path    src/test/key_io_tests.cpp
# commit  938fba502824b9d850b7c710601456dc3d71603e
# blob    9d1b41f78a65d72638064077b42504ed8bc05231
_PLATFORM = (
    (
        "dash1krma5z3ttj75la4m93xcndna9ullamq9y5e9n5rs",
        "f7da0a2b5cbd4ff6bb2c4d89b67d2f3ffeec0525",
    ),
    (
        "dash1kzjl7qzxy9lar37j8r37z3kvt07epqe20ckxfezw",
        "a5ff0046217fd1c7d238e3e146cc5bfd90832a7e",
    ),
    (
        "dash1kpkeye606ez89g7lelp7hnldwwpt76va0v3j6x28",
        "6d92674fd64472a3dfcfc3ebcfed7382bf699d7b",
    ),
    (
        "dash1sppl5xpu70aka8nacc4kj2htflydspzkxch4cad6",
        "43fa183cf3fb6e9e7dc62b692aeb4fc8d8045636",
    ),
)

# public keys and the P2PKH address of each, from a library outside the
# coin's own, which derives them end to end: the Dash mainnet entries of
#
# repo    ebellocchia/bip_utils
# commit  286f03d36c80e1a7229d9586dd3651f5f73ba9b4
# path    tests/addr/test_P2PKH.py
# blob    35e7992add30de07be9b4e9478fa317d5c9787c4
_BIP_UTILS = (
    (
        "03146d29e4a8b263f607f6ffae0a19f2e9be0bc063783e3658f50255c380b45070",
        "XnLyZhQDr3JqFQi7UPC8LddHMgbAyQWiZo",
    ),
    (
        "02b80e30b1cfbd4e172212110f914b66cdaa83967eade9c9884571906164a8cc44",
        "XykvvzP3nK2KRLKkpCe6hHV6p2w5DNQD56",
    ),
)

# the seed of the generated keys, fixed so that two runs ask the same
_SEED = 2014


def _point_of_wif(wif: str) -> tuple[int, int]:
    """Return the public key of a compressed Dash WIF."""
    payload = b58decode_check(wif)
    assert payload[0] == _WIF_VERSION
    assert len(payload) == 34
    assert payload[-1] == 1
    return mult(int.from_bytes(payload[1:33], "big"), secp256k1.G, secp256k1)


@pytest.mark.parametrize("wif, address", _KEY_TESTS)
def test_a_key_of_dash_core_gives_its_address(wif: str, address: str) -> None:
    """Dash Core's test keys give Dash Core's addresses."""
    assert address_from_pub_key(_point_of_wif(wif)) == address
    assert is_valid_address(address)


@pytest.mark.parametrize("pub_key, address", _BIP_UTILS)
def test_a_key_gives_the_address_another_library_derives(
    pub_key: str, address: str
) -> None:
    """The derivation, against an independent one."""
    assert address_from_pub_key(pub_key) == address


@pytest.mark.parametrize("address, script", _KEY_IO_VALID)
def test_an_address_of_dash_core_is_valid(address: str, script: str) -> None:
    """Each mainnet address is valid, and encodes its script's hash."""
    assert_valid_address(address)
    octets = bytes.fromhex(script)
    if octets[:3] == b"\x76\xa9\x14":
        assert base58_address(76, octets[3:23], alphabet=BITCOIN_ALPHABET) == address
    else:
        assert octets[:2] == b"\xa9\x14"
        assert base58_address(16, octets[2:22], alphabet=BITCOIN_ALPHABET) == address


@pytest.mark.parametrize("address", _KEY_IO_INVALID)
def test_an_invalid_string_of_dash_core_is_refused(address: str) -> None:
    """Each invalid string is refused, and the refusal does not quote it."""
    assert not is_valid_address(address)
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    if len(address) > 12:
        assert_secret_free(caught.value, [address])


@pytest.mark.parametrize("address, digest", _PLATFORM)
def test_a_platform_address_is_refused(address: str, digest: str) -> None:
    """A DIP-18 Platform address is refused, as Dash Core refuses it.

    The P2PKH address of the hash it carries is valid.
    """
    assert not is_valid_address(address)
    assert not is_valid_address(address.upper())
    assert is_valid_address(
        base58_address(76, bytes.fromhex(digest), alphabet=BITCOIN_ALPHABET)
    )


def test_the_derivation_holds_over_generated_keys() -> None:
    """A property over keys from a fixed seed.

    Each address is valid and has a leading X, and a point, its
    compressed encoding and a prepared point give the same address.
    """
    rng = random.Random(_SEED)
    for _ in range(16):
        point = mult(rng.randrange(1, secp256k1.n), secp256k1.G, secp256k1)
        compressed = bytes_from_point(point, secp256k1)
        address = address_from_pub_key(point)
        assert address.startswith("X")
        assert is_valid_address(address)
        for spelling in (compressed, compressed.hex(), PreparedPoint(point)):
            assert address_from_pub_key(spelling) == address


@pytest.mark.parametrize(
    "address, reason",
    [
        (
            base58_address(76, bytes(32), alphabet=BITCOIN_ALPHABET),
            "32-byte hash for version byte 76",
        ),
        # Bitcoin's P2PKH version byte
        (
            base58_address(0, bytes(20), alphabet=BITCOIN_ALPHABET),
            "unknown version byte: 0",
        ),
        ("0OIl", "Base58 string contains invalid characters"),
    ],
)
def test_an_address_of_another_shape_is_refused(address: str, reason: str) -> None:
    """Each way a Base58Check string is not a Dash address."""
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    assert str(caught.value) == reason


def test_an_uncompressed_key_is_refused() -> None:
    """A key written uncompressed hashes to another address: refused."""
    point = _point_of_wif(_KEY_TESTS[0][0])
    uncompressed = bytes_from_point(point, secp256k1, compressed=False)
    with pytest.raises(CoinAddressesValueError, match="uncompressed public key"):
        address_from_pub_key(uncompressed)


@pytest.mark.parametrize("address", [None, b"X", 0, ["X"]])
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

    Dash Core skips whitespace around an address, and
    `coin_addresses._bitcoin` says why this package does not.
    """
    assert is_valid_address(address)
    padded = f"{before}{address}{after}"
    with pytest.raises(CoinAddressesValueError):
        assert_valid_address(padded)
    assert not is_valid_address(padded)
