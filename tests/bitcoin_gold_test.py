# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for Bitcoin Gold addresses: each script type, the validation."""

from __future__ import annotations

import random

import pytest
from base58_bech32.base58 import BITCOIN_ALPHABET, b58decode_check
from base58_bech32.bech32 import (
    BECH32_1_CONST,
    BECH32_M_CONST,
    bech32_encode,
    convertbits,
)
from ecc.curves import PreparedPoint, bytes_from_point, mult, secp256k1

from coin_addresses._bitcoin import base58_address, segwit_address
from coin_addresses.bitcoin_gold import (
    address_from_pub_key,
    assert_valid_address,
    is_valid_address,
)
from coin_addresses.exceptions import CoinAddressesTypeError, CoinAddressesValueError

from .secret_free import assert_secret_free

# two private keys, as compressed WIF, and the P2PKH address of each one's
# public key, `strSecret1C`, `strSecret2C`, `addr1C` and `addr2C`:
#
# repo    BTCGPU/BTCGPU
# path    src/test/key_tests.cpp
# commit  1b85f0953725812dedcfc5a7ac077c16d419e4ba
# blob    834209b0f06f78f4184563329cce4af005bcbf7e
_KEY_TESTS = (
    (
        "Kwr371tjA9u2rFSMZjTNun2PXXP3WPZu2afRHTcta6KxEUdm1vEw",
        "GfeEGwCpwEncjfbCEU7AiLyCmhD5A3KWsz",
    ),
    (
        "L3Hq7a8FEQwJkW1M2GNKDW28546Vp5miewcCzSqUD9kCAXrJdS3g",
        "GVGeSRJHz48p4kTpGMYph7KabYEzYyPDXr",
    ),
)
# the version byte of a Bitcoin Gold WIF, `SECRET_KEY` of the chainparams
# the module's docstring cites
_WIF_VERSION = 128

# a public key, and the outputs `bitcoin-tx` writes for it as P2WPKH and
# as P2SH-P2WPKH: the address of the first, and the script hash of the
# second, whose address the file writes with Bitcoin's version byte 5:
#
# repo    BTCGPU/BTCGPU
# commit  1b85f0953725812dedcfc5a7ac077c16d419e4ba
# path    test/util/data/bitcoin-util-test.json
# blob    99cd4ab695bcf93c85a0e09c4b9d273928f95a50
# path    test/util/data/txcreateoutpubkey2.json
# blob    f6a0b2388426556c9c5fee71756c73d07e319e9e
# path    test/util/data/txcreateoutpubkey3.json
# blob    4d904df3c8a6af1548af4cc6643bd0b6ffb7e116
_OUTPUBKEY = "02a5613bd857b7048924264d1e70e08fb2a7e6527d32b7ab1bb993ac59964ff397"
_OUTPUBKEY_P2WPKH = "btg1q5fgkuac9s2ry56jka5s6zqsyfcugcchrja7tf8"
_OUTPUBKEY_P2SH_HASH = "a5ab14c9804d0d8bf02f1aea4e82780733ad0a83"
_OUTPUBKEY_P2SH_BITCOIN = "3GnzN8FqgvYGYdhj8NW6UNxxVv3Uj1ApQn"

# the mainnet addresses, and the scriptPubKey of each, that are no
# private key:
#
# repo    BTCGPU/BTCGPU
# path    src/test/data/key_io_valid.json
# commit  1b85f0953725812dedcfc5a7ac077c16d419e4ba
# blob    1629e7051c7af227ad3ba9735dad7db9484ff08c
_KEY_IO_VALID = (
    (
        "GUHcigT74ggLsmbxHFTLfn2ZUNJUWiXaMG",
        "76a914728d4cc27d19707b0197cfcd7c412d43287864b588ac",
    ),
    (
        "Aa6QUX6pRcncJN7vm7FG8vsy62gyKuANy6",
        "a914c8f37c3cc21561296ad81f4bec6b5de10ebc185187",
    ),
    (
        "btg1q5cuatynjmk4szh40mmunszfzh7zrc5xmn8padv",
        "0014a639d59272ddab015eafdef9380922bf843c50db",
    ),
    (
        "btg1qkw7lz3ahms6e0ajv27mzh7g62tchjpmve4afc29u7w49tddydy2s2vtjh5",
        "0020b3bdf147b7dc3597f64c57b62bf91a52f179076ccd7a9c28bcf3aa55b5a46915",
    ),
    (
        "btg1p5rgvqejqh9dh37t9g94dd9cm8vtqns7dndgj423egwggsggcdzms7pg7wc",
        "5120a0d0c06640b95b78f965416ad6971b3b1609c3cd9b512aaa39439088211868b7",
    ),
    ("btg1zr4pqk06j6k", "52021d42"),
    (
        "GPoxp8rSQRSeVckJTGfNBgin8C1rakneRS",
        "76a9144171ec673aeb9fcf42af6094a3c82207e3b9a78188ac",
    ),
    (
        "ASrRHjXu4jkTRxq12JerpKhTh3111Yy2Va",
        "a914798575fc1041b9440c4e63c28e57e597d00b7e4387",
    ),
    (
        "btg1qz377zwe5awr68dnggengqx9vrjt05k98kcktlm",
        "0014147de13b34eb87a3b66846668018ac1c96fa58a7",
    ),
    (
        "btg1qkmhskpdzg8kdkfywhu09kswwn9qan9vnkrf6mk40jvnr06s6sz5s7frh5h",
        "0020b6ef0b05a241ecdb248ebf1e5b41ce9941d99593b0d3addaaf932637ea1a80a9",
    ),
    (
        "btg1ps8cndas60cntk8x79sg9f5e5jz7x050z8agyugln2ukkks23rryq0eklxj",
        "512081f136f61a7e26bb1cde2c1054d33490bc67d1e23f504e23f3572d6b415118c8",
    ),
    ("btg1zn4ts5uwx8l", "52029d57"),
    (
        "GKRbyaugsGqLWvjudtAUwZCeyFur6K6ENR",
        "76a9141156e00f70061e5faba8b71593a8c7554b47090c88ac",
    ),
    (
        "Accgu45kVdtN3fQvtbctgd5d6yE5opDLsU",
        "a914e49decc9e5d97e0547d3642f3a4795b13ae62bca87",
    ),
)

# every string of the file, each invalid on every network:
#
# repo    BTCGPU/BTCGPU
# path    src/test/data/key_io_invalid.json
# commit  1b85f0953725812dedcfc5a7ac077c16d419e4ba
# blob    87a1ea0cc55cf58dcec4b1ed0cd25dbda548a877
_KEY_IO_INVALID = (
    "",
    "x",
    "2v7k5Bb8Lr1MMgTgW6HAf5YHXi6BzpPjHpQ4srD4RSwHYpzXKiXmLAgiLhkXvp3JF5v7nq45EWr",
    "RAZzCGtMbiUgMiiyrZySrSpdfnQReFXA3r",
    "NYamy7tcPQTzoU5iyQojD3sqhiz7zxkvn8",
    "geaFG555Ex5nyRf7JjW6Pj2GwZA8KYxtJJLbr1eZhVW75STbYBZeRszy3wg4pkKdF4ez9J4wQiz",
    "2Cxmid3c2XQ2zvQ8SA1ha2TKqvqbJS9XFmXRsCneBS3Po7Qqb65z5zNdsoF9AfieXFcpoVPmkmfa",
    "gaJ7UVge2njVg9tFTetJrtHgruMm7aQDiSAxfHrVEgzK8N2ooagDVmDkdph434xzc4K96Gjyxcs",
    "5JN5BEVQPZ3tAiatz1RGXkrJuE3EC6bervMaPb38wTNgEuZCeqp",
    "3TnFbyUtBRS5rE1KTW81qLVspjJNaB3uu6uuvLjxhZo2DB6PCGh",
    "7UgSZGaMaTc4d2mdEgcGBFiMeS6eMsithGUqvBsKTQdGzD7XQDbMEYo3gojdbXEPbUdFF3CQoK72f",
    "9261wfqQqruNDnBDhbbb4tN9oKA1KpRFHeoYeufyJApVGixyAG4V",
    "cS824CTUh18scFmYuqt6BgxuRhdR4dEEnCHs3fzBbcyQgbfasHbw",
    "tc1q0ywf7wkz6t580n3yemd3ucfw8jxn93tpc6wskt",
    "bt1pxeeuh96wpm5c6u3kavts2qgwlv6y8um7u7ga6ltlwrhrv7w9vers8lgt3k",
    "tb130lvl2lyugsk2tf3zhwcjjv39dmwt2tt7ytqaexy8edwcuwks6p5scll5kz",
    "btgrt1rhsveeudk",
    "bc10rmfwl8nxdweeyc4sf89t0tn9fv9w6qpyzsnl2r4k48vjqh03qas9asdje0rlr0phru0wqw0p",
    "tb1qjqnfsuatr54e957xzg9sqk7yqcry9lns",
    "btgrt1q8p08mv8echkf3es027u4cdswxlylm3th76ls8v6y4zy4vwsavngpr4e4td",
    "BC1QNC2H66VLWTWTW52DP0FYUSNU3QQG5VT4V",
    "tb1qgk665m2auw09rc7pqyf7aulcuhmatz9xqtr5mxew7zuysacaascqs9v0vn",
    "btgrt17CAPP7",
    "bc1qxmf2d6aerjzam3rur0zufqxqnyqfts5u302s7x",
    "tb1qn8x5dnzpexq7nnvrvnhwr9c3wkakpcyu9wwsjzq9pstkwg0t6qhs4l3rv6",
    "BCRT1Q397G2RNVYRL5LK07CE8NCKHVKP8Z4SC9U0MVH9",
    "bc1pgxwyajq0gdn389f69uwn2fw9q0z5c9s063j5dgkdd23ajaud4hpsercr9h",
    "tb1z6mnmp5k542l6yk4ul0mp4rq3yvz44lfm",
    "btgrt17capp7",
    "2D2bqvKseKHdoKjCNvjVULUgmxHu9hjKGwDbPRjTRH59tsHNLeyKwq3vyVBbo9LByY9wiapqjwFY",
    "2SSjAim4wZpeQRe5zTj1qqS6Li9ttJDaZ3ze",
    "mi9H6MjLwXxy9kxe1x4ToxyLRBsmcZxgVi",
    "VciXoxEitcn88jy197J9n9cpJ1pZahzU3SyWUiHqLgcfjttLEEJz",
    "KppmwADGoExPT9Eq5hjRWpWFDbzJyfzHFgsfxBiDHNpVBgWPRNuy",
    "TN7EQXMxKffzvHo54yHHu9R4ks9f5gWBW3MMVf5k72zAqrgVK9ys",
    "92dbrMEYzP5dD5UhQ6maNkCQ4GLG42BM4Gc6XKZzSSMSfosfkkcB",
    "J7VQxPxyzuWEkRstQWpCz2AgysEz1APgnWCEQrFvkN3umAnCrhQF",
    "tc1qymllj6c96v5qj2504y27ldtner6eh8ldx38t83",
    "bt1flep4g",
    "tb13c553hwygcgj48qwmr9f8q0hgdcfklyaye5sxzcpcjnmxv4z506xs90tchn",
    "btgrt1tyddyu",
    "bc10qssq2mknjqf0glwe2f3587wc4jysvs3f8s6chysae6hcl6fxzdm4wxyyscrl5k9f5qmnf05a",
    "tb1q425lmgvxdgtyl2m6xuu2pc354y4fvgg8",
    "btgrt1q9wp8e5d2u3u4g0pll0cy7smeeuqezdun9xl439n3p2gg4fvgfvk3hu52hj",
    "bc1qrz5acazpue8vl4zsaxn8fxtmeuqmyjkq3",
    "tb1qkeuglpgmnex9tv3fr7htzfrh3rwrk23r52rx9halxzmv9fr85lwq0fwhmp",
    "btgrt1qd0t2wrhl7s57z99rsyaekpq0dyjcQRSSmz80r4",
    "BC1QXLFDUCGX90T3E53PQCNKJ2PK25MSF3VLPMVY6T",
    "tb1qmycg4zszgnk34vaurx3cu8wpvteg9h40yq6cp52gt26gjel03t3su3x3xu",
    "btgrt1q9hy58r4fnuxqzdqndpmq9pptc9nt2dw3rczf5e",
    "BC1PA7682NAY6JQSLUWAJYTC0ERWTMW7A4RPWLNTUS32LCXWLHVKKKTQ2UL8CG",
    "tb1z850dpxnwz2fzae5h2myatj4yvu6rq5xq",
    "btgrt1sp525pzjsmpqvcrawjreww36e9keg876skjvpwt",
    "xcAvW5jurCpzSpLxBKEhCewCgwwuGhqJnC",
    "2Cvv8yp9kXbQt8EKh6Yma95yJ1uwYF9YKXuVhGJyu3dHGVsb2AVpTC62TFACZZ3KDNrALxR2CVNs",
    "niUuL46hCuEVvkAzZKHvD746qbmLmzip9Pv3F6UZV14JxzEXBnTkVxCT4URapChJG6qAEgsZs6G",
    "2UHHgGfiipzvB8Eumnmvq6SowvrMJimjT3NwwG1839XEiUfwtpSdkUrseNsQuagXv21ce7aZu6yo",
    "8u9djKu4u6o3bsgeR4BKNnLK3akpo64FYzDAmA9239wKeshgF97",
    "TC1QPAARXSLVMXHVRR0474LZXQYZWLGFZYPSFVL9E4",
    "bt1pakek0n2267t9yaksxaczgr2syhv9y3xkx0wnsdwchfa6xkmjtvuqg3kgyr",
    "tb13h83rtwq62udrhwpn87uely7cyxcjrj0azz6a4r3n9s87x5uj98ys6ufp83",
    "btgrt1rk5vw5qf2",
    "bc10d3rmtg62h747en5j6fju5g5qyvsransrkty6ghh96pu647wumctejlsngh9pf26cysrys2x2",
    "tb1qajuy2cdwqgmrzc7la85al5cwcq374tsp",
    "btgrt1q3udxvj6x20chqh723mn064mzz65yr56ef00xk8czvu3jnx04ydapzk02s5",
    "bc1qule2szwzyaq4qy0s3aa4mauucyqt6fewe",
    "tb1ql0qny5vg9gh5tyzke6dw36px5ulkrp24x53x0pl2t5lpwrtejw3s2seej2",
    "btgrt17CAPP7",
    "bc1qtvm6davyf725wfedc2d5mrgfewqgcrce8gjrpl",
    "tb1q5acjgtqrrw3an0dzavxxxzlex8k7aukjzjk9v2u4rmfdqxjphcyq7ge97e",
)

# the seed of the generated keys, fixed so that two runs ask the same
_SEED = 2017


def _point_of_wif(wif: str) -> tuple[int, int]:
    """Return the public key of a compressed Bitcoin Gold WIF."""
    payload = b58decode_check(wif)
    assert payload[0] == _WIF_VERSION
    assert len(payload) == 34
    assert payload[-1] == 1
    return mult(int.from_bytes(payload[1:33], "big"), secp256k1.G, secp256k1)


def _segwit(version: int, program: bytes) -> str:
    """Return the Bitcoin Gold segwit address of a witness program."""
    return segwit_address(version, program, hrp="btg", limit=90)


def _address_of_script(script: str) -> str:
    """Return the address of a scriptPubKey, segwit in lower case."""
    octets = bytes.fromhex(script)
    if octets[:3] == b"\x76\xa9\x14":
        return base58_address(38, octets[3:23], alphabet=BITCOIN_ALPHABET)
    if octets[:2] == b"\xa9\x14":
        return base58_address(23, octets[2:22], alphabet=BITCOIN_ALPHABET)
    version = 0 if octets[0] == 0 else octets[0] - 0x50
    return _segwit(version, octets[2:])


@pytest.mark.parametrize("wif, address", _KEY_TESTS)
def test_a_key_of_btg_core_gives_its_address(wif: str, address: str) -> None:
    """BTG Core's test keys give BTG Core's P2PKH addresses."""
    point = _point_of_wif(wif)
    assert address_from_pub_key(point) == address
    assert address_from_pub_key(point, script_type="p2pkh") == address
    assert is_valid_address(address)


def test_the_segwit_outputs_of_btg_core_are_derived() -> None:
    """The P2WPKH address and the P2SH-P2WPKH hash of `bitcoin-tx`'s key.

    The P2SH-P2WPKH address carries that hash with version byte 23, and
    the file's own spelling, with Bitcoin's 5, is refused.
    """
    p2wpkh = address_from_pub_key(_OUTPUBKEY, script_type="p2wpkh")
    assert p2wpkh == _OUTPUBKEY_P2WPKH
    p2sh = address_from_pub_key(_OUTPUBKEY, script_type="p2sh-p2wpkh")
    assert b58decode_check(p2sh) == bytes([23]) + bytes.fromhex(_OUTPUBKEY_P2SH_HASH)
    assert is_valid_address(p2wpkh)
    assert is_valid_address(p2sh)
    assert b58decode_check(_OUTPUBKEY_P2SH_BITCOIN)[1:] == bytes.fromhex(
        _OUTPUBKEY_P2SH_HASH
    )
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(_OUTPUBKEY_P2SH_BITCOIN)
    assert str(caught.value).startswith(
        "neither a legacy address (unknown version byte: 5)"
    )


@pytest.mark.parametrize("address, script", _KEY_IO_VALID)
def test_an_address_of_btg_core_is_valid(address: str, script: str) -> None:
    """Each mainnet address is valid, and encodes its script's hash.

    The segwit ones are valid in upper case too, as the file's
    `tryCaseFlip` says.
    """
    assert_valid_address(address)
    assert address == _address_of_script(script)
    if address.startswith("btg1"):
        assert is_valid_address(address.upper())


@pytest.mark.parametrize("address", _KEY_IO_INVALID)
def test_an_invalid_string_of_btg_core_is_refused(address: str) -> None:
    """Each invalid string is refused, and the refusal does not quote it."""
    assert not is_valid_address(address)
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    if len(address) > 12:
        assert_secret_free(caught.value, [address])


def test_the_three_script_types_hold_over_generated_keys() -> None:
    """A property over keys from a fixed seed.

    Each script type gives a valid address, P2PKH a leading G,
    P2SH-P2WPKH a leading A, P2WPKH the HRP; the three differ; and a
    point and its compressed encoding give the same address.
    """
    rng = random.Random(_SEED)
    for _ in range(16):
        point = mult(rng.randrange(1, secp256k1.n), secp256k1.G, secp256k1)
        compressed = bytes_from_point(point, secp256k1)
        addresses = {
            script_type: address_from_pub_key(point, script_type=script_type)
            for script_type in ("p2pkh", "p2sh-p2wpkh", "p2wpkh")
        }
        assert addresses["p2pkh"].startswith("G")
        assert addresses["p2sh-p2wpkh"].startswith("A")
        assert addresses["p2wpkh"].startswith("btg1q")
        assert len(set(addresses.values())) == 3
        for script_type, address in addresses.items():
            assert is_valid_address(address)
            for spelling in (compressed, compressed.hex(), PreparedPoint(point)):
                assert (
                    address_from_pub_key(spelling, script_type=script_type) == address
                )


@pytest.mark.parametrize(
    "address, reason",
    [
        (
            # a P2PKH address whose hash is one byte short
            base58_address(38, bytes(19), alphabet=BITCOIN_ALPHABET),
            "19-byte hash for version byte 38",
        ),
        (
            # a Bitcoin P2PKH address
            base58_address(0, bytes(20), alphabet=BITCOIN_ALPHABET),
            "unknown version byte: 0",
        ),
        (
            # the Base58Check of an empty payload
            "3QJmnh",
            "no version byte",
        ),
    ],
)
def test_a_legacy_address_of_another_shape_is_refused(
    address: str, reason: str
) -> None:
    """The legacy refusals, each given beside the segwit one."""
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    assert str(caught.value).startswith(f"neither a legacy address ({reason})")


@pytest.mark.parametrize(
    "version, program, reason",
    [
        (0, bytes(21), "21-byte witness program for witness version 0"),
        (1, bytes(1), "1-byte witness program"),
        (16, bytes(41), "41-byte witness program"),
    ],
)
def test_a_segwit_address_of_another_shape_is_refused(
    version: int, program: bytes, reason: str
) -> None:
    """A witness program of a size its version does not take."""
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(_segwit(version, program))
    assert str(caught.value).endswith(f"nor a segwit one ({reason})")


def test_a_segwit_address_with_the_wrong_checksum_is_refused() -> None:
    """Version 0 in bech32m, and version 1 in bech32, as BIP350 says."""
    v0 = bech32_encode(
        "btg", [0, *convertbits(bytes(20), 8, 5)], m=BECH32_M_CONST
    ).decode("ascii")
    v1 = bech32_encode(
        "btg", [1, *convertbits(bytes(32), 8, 5)], m=BECH32_1_CONST
    ).decode("ascii")
    for address, version in ((v0, 0), (v1, 1)):
        with pytest.raises(CoinAddressesValueError) as caught:
            assert_valid_address(address)
        reason = f"wrong checksum for witness version {version}"
        assert str(caught.value).endswith(f"nor a segwit one ({reason})")


@pytest.mark.parametrize(
    "data, reason",
    [
        ([], "no witness version"),
        ([17, *[0] * 32], "invalid witness version: 17"),
    ],
)
def test_a_bech32_string_with_no_valid_version_is_refused(
    data: list[int], reason: str
) -> None:
    """No data at all, and a version above 16."""
    address = bech32_encode("btg", data, m=BECH32_M_CONST).decode("ascii")
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    assert str(caught.value).endswith(f"nor a segwit one ({reason})")


@pytest.mark.parametrize(
    "address",
    [
        # Bitcoin's P2WPKH address of BIP173's example key
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        # Litecoin's, from the README of this repository
        "ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9",
    ],
)
def test_another_hrp_is_refused(address: str) -> None:
    """Another coin's P2WPKH address of the same key is not Bitcoin Gold's."""
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    assert str(caught.value).endswith("nor a segwit one (not the Bitcoin Gold HRP)")


@pytest.mark.parametrize("script_type", ["", "P2PKH", "p2tr", "p2sh"])
def test_an_unknown_script_type_is_refused(script_type: str) -> None:
    """A script type the module does not give, unquoted."""
    point = _point_of_wif(_KEY_TESTS[0][0])
    with pytest.raises(CoinAddressesValueError) as caught:
        address_from_pub_key(point, script_type=script_type)
    assert str(caught.value) == (
        "unknown script type, not one of p2pkh, p2sh-p2wpkh, p2wpkh"
    )


@pytest.mark.parametrize("script_type", [None, 0, b"p2pkh"])
def test_a_script_type_of_no_string_type_is_refused(script_type: object) -> None:
    """A non-string script type is a caller's mistake."""
    point = _point_of_wif(_KEY_TESTS[0][0])
    with pytest.raises(CoinAddressesTypeError, match="script type not a string"):
        address_from_pub_key(point, script_type=script_type)  # type: ignore[arg-type]


def test_an_uncompressed_key_is_refused() -> None:
    """A key written uncompressed hashes to another address: refused."""
    point = _point_of_wif(_KEY_TESTS[0][0])
    uncompressed = bytes_from_point(point, secp256k1, compressed=False)
    for script_type in ("p2pkh", "p2sh-p2wpkh", "p2wpkh"):
        with pytest.raises(CoinAddressesValueError, match="uncompressed public key"):
            address_from_pub_key(uncompressed, script_type=script_type)


@pytest.mark.parametrize("address", [None, b"btg1q", 0, ["G"]])
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
@pytest.mark.parametrize("address", [_KEY_TESTS[0][1], _OUTPUBKEY_P2WPKH])
def test_whitespace_around_an_address_is_refused(
    before: str, after: str, address: str
) -> None:
    """An address with whitespace around it is refused.

    BTG Core skips whitespace around a legacy address, and
    `coin_addresses._bitcoin` says why this package does not.
    """
    assert is_valid_address(address)
    padded = f"{before}{address}{after}"
    with pytest.raises(CoinAddressesValueError):
        assert_valid_address(padded)
    assert not is_valid_address(padded)
