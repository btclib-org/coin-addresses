# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for Litecoin addresses: each script type, the validation."""

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

from coin_addresses import litecoin
from coin_addresses._bitcoin import base58_address
from coin_addresses.exceptions import CoinAddressesTypeError, CoinAddressesValueError
from coin_addresses.litecoin import (
    address_from_pub_key,
    assert_valid_address,
    is_valid_address,
)

from .secret_free import assert_secret_free

# two private keys, as compressed WIF, and the P2PKH address of each one's
# public key, `strSecret1C`, `strSecret2C`, `addr1C` and `addr2C`:
#
# repo    litecoin-project/litecoin
# path    src/test/key_tests.cpp
# commit  ec1b6489a900d09cf5991e220dce089c77a232a2
# blob    79fff33393cd72780071dc5898a97d46fc017eb3
_KEY_TESTS = (
    (
        "T3gJYmBuZXsdd65E7NQF88ZmUP2MaUanqnZg9GFS94W7kND4Ebjq",
        "Lh2G82Bi33RNuzz4UfSMZbh54jnWHVnmw8",
    ),
    (
        "T986ZKRRdnuuXLeDZuKBRrZW1ujotAncU9WTrFU1n7vMgRW75ZtF",
        "LWegHWHB5rmaF5rgWYt1YN3StapRdnGJfU",
    ),
)
# the version byte of a Litecoin WIF, `SECRET_KEY` of the chainparams
# the module's docstring cites
_WIF_VERSION = 176

# the mainnet addresses, and the scriptPubKey of each, that are no
# private key:
#
# repo    litecoin-project/litecoin
# path    src/test/data/key_io_valid.json
# commit  ec1b6489a900d09cf5991e220dce089c77a232a2
# blob    a9aeed9cc54136fe6a5a070354b578627cfb3f8c
_KEY_IO_VALID = (
    (
        "LT2KVaAy1ppRuxRgrS5RNU3vBsy7RibPeA",
        "76a914558dbca7118cd5894502767c7b2ffc21a22f54db88ac",
    ),
    (
        "MHrYRxAiMNBTku3eoDHwhA1LQGDjUStZW2",
        "a9146d328a5b2a20d943a641c8d29b6cc3c2d2df85d387",
    ),
    (
        "M9dw1FAoWpHC6PcMzoCHhqQ9McvTyG5Ywj",
        "a914130ef8742ad7492b389509252c6721775fb1127387",
    ),
    (
        "ltc1qhdhvrwe6rgqns8fz28tee0hphr5x7ulw5exv4w",
        "0014bb6ec1bb3a1a01381d2251d79cbee1b8e86f73ee",
    ),
    (
        "ltc1qa9dykljtgeayhm8ygx25sc22p0wzgudpe4hw9dyvaz0ye3j5kduq9mf68z",
        "0020e95a4b7e4b467a4bece4419548614a0bdc2471a1cd6ee2b48ce89e4cc654b378",
    ),
    (
        "ltc1ppu2gv0tujus0f6eggrk7eqmaf0567x6zer4fcuhz4z7ztzq9u9yseqxltc",
        "51200f14863d7c9720f4eb2840edec837d4be9af1b42c8ea9c72e2a8bc258805e149",
    ),
    ("ltc1zjwls6j8c4u", "520293bf"),
    (
        "LbfVMz974gbbGFqXF7FZUpSBWSbwBHDwR5",
        "76a914b4565f467408e9e1c1d2a3b0ccdeff84db3a3b9388ac",
    ),
    (
        "MWGEAUUZoN4r6puz8KsgnE9wNTQ8fGWCEy",
        "a914f54ec8d7b0c3f8ab8194db3432d19f8d44d03b1287",
    ),
    (
        "MNYP3h6XQQcVBohyVrxAtRGhbyvPpXzyFR",
        "a914a09bd94f4b099d721ddc95bc8ed928aef40833ce87",
    ),
    (
        "ltc1qxjkwr09apz3w5hsr33uyq9sdfx8tn26g39g00g",
        "001434ace1bcbd08a2ea5e038c7840160d498eb9ab48",
    ),
    (
        "ltc1qjaxhjwmp26afq279pza0zd6lrguxfcee08fw4xv5r6ksrr0wk4uqzjxfdz",
        "0020974d793b6156ba902bc508baf1375f1a3864e33979d2ea99941ead018deeb578",
    ),
    (
        "ltc1p59fcnxdn05t6adags3dc0vuvm4ejd7chsspp9ryqkvvlxrwkdylqfsruty",
        "5120a1538999b37d17aeb7a8845b87b38cdd7326fb178402128c80b319f30dd6693e",
    ),
    ("ltc1zpr0qrh9zvs", "520208de"),
    (
        "LgUPnP2UZxmFBJb8FDgNd5JcU9b7CNfrw1",
        "76a914e915c49f55d8de0b6041de19c9fa2f21820b201288ac",
    ),
    (
        "MU2UAbDxiiirZuGTZ6nSaFajsXFkLHozcU",
        "a914dcc465d5dd517c24c4dc95d7a338fca76d753ddb87",
    ),
)

# every string of the file, each invalid on every network:
#
# repo    litecoin-project/litecoin
# path    src/test/data/key_io_invalid.json
# commit  ec1b6489a900d09cf5991e220dce089c77a232a2
# blob    3c9029b86771c36867127f5d1bce24e45fb46ba8
_KEY_IO_INVALID = (
    "",
    "x",
    "dfbPb4pUb4pTX4UQYFUjKyiSF8CQgxugLS62GjwZypEoibsosn9Vb4KVCda1rRWmZmNiRrwvmCn",
    "9HNmZX4VS73qJEWzmNcmXbkQ9TFf6sUTCQ",
    "gjLg9jYHzW5ciXEDz9zWiotzYe2cct2PTtToqpoFgwo4EkCAaDDrofJawHSpRU8ki2bggowiBok",
    "SLrpY37XP4qJryx7fjPZMak4Lxzfo5WShx",
    "kTcGJ65MCfb8jXDWf1sYGEpCyA4kcP9BDk",
    "521Yh6VfYQu5PtUDwaFAvsKAwczLgviqYpgbSxRdRzpjtnmT6JmTUeqsATPFj17ABdvzwPv8uugf9",
    "cUBHNh9Q2nDG6rsPProgGCZJnjUMEMyHWqm6p9eHwQJDPdm5rYBE",
    "7V7qeUyYjXzGsWD7SJRAep6s7kcptC2irxWDgByP1vHNt2cTJGcCDqTH9WRYtkQgx6dYxCtXJwgMk",
    "tc1qqtcszl2x5dm89t8989ylwucwsnqq2pmxxv4wuw",
    "bt1p2c4wcwdszz8qhgg2anf8q4qh3wfvr007f8zjyfud0wneenz85upsfwevl6",
    "tltc13vj87tzu08d9277dqfzafda7snm796xrx3kyv2536km3m3ef7lk7q0yq8hg",
    "RLTC1RUCQRYUFY",
    "ltc10utujc7h82n098qam35qv4sm4kztue0lh04er7zf6lslcwfmhc92kym83guu06nrvl56g2ekm",
    "tltc1qh8tp3qqmtz474xju0rajr3uz8vw00j2r",
    "rltc1q2k5v9aryyn8pqg5dsjy0f8700tq2ph7q3mkcu573fjutlckyu7u3ysyapj",
    "ltc153m7rf",
    "tltc1qywr4l8fyce9u6lwsykq4uez3g8kjfwterfxtjs784m526tavu84qeslpvf",
    "RLTC1QLPJ9XAKFWDYNP49LZ67kvf6FSKWD0P494P5PLT",
    "ltc1qfflgggucfrs482us7q786eew4ryqta3vl2aspf",
    "tltc1q8wdx4az9f0lyvrpumqp74teu99vfay22etgulptz0u3zwl49wc6s2pktf0",
    "rltc1qwvcm8vv0z02rvsx40w37jqhwcsr2rzyy7ksnsq",
    "ltc1pdhzupjn6sdyalpqn2flajzeyh7qw7r68z6zqnky8ns07k2du90jsd76y75",
    "tltc1z8pp8yj2xsvf40fw42suw8fntrchs0pdc",
    "rltc1sp3lm8alrzckqhe6nk29xp2de7qwvhq5e7qe8fa",
    "pLrE7DTSJEqA3EY9pn9xqxGsQQq1ZodMq9",
    "ftPq56BTH4DpneHagKmzzoaFaNzKKtJzNnTw1HKUAHuKoHHANUTkSh8PW1ETaDJARc9B1PzwVok",
    "2MwUPLQvSc9iamSJ4bKEGM7gHBaZeP9LNxp",
    "DHTtS2VMFFKgjtNzvPBmhzkhxpVdQEX8CfEt8h72xDrn9A8LFzUbseFtVPbzAmTPysdDTcQM8iS",
    "2N1evLCwGTML3dbW9PRk8nEgGYNb3rxG5RtN",
    "T3zMzNuAAXou7nsh1ah6y1Mrj9DZ2Wgx5yoqiSsrxiQbfw57BHrz",
    "oEPMsv4V5qZKoUyfNeCz1Z87PzPohDwhvJDd4UKivg4PWSen16kAZokNyTveoNrzowQEXaxRi8J",
    "cU6LESh6ttsCfCf4xQXv3CrNY4JHWACNoJCDrbVaRj3WYpyUCGzV",
    "tc1q8s7jrus7u2qgdm895pyv30le3cprehalv9lnc3",
    "bt1paw9uw7srejsczdlfe28xwdyqzk8lrjw9x8jdqw6pr2pwd2v9ywusum6u0n",
    "tltc13vgu624uk8ft5ll4aa2mpawe8xj63dxzzyn73zv9920n3v9p4xlvs46fqn5",
    "rltc1rvgnh26gv",
    "ltc10wqhm0mq4dq3gcckz0vpa00k62awh67cdwymfu6jc2jttg8n8sdwjdy6hst25zf37fcneh0fh",
    "tltc1qnmrmqt9d459t7yed75t97w85rvhpm2lu",
    "rltc1qddrre03z0h5qcg5y4qcyhzh9jera7zue8uv4y5nttg44gtyy8gc3w0j0ra",
    "ltc1qc7c53klkh5hhutxursumtl4eevq03vhzq",
    "tltc1q8j0kqm4q2w34kval4px7yauhq02hzy5xqp8jazsvu9zj8ptzhf5qzd7fee",
    "rltc1q9yk0zwnmamlt09wz6yu3v03xwcfnZQ8Ae8tmyc",
    "ltc1qc243zefnc9kzmsw72nytw4542g9nhwlxepjl6l",
    "tltc1qve28jd595ssf2usq5rhw24ehsny2f4tg62emue3q9wm40t7hplmqlftk8j",
    "rltc1q7mqj6cpffp32z0vksng3z5fr9fvhtt9mrgxrj8",
    "ltc1pt9dz00jx8y7x8ylmwe8q0llyrzs32px96wgsm8znsnmj9cgs0ffszkcwyf",
    "tltc1zhf4exwjxy7gh08najmlq4qn37uhvrzsv",
    "rltc14aymck",
    "2J5Aw2ADD73uDiWjBygH9v9CUc4FoMCnpXmdA3ArF5eG2M3quPMZcVzL7D6FbijsGcsq6dohRrm5",
    "2CyfoCce6BLYfKyAjW6n7x1gie1VMWwnKuZdq4U2MnaYzqSg1NKs6i66DQnGPGzwv33UM5cJehsk",
    "A2oWG2iWYa3NvYJ5r8JcxYCcEeHDP7LGCSMWQFQePa5QuAYsfNHS",
    "928oyNBWu1x44NuMptnH95toXArxtJBXLsJVg4xBTJuf92Q3HHXy",
    "cTMLykLqdEAst53pvxkJ5urLdXAU4zqhwzAwnurEWowy9d36ABYs",
    "cS2qXYzEZkoTgxp3xKBAXFXEQ1TcD9LLoGTpvMSr45o2rfxu1SAj",
    "AyUHw9wePktAhQPe4CUfGD6iU6tP7zGUSUPjp4GkmUj3dqVPDFw4",
    "tc1q8e3cz8e6jxrylsvmc7ng595rvn2m74ka5nhmyz",
    "bt1pyaatm98c7wmepfv558k6vt9zhtls6rdggelh86wyahsgye3h7vyst22puy",
    "tltc1355kwhrv2gsc7fyfma88nxqqzs3mmlcetg29cpfrd39hp2xjd3jwsrz78uv",
    "rltc1r55jrpej6",
    "ltc1pdtjxt",
    "tltc1gut4t3",
    "rltc1qnv2uheg45ns07mv6f0h82xz48xzahaemlvxczexnl74jglwvetqp73s7wn",
    "ltc1q0susza3qwj6lyp7d2q6g258vrgqw4afzt",
    "tltc1qsv7l20xzequp2hvtpmyc0nw6mmefyd0zj4a27y0jgkr2mcypfnss4fc7ky",
    "rltc1qu8qwtg4kx886ex2frzcp4v9lk9V440cd75ch47",
    "LTC1Q3ME3JU4NWKE72UUETHLKLZMWQAVTDG4AG8FXSK",
    "tltc1qc5d8gx5zm4vwufpp8galregpckfx52jfwyxtpng8pamd37g0pv3svfvnu4",
    "RLTC1QR29H2QPX85CF7PCHDLWU8L7J4NZ2TW5LA5FFZM",
)

# public keys and the P2WPKH or P2SH-P2WPKH address of each, from a
# library outside the coin's own, which derives them end to end: the
# Litecoin mainnet entries of
#
# repo    ebellocchia/bip_utils
# commit  286f03d36c80e1a7229d9586dd3651f5f73ba9b4
# path    tests/addr/test_P2WPKH.py
# blob    8e36d79854bc3782325c37ea35df490630d8d490
# path    tests/addr/test_P2SH.py
# blob    381e2415cfd59029009dadd3626f84ab4e573949
_BIP_UTILS = (
    (
        "021c1750d4a5ad543967b30e9447e50da7a5873e8be133eb25f2ce0ea5638b9d17",
        "p2wpkh",
        "ltc1qwlezpr3890hcp6vva9twqh27mr6edadreqvhnn",
    ),
    (
        "0201084ea04fa9619a056281e7c87a97693f67e5baa4ec604e7e8245b84e31cc96",
        "p2wpkh",
        "ltc1qdjtr2jc5uu6r0ss2fcey3djvkhlu7jux420fhr",
    ),
    (
        "0224ca66698d0c4865a8718a3d35c696f140e4d15c24f4d9415e599db3d75daf39",
        "p2sh-p2wpkh",
        "MJfELhwt9S6Sr9hadHGsnTELZzFUVjMrFc",
    ),
    (
        "039b6933bd6bb28bf30895756d2c7ce11b7c6bc20e6f51ca472463128da1402359",
        "p2sh-p2wpkh",
        "MQJA6RzwpcX4BWUCqSqxDCLfYHzgYna6cr",
    ),
)

# the seed of the generated keys, fixed so that two runs ask the same
_SEED = 2011


def _point_of_wif(wif: str) -> tuple[int, int]:
    """Return the public key of a compressed Litecoin WIF."""
    payload = b58decode_check(wif)
    assert payload[0] == _WIF_VERSION
    assert len(payload) == 34
    assert payload[-1] == 1
    return mult(int.from_bytes(payload[1:33], "big"), secp256k1.G, secp256k1)


def _address_of_script(script: str) -> str:
    """Return the Litecoin address of a scriptPubKey, segwit in lower case."""
    octets = bytes.fromhex(script)
    if octets[:3] == b"\x76\xa9\x14":
        return base58_address(48, octets[3:23], alphabet=BITCOIN_ALPHABET)
    if octets[:2] == b"\xa9\x14":
        return base58_address(50, octets[2:22], alphabet=BITCOIN_ALPHABET)
    version = 0 if octets[0] == 0 else octets[0] - 0x50
    return litecoin._segwit_address(version, octets[2:])


@pytest.mark.parametrize("wif, address", _KEY_TESTS)
def test_a_key_of_litecoin_core_gives_its_address(wif: str, address: str) -> None:
    """Litecoin Core's test keys give Litecoin Core's P2PKH addresses."""
    point = _point_of_wif(wif)
    assert address_from_pub_key(point) == address
    assert address_from_pub_key(point, script_type="p2pkh") == address
    assert is_valid_address(address)


@pytest.mark.parametrize("pub_key, script_type, address", _BIP_UTILS)
def test_a_key_gives_the_address_another_library_derives(
    pub_key: str, script_type: str, address: str
) -> None:
    """The two segwit script types, against an independent derivation."""
    assert address_from_pub_key(pub_key, script_type=script_type) == address
    assert is_valid_address(address)


@pytest.mark.parametrize("address, script", _KEY_IO_VALID)
def test_an_address_of_litecoin_core_is_valid(address: str, script: str) -> None:
    """Each mainnet address is valid, and encodes its script's hash.

    The segwit ones are valid in upper case too, as the file's
    `tryCaseFlip` says.
    """
    assert_valid_address(address)
    assert address == _address_of_script(script)
    if address.startswith("ltc1"):
        assert is_valid_address(address.upper())


@pytest.mark.parametrize("address", _KEY_IO_INVALID)
def test_an_invalid_string_of_litecoin_core_is_refused(address: str) -> None:
    """Each invalid string is refused, and the refusal does not quote it."""
    assert not is_valid_address(address)
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    if len(address) > 12:
        assert_secret_free(caught.value, [address])


def test_the_bitcoin_p2sh_version_byte_is_read() -> None:
    """A P2SH address of version byte 5, a leading 3, is still valid.

    Litecoin Core reads it, and writes P2SH with 50, a leading M.
    """
    digest = bytes.fromhex("6d328a5b2a20d943a641c8d29b6cc3c2d2df85d3")
    address = base58_address(5, digest, alphabet=BITCOIN_ALPHABET)
    assert address.startswith("3")
    assert is_valid_address(address)
    assert base58_address(50, digest, alphabet=BITCOIN_ALPHABET) == _KEY_IO_VALID[1][0]


def test_the_three_script_types_hold_over_generated_keys() -> None:
    """A property over keys from a fixed seed.

    Each script type gives a valid address, P2PKH a leading L,
    P2SH-P2WPKH a leading M, P2WPKH the HRP; the three differ; and a
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
        assert addresses["p2pkh"].startswith("L")
        assert addresses["p2sh-p2wpkh"].startswith("M")
        assert addresses["p2wpkh"].startswith("ltc1q")
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
            base58_address(48, bytes(19), alphabet=BITCOIN_ALPHABET),
            "19-byte hash for version byte 48",
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
    address = litecoin._segwit_address(version, program)
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    assert str(caught.value).endswith(f"nor a segwit one ({reason})")


def test_a_segwit_address_with_the_wrong_checksum_is_refused() -> None:
    """Version 0 in bech32m, and version 1 in bech32, as BIP350 says."""
    v0 = bech32_encode(
        "ltc", [0, *convertbits(bytes(20), 8, 5)], m=BECH32_M_CONST
    ).decode("ascii")
    v1 = bech32_encode(
        "ltc", [1, *convertbits(bytes(32), 8, 5)], m=BECH32_1_CONST
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
    address = bech32_encode("ltc", data, m=BECH32_M_CONST).decode("ascii")
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    assert str(caught.value).endswith(f"nor a segwit one ({reason})")


def test_another_hrp_is_refused() -> None:
    """Bitcoin's P2WPKH address of BIP173's example key is not Litecoin's."""
    address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    assert str(caught.value).endswith("nor a segwit one (not the Litecoin HRP)")


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
    for spelling in (uncompressed, uncompressed.hex(), bytearray(uncompressed)):
        with pytest.raises(CoinAddressesValueError, match="uncompressed public key"):
            address_from_pub_key(spelling)


@pytest.mark.parametrize("address", [None, b"ltc1q", 0, ["L"]])
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
@pytest.mark.parametrize("address", [_KEY_TESTS[0][1], _KEY_IO_VALID[3][0]])
def test_whitespace_around_an_address_is_refused(
    before: str, after: str, address: str
) -> None:
    """An address with whitespace around it is refused.

    Litecoin Core skips whitespace around a legacy address, and
    `coin_addresses._bitcoin` says why this package does not.
    """
    assert is_valid_address(address)
    padded = f"{before}{address}{after}"
    with pytest.raises(CoinAddressesValueError):
        assert_valid_address(padded)
    assert not is_valid_address(padded)
