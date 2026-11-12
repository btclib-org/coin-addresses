# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for Bitcoin Cash addresses: CashAddr and legacy, the validation."""

from __future__ import annotations

import random

import pytest
from base58_bech32.base58 import b58decode_check
from base58_bech32.cashaddr import cashaddr_decode, cashaddr_encode
from base58_bech32.exceptions import Base58Bech32ValueError
from ecc.curves import PreparedPoint, bytes_from_point, mult, secp256k1

from coin_addresses._bitcoin import base58_address
from coin_addresses.bitcoin_cash import (
    address_from_pub_key,
    assert_valid_address,
    is_valid_address,
    legacy_address_from_pub_key,
)
from coin_addresses.exceptions import CoinAddressesTypeError, CoinAddressesValueError

from .secret_free import assert_secret_free

# the specification, whose tables and checksum vectors are transcribed
# below:
#
# repo    bitcoincashorg/bitcoincash.org
# path    spec/cashaddr.md
# commit  3e2e6da8c38dab7ba12149d327bc4b259aaad684
# blob    c2c798b5bdefd68ba5aa6482440ddcda4531cc70
#
# "Examples of address translation": a legacy address and the CashAddr
# one of the same type and hash
_TRANSLATION = (
    (
        "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu",
        "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
    ),
    (
        "1KXrWXciRDZUpQwQmuM1DbwsKDLYAYsVLR",
        "bitcoincash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy",
    ),
    (
        "16w1D5WRVKJuZUsSRzdLp9w3YGcgoxDXb",
        "bitcoincash:qqq3728yw0y47sqn6l2na30mcw6zm78dzqre909m2r",
    ),
    (
        "3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC",
        "bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq",
    ),
    (
        "3LDsS579y7sruadqu11beEJoTjdFiFCdX4",
        "bitcoincash:pr95sy3j9xwd2ap32xkykttr4cvcu7as4yc93ky28e",
    ),
    (
        "31nwvkZwyPdgzjBJZXfDmSWsC4ZLKpYyUw",
        "bitcoincash:pqq3728yw0y47sqn6l2na30mcw6zm78dzq5ucqzc37",
    ),
)

# "Larger Test Vectors": an address, its type and its hash
_LARGER = (
    (
        "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
        0,
        "f5bf48b397dae70be82b3cca4793f8eb2b6cdac9",
    ),
    (
        "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t",
        1,
        "f5bf48b397dae70be82b3cca4793f8eb2b6cdac9",
    ),
    (
        "pref:pr6m7j9njldwwzlg9v7v53unlr4jkmx6ey65nvtks5",
        1,
        "f5bf48b397dae70be82b3cca4793f8eb2b6cdac9",
    ),
    (
        "prefix:0r6m7j9njldwwzlg9v7v53unlr4jkmx6ey3qnjwsrf",
        15,
        "f5bf48b397dae70be82b3cca4793f8eb2b6cdac9",
    ),
    (
        "bitcoincash:q9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2ws4mr9g0",
        0,
        "7adbf6c17084bc86c1706827b41a56f5ca32865925e946ea",
    ),
    (
        "bchtest:p9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2u94tsynr",
        1,
        "7adbf6c17084bc86c1706827b41a56f5ca32865925e946ea",
    ),
    (
        "pref:p9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2khlwwk5v",
        1,
        "7adbf6c17084bc86c1706827b41a56f5ca32865925e946ea",
    ),
    (
        "prefix:09adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2p29kc2lp",
        15,
        "7adbf6c17084bc86c1706827b41a56f5ca32865925e946ea",
    ),
    (
        "bitcoincash:qgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcw59jxxuz",
        0,
        "3a84f9cf51aae98a3bb3a78bf16a6183790b18719126325bfc0c075b",
    ),
    (
        "bchtest:pgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcvs7md7wt",
        1,
        "3a84f9cf51aae98a3bb3a78bf16a6183790b18719126325bfc0c075b",
    ),
    (
        "pref:pgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcrsr6gzkn",
        1,
        "3a84f9cf51aae98a3bb3a78bf16a6183790b18719126325bfc0c075b",
    ),
    (
        "prefix:0gagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkc5djw8s9g",
        15,
        "3a84f9cf51aae98a3bb3a78bf16a6183790b18719126325bfc0c075b",
    ),
    (
        "bitcoincash:qvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq5nlegake",
        0,
        "3173ef6623c6b48ffd1a3dcc0cc6489b0a07bb47a37f47cfef4fe69de825c060",
    ),
    (
        "bchtest:pvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq7fqng6m6",
        1,
        "3173ef6623c6b48ffd1a3dcc0cc6489b0a07bb47a37f47cfef4fe69de825c060",
    ),
    (
        "pref:pvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq4k9m7qf9",
        1,
        "3173ef6623c6b48ffd1a3dcc0cc6489b0a07bb47a37f47cfef4fe69de825c060",
    ),
    (
        "prefix:0vch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxqsh6jgp6w",
        15,
        "3173ef6623c6b48ffd1a3dcc0cc6489b0a07bb47a37f47cfef4fe69de825c060",
    ),
    (
        "bitcoincash:qnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklv39gr3uvz",
        0,
        "c07138323e00fa4fc122d3b85b9628ea810b3f381706385e289b0b25631197d194b5c238beb136fb",
    ),
    (
        "bchtest:pnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklvmgm6ynej",
        1,
        "c07138323e00fa4fc122d3b85b9628ea810b3f381706385e289b0b25631197d194b5c238beb136fb",
    ),
    (
        "pref:pnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklv0vx5z0w3",
        1,
        "c07138323e00fa4fc122d3b85b9628ea810b3f381706385e289b0b25631197d194b5c238beb136fb",
    ),
    (
        "prefix:0nq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklvwsvctzqy",
        15,
        "c07138323e00fa4fc122d3b85b9628ea810b3f381706385e289b0b25631197d194b5c238beb136fb",
    ),
    (
        "bitcoincash:qh3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqex2w82sl",
        0,
        "e361ca9a7f99107c17a622e047e3745d3e19cf804ed63c5c40c6ba763696b98241223d8ce62ad48d863f4cb18c930e4c",
    ),
    (
        "bchtest:ph3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqnzf7mt6x",
        1,
        "e361ca9a7f99107c17a622e047e3745d3e19cf804ed63c5c40c6ba763696b98241223d8ce62ad48d863f4cb18c930e4c",
    ),
    (
        "pref:ph3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqjntdfcwg",
        1,
        "e361ca9a7f99107c17a622e047e3745d3e19cf804ed63c5c40c6ba763696b98241223d8ce62ad48d863f4cb18c930e4c",
    ),
    (
        "prefix:0h3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqakcssnmn",
        15,
        "e361ca9a7f99107c17a622e047e3745d3e19cf804ed63c5c40c6ba763696b98241223d8ce62ad48d863f4cb18c930e4c",
    ),
    (
        "bitcoincash:qmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqscw8jd03f",
        0,
        "d9fa7c4c6ef56dc4ff423baae6d495dbff663d034a72d1dc7d52cbfe7d1e6858f9d523ac0a7a5c34077638e4dd1a701bd017842789982041",
    ),
    (
        "bchtest:pmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqs6kgdsg2g",
        1,
        "d9fa7c4c6ef56dc4ff423baae6d495dbff663d034a72d1dc7d52cbfe7d1e6858f9d523ac0a7a5c34077638e4dd1a701bd017842789982041",
    ),
    (
        "pref:pmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqsammyqffl",
        1,
        "d9fa7c4c6ef56dc4ff423baae6d495dbff663d034a72d1dc7d52cbfe7d1e6858f9d523ac0a7a5c34077638e4dd1a701bd017842789982041",
    ),
    (
        "prefix:0mvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqsgjrqpnw8",
        15,
        "d9fa7c4c6ef56dc4ff423baae6d495dbff663d034a72d1dc7d52cbfe7d1e6858f9d523ac0a7a5c34077638e4dd1a701bd017842789982041",
    ),
    (
        "bitcoincash:qlg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96mtky5sv5w",
        0,
        "d0f346310d5513d9e01e299978624ba883e6bda8f4c60883c10f28c2967e67ec77ecc7eeeaeafc6da89fad72d11ac961e164678b868aeeec5f2c1da08884175b",
    ),
    (
        "bchtest:plg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96mc773cwez",
        1,
        "d0f346310d5513d9e01e299978624ba883e6bda8f4c60883c10f28c2967e67ec77ecc7eeeaeafc6da89fad72d11ac961e164678b868aeeec5f2c1da08884175b",
    ),
    (
        "pref:plg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96mg7pj3lh8",
        1,
        "d0f346310d5513d9e01e299978624ba883e6bda8f4c60883c10f28c2967e67ec77ecc7eeeaeafc6da89fad72d11ac961e164678b868aeeec5f2c1da08884175b",
    ),
    (
        "prefix:0lg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96ms92w6845",
        15,
        "d0f346310d5513d9e01e299978624ba883e6bda8f4c60883c10f28c2967e67ec77ecc7eeeaeafc6da89fad72d11ac961e164678b868aeeec5f2c1da08884175b",
    ),
)

# the "test vector for checksum computation", whose payloads are not
# valid on purpose
_CHECKSUM = (
    "prefix:x64nx6hz",
    "p:gpf8m4h7",
    "bitcoincash:qpzry9x8gf2tvdw0s3jn54khce6mua7lcw20ayyn",
    "bchtest:testnetaddress4d6njnut",
    "bchreg:555555555555555555555555555555555555555555555udxmlmrz",
)

# the entries with the mainnet prefix, an address, its type and its hash:
#
# repo    bitcoin-cash-node/bitcoin-cash-node (gitlab.com)
# path    src/test/data/cashaddr_token_types.json
# commit  e13b48e37b3005dca9a316f75aea456697a5dfd6
# blob    28afff7d5cc83969aa336404f4433d0eba846156
_TOKEN_TYPES = (
    (
        "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
        0,
        "f5bf48b397dae70be82b3cca4793f8eb2b6cdac9",
    ),
    (
        "bitcoincash:zr6m7j9njldwwzlg9v7v53unlr4jkmx6eycnjehshe",
        2,
        "f5bf48b397dae70be82b3cca4793f8eb2b6cdac9",
    ),
    (
        "bitcoincash:qr7fzmep8g7h7ymfxy74lgc0v950j3r2959lhtxxsl",
        0,
        "fc916f213a3d7f1369313d5fa30f6168f9446a2d",
    ),
    (
        "bitcoincash:zr7fzmep8g7h7ymfxy74lgc0v950j3r295z4y4gq0v",
        2,
        "fc916f213a3d7f1369313d5fa30f6168f9446a2d",
    ),
    (
        "bitcoincash:qpagr634w55t4wp56ftxx53xukhqgl24yse53qxdge",
        0,
        "7a81ea357528bab834d256635226e5ae047d5524",
    ),
    (
        "bitcoincash:zpagr634w55t4wp56ftxx53xukhqgl24ys77z7gth2",
        2,
        "7a81ea357528bab834d256635226e5ae047d5524",
    ),
    (
        "bitcoincash:qq9l9e2dgkx0hp43qm3c3h252e9euugrfc6vlt3r9e",
        0,
        "0bf2e54d458cfb86b106e388dd54564b9e71034e",
    ),
    (
        "bitcoincash:zq9l9e2dgkx0hp43qm3c3h252e9euugrfcaxv4l962",
        2,
        "0bf2e54d458cfb86b106e388dd54564b9e71034e",
    ),
    (
        "bitcoincash:qre24q38ghy6k3pegpyvtxahu8q8hqmxmqqn28z85p",
        0,
        "f2aa822745c9ab44394048c59bb7e1c07b8366d8",
    ),
    (
        "bitcoincash:zre24q38ghy6k3pegpyvtxahu8q8hqmxmq8eeevptj",
        2,
        "f2aa822745c9ab44394048c59bb7e1c07b8366d8",
    ),
    (
        "bitcoincash:qz7xc0vl85nck65ffrsx5wvewjznp9lflgktxc5878",
        0,
        "bc6c3d9f3d278b6a8948e06a399974853097e9fa",
    ),
    (
        "bitcoincash:zz7xc0vl85nck65ffrsx5wvewjznp9lflg3p4x6pp5",
        2,
        "bc6c3d9f3d278b6a8948e06a399974853097e9fa",
    ),
    (
        "bitcoincash:ppawqn2h74a4t50phuza84kdp3794pq3ccvm92p8sh",
        1,
        "7ae04d57f57b55d1e1bf05d3d6cd0c7c5a8411c6",
    ),
    (
        "bitcoincash:rpawqn2h74a4t50phuza84kdp3794pq3cct3k50p0y",
        3,
        "7ae04d57f57b55d1e1bf05d3d6cd0c7c5a8411c6",
    ),
    (
        "bitcoincash:pqv53dwyatxse2xh7nnlqhyr6ryjgfdtagkd4vc388",
        1,
        "1948b5c4eacd0ca8d7f4e7f05c83d0c92425abea",
    ),
    (
        "bitcoincash:rqv53dwyatxse2xh7nnlqhyr6ryjgfdtag38xjkhc5",
        3,
        "1948b5c4eacd0ca8d7f4e7f05c83d0c92425abea",
    ),
    (
        "bitcoincash:prseh0a4aejjcewhc665wjqhppgwrz2lw5txgn666a",
        1,
        "e19bbfb5ee652c65d7c6b54748170850e1895f75",
    ),
    (
        "bitcoincash:rrseh0a4aejjcewhc665wjqhppgwrz2lw5vvmd5u9w",
        3,
        "e19bbfb5ee652c65d7c6b54748170850e1895f75",
    ),
    (
        "bitcoincash:pzltaslh7xnrsxeqm7qtvh0v53n3gfk0v5wwf6d7j4",
        1,
        "bebec3f7f1a6381b20df80b65deca4671426cf65",
    ),
    (
        "bitcoincash:rzltaslh7xnrsxeqm7qtvh0v53n3gfk0v5fy6yrcdx",
        3,
        "bebec3f7f1a6381b20df80b65deca4671426cf65",
    ),
    (
        "bitcoincash:pvqqqqqqqqqqqqqqqqqqqqqqzg69v7ysqqqqqqqqqqqqqqqqqqqqqpkp7fqn0",
        1,
        "0000000000000000000000000000123456789000000000000000000000000000",
    ),
    (
        "bitcoincash:rvqqqqqqqqqqqqqqqqqqqqqqzg69v7ysqqqqqqqqqqqqqqqqqqqqqn9alsp2y",
        3,
        "0000000000000000000000000000123456789000000000000000000000000000",
    ),
    (
        "bitcoincash:pdzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3jh2p5nn",
        1,
        "4444444444444444444444444444444444444444444444444444444444444444",
    ),
    (
        "bitcoincash:rdzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygrpttc42c",
        3,
        "4444444444444444444444444444444444444444444444444444444444444444",
    ),
    (
        "bitcoincash:pwyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsh3sujgcr",
        1,
        "8888888888888888888888888888888888888888888888888888888888888888",
    ),
    (
        "bitcoincash:rwyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9zvatfpg",
        3,
        "8888888888888888888888888888888888888888888888888888888888888888",
    ),
    (
        "bitcoincash:p0xvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvcm6gz4t77",
        1,
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    ),
    (
        "bitcoincash:r0xvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvcff5rv284",
        3,
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    ),
    (
        "bitcoincash:p0llllllllllllllllllllllllllllllllllllllllllllllllll7x3vthu35",
        1,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ),
    (
        "bitcoincash:r0llllllllllllllllllllllllllllllllllllllllllllllllll75zs2wagl",
        3,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ),
    (
        "bitcoincash:q9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2ws4mr9g0",
        0,
        "7adbf6c17084bc86c1706827b41a56f5ca32865925e946ea",
    ),
    (
        "bitcoincash:qgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcw59jxxuz",
        0,
        "3a84f9cf51aae98a3bb3a78bf16a6183790b18719126325bfc0c075b",
    ),
    (
        "bitcoincash:qvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq5nlegake",
        0,
        "3173ef6623c6b48ffd1a3dcc0cc6489b0a07bb47a37f47cfef4fe69de825c060",
    ),
    (
        "bitcoincash:qnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklv39gr3uvz",
        0,
        "c07138323e00fa4fc122d3b85b9628ea810b3f381706385e289b0b25631197d194b5c238beb136fb",
    ),
    (
        "bitcoincash:qh3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqex2w82sl",
        0,
        "e361ca9a7f99107c17a622e047e3745d3e19cf804ed63c5c40c6ba763696b98241223d8ce62ad48d863f4cb18c930e4c",
    ),
    (
        "bitcoincash:qmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqscw8jd03f",
        0,
        "d9fa7c4c6ef56dc4ff423baae6d495dbff663d034a72d1dc7d52cbfe7d1e6858f9d523ac0a7a5c34077638e4dd1a701bd017842789982041",
    ),
    (
        "bitcoincash:qlg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96mtky5sv5w",
        0,
        "d0f346310d5513d9e01e299978624ba883e6bda8f4c60883c10f28c2967e67ec77ecc7eeeaeafc6da89fad72d11ac961e164678b868aeeec5f2c1da08884175b",
    ),
)

# the mainnet addresses, and the scriptPubKey of each, that are no
# private key:
#
# repo    bitcoin-cash-node/bitcoin-cash-node (gitlab.com)
# path    src/test/data/key_io_valid.json
# commit  e13b48e37b3005dca9a316f75aea456697a5dfd6
# blob    8352901bdfcae1acb7c734d13926393c6e5796cd
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
    (
        "Brc3AngqMnEgM3xi4ANgu1coWvSRwgXvK3uMxidgWALk72ihur",
        "aa209597d6599cfcec094a56d68a262f351e1377bd3015f946daf11053301e6501c087",
    ),
)

# every string of the file:
#
# repo    bitcoin-cash-node/bitcoin-cash-node (gitlab.com)
# path    src/test/data/key_io_invalid.json
# commit  e13b48e37b3005dca9a316f75aea456697a5dfd6
# blob    ab12a1acafd82946f80e4679a6874668b05bc6fa
_KEY_IO_INVALID = (
    "",
    "x",
    "37qgekLpCCHrQuSjvX3fs496FWTGsHFHizjJAs6NPcR47aefnnCWECAhHV6E3g4YN7u7Yuwod5Y",
    "dzb7VV1Ui55BARxv7ATxAtCUeJsANKovDGWFVgpTbhq9gvPqP3yv",
    "MuNu7ZAEDFiHthiunm7dPjwKqrVNCM3mAz6rP9zFveQu14YA8CxExSJTHcVP9DErn6u84E6Ej7S",
    "rPpQpYknyNQ5AEHuY6H8ijJJrYc2nDKKk9jjmKEXsWzyAQcFGpDLU2Zvsmoi8JLR7hAwoy3RQWf",
    "4Uc3FmN6NQ6zLBK5QQBXRBUREaaHwCZYsGCueHauuDmJpZKn6jkEskMB2Zi2CNgtb5r6epWEFfUJq",
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

# two private keys, as compressed WIF, and the legacy P2PKH address of
# each one's public key, `strSecret1C`, `strSecret2C`, `addr1C` and
# `addr2C`:
#
# repo    bitcoin-cash-node/bitcoin-cash-node (gitlab.com)
# path    src/test/key_tests.cpp
# commit  e13b48e37b3005dca9a316f75aea456697a5dfd6
# blob    6113d6f34ea68628f92c06b9934aadcc208b262e
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
# the version byte of a Bitcoin Cash WIF, `SECRET_KEY` of the chainparams
# the module's docstring cites
_WIF_VERSION = 128

# public keys and the CashAddr P2PKH address of each, from a library
# outside the coin's own, which derives them end to end: the mainnet
# entries of
#
# repo    ebellocchia/bip_utils
# commit  286f03d36c80e1a7229d9586dd3651f5f73ba9b4
# path    tests/addr/test_bch_P2PKH.py
# blob    a3f144f980d2f9461e0bfb72073a44e82829b199
_BIP_UTILS = (
    (
        "03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e",
        "bitcoincash:qrvcdmgpk73zyfd8pmdl9wnuld36zh9n4gms8s0u59",
    ),
    (
        "02b5cbfe6ee73b7c5e968e1c515a964894f306a7c882dd18433ab4e16a66d36972",
        "bitcoincash:qpceft8d22pq4894wm9nh673y9rz7wwtpu6ryz8hlr",
    ),
)

# the hash sizes each CashAddr type takes, as the module's docstring says
_SIZES = {0: (20,), 1: (20, 32), 2: (20,), 3: (20, 32)}

# the seed of the generated keys, fixed so that two runs ask the same
_SEED = 2017


def _point_of_wif(wif: str) -> tuple[int, int]:
    """Return the public key of a compressed Bitcoin Cash WIF."""
    payload = b58decode_check(wif)
    assert payload[0] == _WIF_VERSION
    assert len(payload) == 34
    assert payload[-1] == 1
    return mult(int.from_bytes(payload[1:33], "big"), secp256k1.G, secp256k1)


def _is_mainnet_destination(address: str, kind: int, digest: str) -> bool:
    """Whether Bitcoin Cash Node reads a mainnet destination from a CashAddr."""
    if not address.startswith("bitcoincash:"):
        return False
    return len(digest) // 2 in _SIZES.get(kind, ())


@pytest.mark.parametrize("wif, address", _KEY_TESTS)
def test_a_key_of_bitcoin_cash_node_gives_its_address(wif: str, address: str) -> None:
    """Bitcoin Cash Node's test keys give its legacy addresses.

    The CashAddr address of each key carries the same hash.
    """
    point = _point_of_wif(wif)
    assert legacy_address_from_pub_key(point) == address
    cashaddr = address_from_pub_key(point)
    assert cashaddr_decode(cashaddr) == (
        "bitcoincash",
        0,
        b58decode_check(address)[1:],
    )
    assert is_valid_address(address)
    assert is_valid_address(cashaddr)


@pytest.mark.parametrize("pub_key, address", _BIP_UTILS)
def test_a_key_gives_the_address_another_library_derives(
    pub_key: str, address: str
) -> None:
    """The CashAddr derivation, against an independent one."""
    assert address_from_pub_key(pub_key) == address


@pytest.mark.parametrize("legacy, cashaddr", _TRANSLATION)
def test_the_specifications_translations_are_valid(legacy: str, cashaddr: str) -> None:
    """Both forms are valid, and carry the same hash and type."""
    assert_valid_address(legacy)
    assert_valid_address(cashaddr)
    version = b58decode_check(legacy)[0]
    _, kind, digest = cashaddr_decode(cashaddr)
    assert (version, kind) in {(0, 0), (5, 1)}
    assert base58_address(version, digest) == legacy
    assert cashaddr_encode("bitcoincash", kind, digest).decode("ascii") == cashaddr


@pytest.mark.parametrize("address, kind, digest", _LARGER + _TOKEN_TYPES)
def test_a_cashaddr_vector_is_read_as_bitcoin_cash_node_reads_it(
    address: str, kind: int, digest: str
) -> None:
    """The codec reads each vector's type and hash, and validation follows.

    Only the mainnet prefix, a known type, and a hash size that type
    takes make an address of Bitcoin Cash.
    """
    prefix = address.partition(":")[0]
    assert cashaddr_decode(address) == (prefix, kind, bytes.fromhex(digest))
    assert is_valid_address(address) is _is_mainnet_destination(address, kind, digest)


def test_the_vectors_reach_both_answers() -> None:
    """The test above is not answered the same way for every vector."""
    answers = {_is_mainnet_destination(*vector) for vector in _LARGER + _TOKEN_TYPES}
    assert answers == {True, False}


@pytest.mark.parametrize("address", _CHECKSUM)
def test_a_checksum_vector_is_refused_for_its_payload(address: str) -> None:
    """The checksum verifies, with the prefix in it, and the payload does not.

    The codec refuses each vector for what its payload holds, past the
    checksum, and validation refuses it too.
    """
    with pytest.raises(Base58Bech32ValueError) as caught:
        cashaddr_decode(address)
    assert str(caught.value) != "invalid checksum"
    assert not is_valid_address(address)


def test_the_prefix_is_in_the_checksum() -> None:
    """A valid address under another prefix fails its checksum.

    Left out, the prefix is still verified, as `bitcoincash`; in upper
    case the address is valid, and in mixed case it is refused.
    """
    address = _TRANSLATION[0][1]
    payload = address.partition(":")[2]
    assert is_valid_address(payload)
    assert is_valid_address(address.upper())
    assert not is_valid_address(address[:-1] + address[-1].upper())
    for other in ("bchtest", "bitcoincasx"):
        with pytest.raises(CoinAddressesValueError) as caught:
            assert_valid_address(f"{other}:{payload}")
        assert str(caught.value).startswith(
            "neither a CashAddr address (CashAddr prefix is not the one given)"
        )
    # the payload of the specification's checksum vector for bchtest,
    # under the mainnet prefix, fails the checksum
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address("testnetaddress4d6njnut")
    assert str(caught.value).startswith("neither a CashAddr address (invalid checksum)")


@pytest.mark.parametrize("address, script", _KEY_IO_VALID)
def test_a_legacy_address_of_bitcoin_cash_node_is_valid(
    address: str, script: str
) -> None:
    """Each mainnet legacy address is valid, and encodes its script's hash.

    A 32-byte P2SH hash, P2SH32, is among them.
    """
    assert_valid_address(address)
    octets = bytes.fromhex(script)
    if octets[:3] == b"\x76\xa9\x14":
        assert base58_address(0, octets[3:23]) == address
    else:
        assert octets[0] in {0xA9, 0xAA}
        assert base58_address(5, octets[2:-1]) == address


@pytest.mark.parametrize("address", _KEY_IO_INVALID)
def test_an_invalid_string_of_bitcoin_cash_node_is_refused(address: str) -> None:
    """Each invalid string is refused, and the refusal does not quote it."""
    assert not is_valid_address(address)
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    if len(address) > 12:
        assert_secret_free(caught.value, [address])


def test_the_derivation_holds_over_generated_keys() -> None:
    """A property over keys from a fixed seed.

    The two addresses of each key are valid and carry one hash, and a
    point, its compressed encoding and a prepared point give the same
    addresses.
    """
    rng = random.Random(_SEED)
    for _ in range(16):
        point = mult(rng.randrange(1, secp256k1.n), secp256k1.G, secp256k1)
        compressed = bytes_from_point(point, secp256k1)
        cashaddr = address_from_pub_key(point)
        legacy = legacy_address_from_pub_key(point)
        assert cashaddr.startswith("bitcoincash:q")
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
        (
            cashaddr_encode("bitcoincash", 4, bytes(20)).decode("ascii"),
            "unknown CashAddr type: 4",
        ),
        (
            cashaddr_encode("bitcoincash", 0, bytes(32)).decode("ascii"),
            "32-byte hash for CashAddr type 0",
        ),
    ],
)
def test_a_cashaddr_of_another_shape_is_refused(address: str, reason: str) -> None:
    """A type Bitcoin Cash Node does not know, a size P2PKH does not take."""
    with pytest.raises(CoinAddressesValueError) as caught:
        assert_valid_address(address)
    assert str(caught.value).startswith(f"neither a CashAddr address ({reason})")


@pytest.mark.parametrize(
    "address, reason",
    [
        (base58_address(0, bytes(32)), "32-byte hash for version byte 0"),
        # Litecoin's P2PKH version byte
        (base58_address(48, bytes(20)), "unknown version byte: 48"),
    ],
)
def test_a_legacy_address_of_another_shape_is_refused(
    address: str, reason: str
) -> None:
    """A size P2PKH does not take, and another coin's version byte."""
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


@pytest.mark.parametrize("address", [None, b"bitcoincash:", 0, ["q"]])
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
@pytest.mark.parametrize("address", [_KEY_TESTS[0][1], _TRANSLATION[0][1]])
def test_whitespace_around_an_address_is_refused(
    before: str, after: str, address: str
) -> None:
    """An address with whitespace around it is refused.

    Bitcoin Cash Node skips whitespace around a legacy address, and
    `coin_addresses._bitcoin` says why this package does not.
    """
    assert is_valid_address(address)
    padded = f"{before}{address}{after}"
    with pytest.raises(CoinAddressesValueError):
        assert_valid_address(padded)
    assert not is_valid_address(padded)
