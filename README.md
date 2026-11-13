# coin-addresses

A public key to the address a coin derives from it, and the validation
of an address, in typed Python, with nothing above that: no transaction
and no signature.

<!-- Section 2 of the organization's standard says which badges sit here. -->
[![PyPI version](https://img.shields.io/pypi/v/coin-addresses.svg?logo=pypi)](https://pypi.org/project/coin-addresses/)
[![GitHub release](https://img.shields.io/github/v/release/btclib-org/coin-addresses.svg)](https://github.com/btclib-org/coin-addresses/releases)
[![development status](https://img.shields.io/pypi/status/coin-addresses.svg)](https://pypi.org/project/coin-addresses/)
[![license](https://img.shields.io/github/license/btclib-org/coin-addresses.svg)](https://github.com/btclib-org/coin-addresses/blob/main/LICENSE)
[![downloads](https://static.pepy.tech/badge/coin-addresses)](https://pepy.tech/projects/coin-addresses)
[![supported Python versions](https://img.shields.io/pypi/pyversions/coin-addresses.svg?logo=python)](https://pypi.org/project/coin-addresses/)
[![implementation](https://img.shields.io/pypi/implementation/coin-addresses.svg)](https://pypi.org/project/coin-addresses/)
[![wheel](https://img.shields.io/pypi/wheel/coin-addresses.svg)](https://pypi.org/project/coin-addresses/)

## What is here

`coin_addresses.evm` derives and validates the addresses of Ethereum and
of the EVM chains, with their EIP-55 checksum;
`coin_addresses.bitcoin_cash`, `coin_addresses.bitcoin_sv`,
`coin_addresses.bitcoin_gold`, `coin_addresses.ecash`,
`coin_addresses.litecoin`, `coin_addresses.dogecoin` and
`coin_addresses.dash` those of the bitcoin clones; `coin_addresses.tron`
those of Tron, `coin_addresses.cosmos` those of the Cosmos Hub, and
`coin_addresses.xrp` the classic addresses of the XRP Ledger. These are
the coins on secp256k1 of the first stage.
`coin_addresses.solana` gives the addresses of Solana, a coin on ed25519
of the second stage. It builds on
[ecc](https://github.com/btclib-org/ecc) for the curve and on
[base58-bech32](https://github.com/btclib-org/base58-bech32) for the
encodings, and not on btclib.
[btclib-org/.github#2197](https://github.com/btclib-org/.github/issues/2197)
records that decision and tracks the release; the later stages are
[btclib-org/.github#2199](https://github.com/btclib-org/.github/issues/2199),
[btclib-org/.github#2200](https://github.com/btclib-org/.github/issues/2200),
[btclib-org/.github#2201](https://github.com/btclib-org/.github/issues/2201)
and [btclib-org/.github#2202](https://github.com/btclib-org/.github/issues/2202).

The package is fully annotated and ships `py.typed`. Its refusals are
`coin_addresses.exceptions`'s classes: a `ValueError` or a
`TypeError`, under one base, `CoinAddressesException`.

```python
from coin_addresses.exceptions import (
    CoinAddressesException,
    CoinAddressesTypeError,
    CoinAddressesValueError,
)

assert issubclass(CoinAddressesValueError, (CoinAddressesException, ValueError))
assert issubclass(CoinAddressesTypeError, (CoinAddressesException, TypeError))
```

A public key, as a point or in its SEC encoding, compressed or not, gives
its Ethereum address, and an address handed over is checked:

```python
from coin_addresses import evm

# the generator of secp256k1, the public key of the private key 1
pub_key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
address = evm.address_from_pub_key(pub_key)
assert address == "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
assert evm.is_valid_address(address)
assert not evm.is_valid_address(address.replace("E", "e", 1))
```

A bitcoin clone's address is that of the key's compressed SEC encoding,
and a key written uncompressed is refused. The Litecoin and Bitcoin Gold
modules name the script type, and the Bitcoin Cash and eCash modules
give the legacy address beside the CashAddr one:

```python
from coin_addresses import bitcoin_cash, dogecoin, litecoin

pub_key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
address = litecoin.address_from_pub_key(pub_key, script_type="p2wpkh")
assert address == "ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9"
address = bitcoin_cash.address_from_pub_key(pub_key)
assert address == "bitcoincash:qp63uahgrxged4z5jswyt5dn5v3lzsem6cy4spdc2h"
address = bitcoin_cash.legacy_address_from_pub_key(pub_key)
assert address == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
assert dogecoin.is_valid_address(dogecoin.address_from_pub_key(pub_key))
```

eCash writes CashAddr with its own prefix, and Bitcoin SV reads
Bitcoin's legacy addresses alone:

```python
from coin_addresses import bitcoin_cash, bitcoin_gold, bitcoin_sv, dash, ecash

pub_key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
address = ecash.address_from_pub_key(pub_key)
assert address == "ecash:qp63uahgrxged4z5jswyt5dn5v3lzsem6cacy2kzvq"
assert not ecash.is_valid_address(bitcoin_cash.address_from_pub_key(pub_key))
address = bitcoin_sv.address_from_pub_key(pub_key)
assert address == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
assert not bitcoin_sv.is_valid_address(bitcoin_cash.address_from_pub_key(pub_key))
address = bitcoin_gold.address_from_pub_key(pub_key, script_type="p2wpkh")
assert address == "btg1qw508d6qejxtdg4y5r3zarvary0c5xw7k6w057a"
assert dash.address_from_pub_key(pub_key) == "XmN7PQYWKn5MJFna5fRYgP6mxT2F7xpekE"
```

A Tron address carries the bytes of the key's Ethereum address, in
Base58Check:

```python
from coin_addresses import tron

pub_key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
address = tron.address_from_pub_key(pub_key)
assert address == "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC"
assert tron.is_valid_address(address)
```

A Cosmos Hub address carries a bitcoin clone's hash in bech32, with the
HRP `cosmos`, and an address with another chain's HRP is refused:

```python
from coin_addresses import cosmos
from coin_addresses.exceptions import CoinAddressesValueError

pub_key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
address = cosmos.address_from_pub_key(pub_key)
assert address == "cosmos1w508d6qejxtdg4y5r3zarvary0c5xw7k6ah60c"
assert cosmos.is_valid_address(address)
# the same bytes with Osmosis's HRP: a valid bech32 string, refused for
# its HRP alone
osmosis = "osmo1w508d6qejxtdg4y5r3zarvary0c5xw7kjxy2e2"
try:
    cosmos.assert_valid_address(osmosis)
except CoinAddressesValueError as e:
    assert str(e) == "not the Cosmos HRP"
else:
    raise AssertionError(osmosis)
```

An XRP Ledger classic address carries the bytes of a Bitcoin P2PKH
address, written with Ripple's Base58 alphabet. An X-address is refused:

```python
from coin_addresses import xrp

pub_key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
address = xrp.address_from_pub_key(pub_key)
# Bitcoin writes the same bytes as 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
assert address == "rBgGZ9tc4him9KBzD8fKFiQz3fSZpaSwMH"
assert xrp.is_valid_address(address)
# an X-address of another account, from xrpl-py's tests
assert not xrp.is_valid_address("X7AcgcsBL6XDcUb289X4mJ8djcdyKaB5hJDWMArnXr61cqZ")
```

A Solana address is the 32 bytes of an ed25519 public key in Base58,
with no checksum. Any 32 bytes are an address, so a program derived
address, which lies off the curve, is valid too:

```python
from coin_addresses import solana

# a key of bip_utils's tests
pub_key = "e9b6062841bb977ad21de71ec961900633c26f21384e015b014a637a61499547"
address = solana.address_from_pub_key(pub_key)
assert address == "GjJyeC1r2RgkuoCWMyPYkCWSGSGLcz266EaAkLA27AhL"
assert solana.is_valid_address(address)
# the System Program's address, the 32 zero bytes
assert solana.address_from_pub_key(bytes(32)) == "1" * 32
# a program derived address of solana-sdk's tests
assert solana.is_valid_address("BwqrghZA2htAcqq8dzP1WDAhTXYTYWj7CHxF5j7TDBAe")
```

`tests/readme_test.py` runs every Python block of this file, so the
examples above are the ones the suite checks.

## Security

[SECURITY.md](https://github.com/btclib-org/coin-addresses/blob/main/SECURITY.md)
says how to report a vulnerability, which versions are supported, and
how a published file is traced back to the run that built it.

## Contributing

Development is LLM-based: humans are welcome, as long as they are
comfortable with agentic development ;-). A contribution must have been
read and understood by the person who submits it.
[`CONTRIBUTING.md`](https://github.com/btclib-org/coin-addresses/blob/main/CONTRIBUTING.md#working-with-an-llm)
has the rules.

[CONTRIBUTING.md](https://github.com/btclib-org/coin-addresses/blob/main/CONTRIBUTING.md)
has the commands each CI job runs, verbatim. `uv sync` creates the
environment; uv is the only tool that has to be installed.
[REVIEWING.md](https://github.com/btclib-org/coin-addresses/blob/main/REVIEWING.md)
is what a pull request is answered against.

How the organization decides, and who holds which role, is its
[GOVERNANCE.md](https://github.com/btclib-org/.github/blob/main/GOVERNANCE.md);
what it intends to do, and what it deliberately does not, is its
[ROADMAP.md](https://github.com/btclib-org/.github/blob/main/ROADMAP.md).

## Links

- Source: <https://github.com/btclib-org/coin-addresses>
- Releases: <https://github.com/btclib-org/coin-addresses/releases>
- [CHANGELOG.md](https://github.com/btclib-org/coin-addresses/blob/main/CHANGELOG.md),
  and [RELEASE_NOTES.md](https://github.com/btclib-org/coin-addresses/blob/main/RELEASE_NOTES.md)
  for what a release asks a user to act on

## Status

<!-- Section 2 of the organization's standard says which badges sit here. -->
[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/btclib-org/coin-addresses/main.svg)](https://results.pre-commit.ci/latest/github/btclib-org/coin-addresses/main)
[![lint workflow status](https://github.com/btclib-org/coin-addresses/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/btclib-org/coin-addresses/actions/workflows/lint.yml?query=branch%3Amain)
[![test workflow status](https://github.com/btclib-org/coin-addresses/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/btclib-org/coin-addresses/actions/workflows/test.yml?query=branch%3Amain)
[![docs workflow status](https://github.com/btclib-org/coin-addresses/actions/workflows/docs.yml/badge.svg?branch=main)](https://github.com/btclib-org/coin-addresses/actions/workflows/docs.yml?query=branch%3Amain)
[![mutation workflow status](https://github.com/btclib-org/coin-addresses/actions/workflows/mutation.yml/badge.svg?branch=main)](https://github.com/btclib-org/coin-addresses/actions/workflows/mutation.yml?query=branch%3Amain)
[![fuzz workflow status](https://github.com/btclib-org/coin-addresses/actions/workflows/fuzz.yml/badge.svg?branch=main)](https://github.com/btclib-org/coin-addresses/actions/workflows/fuzz.yml?query=branch%3Amain)
[![deps-latest workflow status](https://github.com/btclib-org/coin-addresses/actions/workflows/deps-latest.yml/badge.svg?branch=main)](https://github.com/btclib-org/coin-addresses/actions/workflows/deps-latest.yml?query=branch%3Amain)
[![pypi-install workflow status](https://github.com/btclib-org/coin-addresses/actions/workflows/pypi-install.yml/badge.svg?branch=main)](https://github.com/btclib-org/coin-addresses/actions/workflows/pypi-install.yml?query=branch%3Amain)
[![deps-oldest workflow status](https://github.com/btclib-org/coin-addresses/actions/workflows/deps-oldest.yml/badge.svg?branch=main)](https://github.com/btclib-org/coin-addresses/actions/workflows/deps-oldest.yml?query=branch%3Amain)
[![os-macos workflow status](https://github.com/btclib-org/coin-addresses/actions/workflows/os-macos.yml/badge.svg?branch=main)](https://github.com/btclib-org/coin-addresses/actions/workflows/os-macos.yml?query=branch%3Amain)
[![os-ubuntu workflow status](https://github.com/btclib-org/coin-addresses/actions/workflows/os-ubuntu.yml/badge.svg?branch=main)](https://github.com/btclib-org/coin-addresses/actions/workflows/os-ubuntu.yml?query=branch%3Amain)
[![os-windows workflow status](https://github.com/btclib-org/coin-addresses/actions/workflows/os-windows.yml/badge.svg?branch=main)](https://github.com/btclib-org/coin-addresses/actions/workflows/os-windows.yml?query=branch%3Amain)
[![links workflow status](https://github.com/btclib-org/coin-addresses/actions/workflows/links.yml/badge.svg?branch=main)](https://github.com/btclib-org/coin-addresses/actions/workflows/links.yml?query=branch%3Amain)
[![sdist-rebuild workflow status](https://github.com/btclib-org/coin-addresses/actions/workflows/sdist-rebuild.yml/badge.svg?branch=main)](https://github.com/btclib-org/coin-addresses/actions/workflows/sdist-rebuild.yml?query=branch%3Amain)
[![codeql workflow status](https://github.com/btclib-org/coin-addresses/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/btclib-org/coin-addresses/actions/workflows/codeql.yml?query=branch%3Amain)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/btclib-org/coin-addresses/badge)](https://scorecard.dev/viewer/?uri=github.com/btclib-org/coin-addresses)

---

The btclib organization and its projects are actively supported by
[DGI](https://dgi.io) and [CheckSig](https://checksig.com).
