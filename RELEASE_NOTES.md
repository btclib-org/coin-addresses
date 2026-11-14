# Release notes

Notable changes are documented here.
[CHANGELOG.md](./CHANGELOG.md) is the record behind them: this file says
what a user has to act on, that one says what changed.

Versions are *[calendar versions](https://calver.org/)*, `YYYY.M.D`: the
number says when a release was cut, and promises nothing about
compatibility, so a breaking change is announced in this file — read it
before upgrading, rather than a digit.

## v2026.11.15

`coin_addresses.stellar` is new: it gives the account address of an
ed25519 public key, 56 characters starting with `G`, and validates one.
A muxed account's address is refused. The module publishes
`address_from_pub_key`, `is_valid_address` and `assert_valid_address`,
as every coin module does.

The package requires `base58-bech32` 2026.11.14 or later, the first
release with the strkey codec Stellar's addresses are written in. An
environment that pins an earlier one has to move it.

`griffe check` and `api_gaps.py` against v2026.11.14 report no break of
the public API.

## v2026.11.14

The first release of `coin-addresses`: the address a coin derives from a
public key, and the validation of an address, for Ethereum and the EVM
chains, the bitcoin clones, Tron, the Cosmos Hub, the XRP Ledger and
Solana. There is no earlier version of it to upgrade from.

Each coin is a module of `coin_addresses` that publishes
`address_from_pub_key`, `is_valid_address` and `assert_valid_address`. A
refusal is a `CoinAddressesValueError` or a `CoinAddressesTypeError`,
which a caller catching `ValueError` or `TypeError` still catches.

The release attaches the wheel,
`coin_addresses-2026.11.14-py3-none-any.whl`, the sdist,
`coin_addresses-2026.11.14.tar.gz`, `coin_addresses-2026.11.14.cdx.json`
and `v2026.11.14.intoto.jsonl`; *Supported versions* in
[SECURITY.md](./SECURITY.md) has the `gh attestation verify` command.
