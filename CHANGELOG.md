# Changelog

The release's own pull request writes its section here, from the squash
subjects since the previous tag; a pull request adds no entry
(`CONTRIBUTING.md`'s *Pull requests*, section 9 of [the organization
standard][std]). [RELEASE_NOTES.md](./RELEASE_NOTES.md) has the release
notes, which say what a user has to act on; this file is the record
behind them.

[std]: https://github.com/btclib-org/.github

## v2026.11.14

### Ethereum and the EVM chains, with EIP-55

`coin_addresses.evm` derives an address and its checksum from a public
key, and validates one (closes #2).

### The bitcoin clones

`bitcoin_cash`, `bitcoin_sv`, `bitcoin_gold`, `ecash`, `litecoin`,
`dogecoin` and `dash` (closes #8) (closes #24).

### Tron, the Cosmos Hub and the XRP Ledger

`tron`, `cosmos`, whose README example says why an Osmosis address is
refused, and `xrp`, which refuses a released memoryview as the package's
error (closes #10) (closes #11) (closes #12) (closes #31) (#22).

### Solana, on ed25519

`coin_addresses.solana` (closes #27).

### The public-surface tests read each module's `__all__`

(closes #13) (closes #16).

### The repository opens from the organization's scaffold

With the Read the Docs URL and a corrected `deps-latest.yml` header
(closes #4) (closes #5) (issue btclib-org/.github#2197).

### The fuzz and mutation sentinels run

(issue btclib-org/.github#2213).

### `AGENTS.md` points at `REVIEWING.md` for code review

(issue btclib-org/.github#2009).

### `sourcery.yml` takes btclib-org/.github's concurrency comment

(issue btclib-org/.github#2190).

### The locked and pinned tools move

The dev-tooling and actions groups, and soupsieve for the audit
(closes #23) (#1, #19, #20, #25).
