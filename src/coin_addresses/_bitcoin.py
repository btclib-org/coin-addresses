# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What the bitcoin clones share: the key hash, Base58Check, segwit, CashAddr.

A pay-to-public-key-hash address carries the HASH160 of the key's SEC
encoding, and its compressed and uncompressed encodings give different
addresses. The bitcoin clones' modules give the address of the
compressed one, which BIP32 wallets derive, and refuse a key written
uncompressed rather than answer an address its holder may not expect.
The cosmos and xrp modules do the same: a Cosmos address carries that
hash in bech32, and an XRP Ledger address carries it in Base58Check.

A legacy address is the Base58Check of a version byte and a hash. The
version byte says the coin and the script type; which ones a coin uses
is that coin's module's to say. Tron writes its address the same way,
with a hash of its own, and the XRP Ledger with Ripple's alphabet in
place of Bitcoin's.

Whitespace around a legacy address is refused. The reference nodes'
`DecodeBase58` skips leading and trailing whitespace, so to Bitcoin Cash
Node `" 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"` is an address. Here it is
not: an address is checked as it is to be written. The skip, in each
node:

- https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/e13b48e37b3005dca9a316f75aea456697a5dfd6/src/base58.cpp#L40-80
- https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/src/base58.cpp#L40-L74
- https://github.com/dogecoin/dogecoin/blob/b38c83fbf10302b23ac6e7ad89bc83068efe2fd8/src/base58.cpp#L23-L56
- https://github.com/bitcoin-sv/bitcoin-sv/blob/6504a3aff65ba97c0f6c80962b033e35ecbfed4b/src/base58.cpp#L25-L79
- https://github.com/BTCGPU/BTCGPU/blob/1b85f0953725812dedcfc5a7ac077c16d419e4ba/src/base58.cpp#L38-L85
- https://github.com/Bitcoin-ABC/bitcoin-abc/blob/e726999f0be7f985bf014d2284a0b95a390c9f2b/src/base58.cpp#L39-L101
- https://github.com/dashpay/dash/blob/938fba502824b9d850b7c710601456dc3d71603e/src/base58.cpp#L38-L85

A segwit address is BIP173's bech32, or BIP350's bech32m from witness
version 1, with the coin's HRP, and a CashAddr address carries the
coin's prefix. The functions here take the HRP or the prefix from the
coin's module, which cites its node for it.

A refusal names what is wrong, never the address or the key it was
handed. The refusals of `base58_bech32` do not quote them either, so
their messages are passed on.

The module is private: the coin modules publish what it serves.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from base58_bech32.base58 import BITCOIN_ALPHABET, b58decode_check, b58encode_check
from base58_bech32.bech32 import (
    BECH32_1_CONST,
    BECH32_M_CONST,
    bech32_decode,
    bech32_encode,
    convertbits,
)
from base58_bech32.cashaddr import cashaddr_decode
from base58_bech32.exceptions import Base58Bech32ValueError
from ecc.curves import PubKey, bytes_from_point, point_from_pub_key, secp256k1
from ecc.exceptions import EccTypeError, EccValueError

from coin_addresses._hashes import hash160
from coin_addresses.exceptions import (
    CoinAddressesException,
    CoinAddressesTypeError,
    CoinAddressesValueError,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

__all__: list[str] = []

# the first byte of an uncompressed SEC encoding
_UNCOMPRESSED = 0x04

# the script types a key gives on a coin with segwit, as
# `script_type_address` says
_SCRIPT_TYPES = ("p2pkh", "p2sh-p2wpkh", "p2wpkh")


def pub_key_hash(pub_key: PubKey) -> bytes:
    """Return the HASH160 of a public key's compressed SEC encoding.

    The key is any spelling `ecc.curves.point_from_pub_key` reads but an
    uncompressed SEC encoding: a point, or its compressed encoding, as
    bytes or as hex. A value of no type a key has is a
    `CoinAddressesTypeError`, and one that is no point of the curve, or
    is written uncompressed, a `CoinAddressesValueError`.
    """
    # the refusal is raised after the `try`, so that ecc's exception is
    # neither its cause nor its context
    kind: type[CoinAddressesException]
    try:
        point = point_from_pub_key(pub_key, secp256k1)
    except EccTypeError:
        kind = CoinAddressesTypeError
    except EccValueError:
        kind = CoinAddressesValueError
    else:
        # ecc has parsed it, so a string is hex and a buffer is octets
        if isinstance(pub_key, (str, bytes, bytearray, memoryview)):
            octets = bytes.fromhex(pub_key) if isinstance(pub_key, str) else pub_key
            if octets[0] == _UNCOMPRESSED:
                raise CoinAddressesValueError("uncompressed public key")
        return hash160(bytes_from_point(point, secp256k1))
    raise kind("not a public key")


def assert_string(address: object) -> None:
    """Refuse a non-string as a `CoinAddressesTypeError`.

    `object` and not `str`: a value of any type reaches it, and it is
    what refuses the ones that are no string.
    """
    if not isinstance(address, str):
        raise CoinAddressesTypeError(f"not a string: {type(address).__name__}")


def base58_address(version: int, digest: bytes, *, alphabet: bytes) -> str:
    """Return the Base58Check address of a version byte and a hash.

    `alphabet` is the coin's Base58 alphabet.
    """
    payload = bytes([version]) + digest
    return b58encode_check(payload, alphabet=alphabet).decode("ascii")


def decode_base58_address(
    address: str,
    sizes: Mapping[int, tuple[int, ...]],
    *,
    alphabet: bytes,
) -> tuple[int, bytes]:
    """Return the version byte and the hash of a Base58Check address.

    `sizes` maps each version byte the coin uses to the hash sizes it
    takes. A string that is no Base58Check, a version byte not in
    `sizes`, and a hash of a size its version does not take are each a
    `CoinAddressesValueError`. `alphabet` is as `base58_address` says.
    """
    try:
        payload = b58decode_check(address, alphabet=alphabet)
    except Base58Bech32ValueError as e:
        reason = str(e)
    else:
        if not payload:
            raise CoinAddressesValueError("no version byte")
        version, digest = payload[0], payload[1:]
        if version not in sizes:
            raise CoinAddressesValueError(f"unknown version byte: {version}")
        if len(digest) not in sizes[version]:
            err_msg = f"{len(digest)}-byte hash for version byte {version}"
            raise CoinAddressesValueError(err_msg)
        return version, digest
    raise CoinAddressesValueError(reason)


def segwit_address(version: int, program: bytes, *, hrp: str, limit: int) -> str:
    """Return the segwit address of a witness version and program.

    `hrp` is the coin's, and `limit` the longest string its node reads.
    """
    data = [version, *convertbits(program, 8, 5)]
    m = BECH32_1_CONST if version == 0 else BECH32_M_CONST
    return bech32_encode(hrp, data, m=m, limit=limit).decode("ascii")


def script_type_address(
    pub_key: PubKey,
    script_type: str,
    *,
    p2pkh: int,
    p2sh: int,
    hrp: str,
    limit: int,
) -> str:
    """Return the address of a public key, for one script type.

    `script_type` is "p2pkh", "p2sh-p2wpkh", the P2SH of the version 0
    witness program of the key hash, or "p2wpkh", that witness program
    as a segwit address. Another string is a `CoinAddressesValueError`,
    and a non-string a `CoinAddressesTypeError`. `p2pkh` and `p2sh` are
    the coin's version bytes, and `hrp` and `limit` are as
    `segwit_address` says. The key is read, and refused, as
    `pub_key_hash` says.
    """
    if not isinstance(script_type, str):
        raise CoinAddressesTypeError(
            f"script type not a string: {type(script_type).__name__}"
        )
    if script_type not in _SCRIPT_TYPES:
        err_msg = f"unknown script type, not one of {', '.join(_SCRIPT_TYPES)}"
        raise CoinAddressesValueError(err_msg)
    digest = pub_key_hash(pub_key)
    if script_type == "p2pkh":
        return base58_address(p2pkh, digest, alphabet=BITCOIN_ALPHABET)
    if script_type == "p2wpkh":
        return segwit_address(0, digest, hrp=hrp, limit=limit)
    # the redeem script is the witness program: OP_0, then a push of the
    # 20-byte key hash
    return base58_address(
        p2sh, hash160(b"\x00\x14" + digest), alphabet=BITCOIN_ALPHABET
    )


def assert_valid_segwit_address(
    address: str, *, hrp: str, limit: int, coin: str
) -> None:
    """Refuse a string that is not a segwit address of one coin.

    `hrp` and `limit` are as `segwit_address` says, and `coin` is the
    coin's name, for the refusal of another HRP. Each refusal is a
    `CoinAddressesValueError` or, from the codec, a
    `Base58Bech32ValueError`.
    """
    written, data, m = bech32_decode(address, limit=limit)
    if written != hrp:
        raise CoinAddressesValueError(f"not the {coin} HRP")
    if not data:
        raise CoinAddressesValueError("no witness version")
    version = data[0]
    if version > 16:
        raise CoinAddressesValueError(f"invalid witness version: {version}")
    if m != (BECH32_1_CONST if version == 0 else BECH32_M_CONST):
        raise CoinAddressesValueError(f"wrong checksum for witness version {version}")
    program = convertbits(data[1:], 5, 8, pad=False)
    if version == 0 and len(program) not in (20, 32):
        err_msg = f"{len(program)}-byte witness program for witness version 0"
        raise CoinAddressesValueError(err_msg)
    if not 2 <= len(program) <= 40:
        raise CoinAddressesValueError(f"{len(program)}-byte witness program")


def assert_valid_cashaddr(
    address: str, *, prefix: str, sizes: Mapping[int, tuple[int, ...]]
) -> None:
    """Refuse a string that is not a CashAddr address of one coin.

    `prefix` is the coin's, which an address may leave out, and `sizes`
    maps each CashAddr type the coin uses to the hash sizes it takes.
    Each refusal is a `CoinAddressesValueError` or, from the codec, a
    `Base58Bech32ValueError`.
    """
    _, kind, digest = cashaddr_decode(address, prefix=prefix)
    if kind not in sizes:
        raise CoinAddressesValueError(f"unknown CashAddr type: {kind}")
    if len(digest) not in sizes[kind]:
        err_msg = f"{len(digest)}-byte hash for CashAddr type {kind}"
        raise CoinAddressesValueError(err_msg)
