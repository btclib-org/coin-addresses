# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""An atheris harness fuzzing the address validation of every coin.

An address is what reaches a validator from outside the process: pasted,
scanned from a QR code, or sent by whoever asks to be paid. Each coin's
`is_valid_address` reads `data` as UTF-8 text, a byte that is no UTF-8
replaced, and its `assert_valid_address` has to give the same answer: it
refuses exactly what `is_valid_address` answers `False` for.

A crash here on hostile input is a defect in the validator, never in this
harness. `CoinAddressesValueError` is what a validator refuses a string
with, so it is caught below as the expected outcome; any other exception
propagates to atheris as the finding it is.

The seed corpus holds an address of each format, and a second where a
format has another shape: its case, its length or its leading zeros.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

import atheris

from coin_addresses import (
    bitcoin_cash,
    bitcoin_gold,
    bitcoin_sv,
    cosmos,
    dash,
    dogecoin,
    ecash,
    evm,
    litecoin,
    tron,
    xrp,
)
from coin_addresses.exceptions import CoinAddressesValueError

if TYPE_CHECKING:
    from collections.abc import Callable

# tests/fuzz_corpus_test.py reads this by ast.literal_eval, as well as
# loading this module under a stand-in atheris
ENTRY_POINTS = (
    "coin_addresses.bitcoin_cash:is_valid_address",
    "coin_addresses.bitcoin_gold:is_valid_address",
    "coin_addresses.bitcoin_sv:is_valid_address",
    "coin_addresses.cosmos:is_valid_address",
    "coin_addresses.dash:is_valid_address",
    "coin_addresses.dogecoin:is_valid_address",
    "coin_addresses.ecash:is_valid_address",
    "coin_addresses.evm:is_valid_address",
    "coin_addresses.litecoin:is_valid_address",
    "coin_addresses.tron:is_valid_address",
    "coin_addresses.xrp:is_valid_address",
)


def _agree(valid: bool, assert_valid: Callable[[str], None], text: str) -> None:
    """Refuse an `assert_valid_address` that answers otherwise."""
    try:
        assert_valid(text)
    except CoinAddressesValueError:
        refused = True
    else:
        refused = False
    if refused == valid:
        msg = "assert_valid_address and is_valid_address disagree"
        raise AssertionError(msg)


def fuzz_target(data: bytes) -> None:
    """Validate `data` as an address of every coin.

    `CoinAddressesValueError` is each validator's own refusal of a string
    that is no address; any other exception propagates, which is how
    atheris tells a defect in a validator from the domain of input it
    already rejects.
    """
    text = data.decode("utf-8", errors="replace")
    _agree(bitcoin_cash.is_valid_address(text), bitcoin_cash.assert_valid_address, text)
    _agree(bitcoin_gold.is_valid_address(text), bitcoin_gold.assert_valid_address, text)
    _agree(bitcoin_sv.is_valid_address(text), bitcoin_sv.assert_valid_address, text)
    _agree(cosmos.is_valid_address(text), cosmos.assert_valid_address, text)
    _agree(dash.is_valid_address(text), dash.assert_valid_address, text)
    _agree(dogecoin.is_valid_address(text), dogecoin.assert_valid_address, text)
    _agree(ecash.is_valid_address(text), ecash.assert_valid_address, text)
    _agree(evm.is_valid_address(text), evm.assert_valid_address, text)
    _agree(litecoin.is_valid_address(text), litecoin.assert_valid_address, text)
    _agree(tron.is_valid_address(text), tron.assert_valid_address, text)
    _agree(xrp.is_valid_address(text), xrp.assert_valid_address, text)


def main() -> None:
    """Wire `fuzz_target` to libFuzzer through atheris."""
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_target, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
