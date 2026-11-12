# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for `coin_addresses.exceptions`, and for who catches what it raises.

The classes add nothing to their bases, so what is tested is the
hierarchy: one base to catch everything the package raises, and each
class a subclass of the built-in that names its kind of failure. The
second half is what a caller written against `except ValueError` relies
on.
"""

from __future__ import annotations

import pickle

import pytest

from coin_addresses import exceptions
from coin_addresses.exceptions import (
    CoinAddressesException,
    CoinAddressesTypeError,
    CoinAddressesValueError,
)


def test_every_exception_of_the_module_is_one_base_to_catch() -> None:
    """`except CoinAddressesException` tells this package's failure apart.

    The classes are found rather than listed, so one added to the module
    is one this covers: a new exception that forgot the base would be a
    failure a caller catching it could not catch, and nothing else in the
    suite would say so.
    """
    classes = [
        getattr(exceptions, name)
        for name in exceptions.__all__
        if isinstance(getattr(exceptions, name), type)
    ]
    assert len(classes) == len(exceptions.__all__), "a non-class in __all__"
    uncatchable = [
        cls.__name__ for cls in classes if not issubclass(cls, CoinAddressesException)
    ]
    assert not uncatchable


@pytest.mark.parametrize(
    "cls, builtin",
    [(CoinAddressesValueError, ValueError), (CoinAddressesTypeError, TypeError)],
    ids=["ValueError", "TypeError"],
)
def test_the_base_is_inherited_beside_the_builtin_not_instead_of_it(
    cls: type[CoinAddressesException], builtin: type[Exception]
) -> None:
    """The half that keeps every `except ValueError` already written working."""
    assert issubclass(cls, builtin)
    assert issubclass(cls, CoinAddressesException)


def test_the_base_carries_no_behaviour_of_its_own() -> None:
    """It adds a name to catch and nothing else, which is the whole design."""
    assert CoinAddressesException.__init__ is Exception.__init__
    assert CoinAddressesException.__str__ is Exception.__str__
    error = CoinAddressesValueError("bad")
    assert str(error) == "bad"
    assert error.args == ("bad",)
    back = pickle.loads(pickle.dumps(error))  # noqa: S301 -- bytes this test wrote
    assert type(back) is CoinAddressesValueError
    assert back.args == error.args
