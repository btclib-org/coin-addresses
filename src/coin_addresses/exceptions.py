# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Exception classes.

These exist only to tell an exception raised by coin_addresses from one
raised by any other code: each derives from the built-in that says what
kind of failure it is, and adds nothing to it.

`CoinAddressesException` makes that telling apart a single `except`. It is
inherited *beside* the built-in and not instead of it:
`CoinAddressesValueError` is a `ValueError`, so code catching the built-in
catches it, as `json.JSONDecodeError` is a `ValueError` too.

It is caught and never raised: every refusal the package raises is to be
one of the two below it, and which one says whether the value was wrong or
the type was.

The classes are this package's own rather than `btclib`'s, which keeps the
package free of any import of `btclib`: a caller catching
`btclib.exceptions.BTClibValueError` does not catch these, and one
catching `ValueError` catches both.
"""

from __future__ import annotations

__all__ = [
    "CoinAddressesException",
    "CoinAddressesTypeError",
    "CoinAddressesValueError",
]


class CoinAddressesException(Exception):  # noqa: N818 -- a kind, like Exception itself, not a leaf raised
    """Anything coin_addresses raised, whatever kind of failure it is.

    Never raised: the two below it are, and each says which kind of
    failure it was.
    """


class CoinAddressesValueError(CoinAddressesException, ValueError):
    """A value no valid input could carry; the package's usual refusal."""


class CoinAddressesTypeError(CoinAddressesException, TypeError):
    """An input of a type no conversion accepts: a caller error."""
