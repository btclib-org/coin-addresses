# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests that a keyword-only parameter stays keyword-only.

`*` in a signature is a calling-convention promise, and a mutant of `*`
to `/` drops the keyword-only rule and adds a positional-only one in its
place with every call already written still answering the same (issue
btclib-org/btclib#980). The property is mechanical, one
`inspect.signature(...).parameters[name].kind` per site, so walking
`__all__` once covers every site.

`KEYWORD_ONLY` is that walk, run once against the current tree and
frozen here rather than recomputed by the test: recomputing it from the
same code the test is meant to guard would make the assertion read
whatever a mutation had just done to it and call that the answer. A
keyword-only parameter added to the public surface is a site this table
does not hold, and the test below fails until it does.

A function under a module's `__all__` is named directly; a class is
named once per public method of its own -- `__init__`, and every other
name in its own `__dict__` that does not start with an underscore.
An inherited method is walked where it is defined and not under a
subclass that does not override it.
"""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING, Any

from .all_test import library_modules

if TYPE_CHECKING:
    from collections.abc import Iterator

# Walked from `coin_addresses`, on the commit this file is part of: every
# public callable that takes at least one keyword-only parameter, and the
# names of those parameters in declaration order
KEYWORD_ONLY: dict[str, list[str]] = {
    "coin_addresses.litecoin:address_from_pub_key": ["script_type"],
}


def _kwonly_names(signature: inspect.Signature) -> list[str]:
    """Return the keyword-only parameter names of one signature, in order."""
    return [
        parameter.name
        for parameter in signature.parameters.values()
        if parameter.kind == inspect.Parameter.KEYWORD_ONLY
    ]


def _callables() -> Iterator[tuple[str, Any]]:
    """Yield every name under an `__all__`, and each public method of a class.

    A class is expanded into `__init__` and every name in its own
    `__dict__` that does not start with an underscore, so an alternate
    constructor and an instance method are sites of their own rather than
    invisible because they are not the constructor. What is not a
    function -- a module, a field, a constant -- is yielded too, and
    `_live_keyword_only` passes it over.
    """
    for module in library_modules():
        for name in module.__all__:
            obj = getattr(module, name)
            members = vars(obj) if inspect.isclass(obj) else {}
            yield from (
                (f"{module.__name__}:{name}.{attr}", getattr(obj, attr))
                for attr in members
                if attr == "__init__" or not attr.startswith("_")
            )
            yield f"{module.__name__}:{name}", obj


def _live_keyword_only() -> dict[str, list[str]]:
    """Recompute `KEYWORD_ONLY` from the tree currently under test."""
    return {
        label: names
        for label, obj in _callables()
        if inspect.isfunction(obj) or inspect.ismethod(obj)
        if (names := _kwonly_names(inspect.signature(obj)))
    }


def test_the_recorded_surface_is_the_whole_of_it() -> None:
    """Nothing keyword-only is missing from the table, nothing extra is in it.

    This recomputes the walk and asks the two agree -- a new site, a
    removed one, a renamed parameter, and a `*` a mutant turned to `/`
    all show up as one dictionary differing from another.
    """
    assert _live_keyword_only() == KEYWORD_ONLY


def test_the_walk_reaches_what_it_claims() -> None:
    """A function and a class, and a module's private names out.

    The package's classes are its exceptions, which define no method of
    their own: the class is yielded, and nothing under it.
    """
    labels = {label for label, _ in _callables()}
    assert "coin_addresses.evm:address_from_pub_key" in labels
    assert "coin_addresses.exceptions:CoinAddressesValueError" in labels
    assert "coin_addresses.evm:_checksum_encode" not in labels
