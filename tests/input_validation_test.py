# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The gate for the two rules about a public function's inputs.

CONTRIBUTING.md's "The public surface" states them, and which of the two
classes comes out is not a coin toss -- it is the distinction issue
btclib-org/btclib#814 settled, so this file drives the two separately:

- **a value of a type the signature does not declare** is the caller's
  own mistake, and leaves as a `CoinAddressesTypeError`.
- **a value of a declared type that no valid input carries** is a fact
  about the input, and leaves as a `CoinAddressesValueError`, except from
  an `is_*` function, which answers `False` about it.

## How it calls what it calls

The input types are few: `ecc`'s `PubKey`, and `str`. `_WRONG_TYPE` and
`_WRONG_VALUE` give each of them values of the two kinds, and the walk
finds every public module-level function whose *required* parameters
are all of those types. Those it can call with no fixture and no
knowledge of what the function does.

Every argument is wrong at once, which is not weaker than one wrong
argument among valid ones: whichever the function refuses first, the rule
says how it must refuse it. And it needs no valid values, which is what
makes the walk automatic.

## What it does not reach

A **parameter with a default** is never driven: to reach it the arguments
before it would have to be valid, which is the table this design is built
to do without.

A function taking a type the vocabulary does not build is driven by the
tests of its own module. So is one with a keyword-only parameter that
has no default: the walk passes its arguments by position.
`test_the_walk_reaches_what_it_claims` pins what the walk does find, so
a narrowing of it fails here rather than quietly running over less.
"""

from __future__ import annotations

import ast
import importlib
from collections.abc import Callable, Iterator
from functools import partial
from pathlib import Path
from typing import Any

import pytest

from coin_addresses.exceptions import (
    CoinAddressesTypeError,
    CoinAddressesValueError,
)

_LIBRARY = Path(__file__).parents[1] / "src" / "coin_addresses"

# a value of no type the alias declares: the caller's own mistake, and a
# call mypy refuses. The tuples are read round-robin so that a function
# taking three parameters of one type is called with three different
# wrong values. Constants and not a strategy: what this gate reports has
# to be the same on two runs, the lists below being read as statements
# about the tree
_WRONG_TYPE: dict[str, tuple[Any, ...]] = {
    "PubKey": (None, 1.5, [1, 2]),
    "str": (None, 1.5, b"0x" + bytes(40)),
}

# a value of a declared type that no valid input carries: a fact about
# the input. Every one of these type checks -- that is what puts it in
# this dict rather than in the one above -- so a `# type: ignore` is never
# needed to build the call, which is the same line drawn twice
_WRONG_VALUE: dict[str, tuple[Any, ...]] = {
    # a hex string that is not hex, octets of no point, a point off the curve
    "PubKey": ("not hex at all", bytes(33), (1, 2)),
    # no prefix, and a prefix with no digits
    "str": ("", "0x"),
}


def _alias_of(annotation: ast.expr) -> str | None:
    """Return the input type an annotation names, `X | None` included."""
    name = ast.unparse(annotation).replace(" | None", "").strip()
    return name if name in _WRONG_TYPE else None


def _drivable_in(module: str, source: str) -> dict[str, list[str]]:
    """Return every public function of one module the vocabulary can call.

    Required parameters only: what carries a default is what a caller may
    leave out, so a function is driven on the arguments it insists on.
    All of them have to be in the vocabulary -- one `bytes` and the walk
    has nothing to pass.
    """
    found: dict[str, list[str]] = {}
    for node in ast.parse(source).body:
        if not isinstance(node, ast.FunctionDef) or node.name.startswith("_"):
            continue
        # a required keyword-only parameter, which `kw_defaults` holds
        # as None
        if None in node.args.kw_defaults:
            continue
        positional = [*node.args.posonlyargs, *node.args.args]
        required = positional[: len(positional) - len(node.args.defaults)]
        # `is not None` narrows for mypy and never filters: mypy runs
        # strict over this package, so a parameter without an
        # annotation is a state the library does not reach
        annotations = [a.annotation for a in required if a.annotation is not None]
        aliases = [_alias_of(a) for a in annotations]
        if required and len(aliases) == len(required) and all(aliases):
            found[f"{module}.{node.name}"] = [a for a in aliases if a]
    return found


def _drivable() -> dict[str, list[str]]:
    """Return every public function the vocabulary can call, by dotted name."""
    found: dict[str, list[str]] = {}
    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        found |= _drivable_in(module, path.read_text(encoding="utf-8"))
    return found


_DRIVABLE = _drivable()


def _calls(
    dotted: str, vocabulary: dict[str, tuple[Any, ...]]
) -> Iterator[Callable[[], Any]]:
    """Yield one prepared call per round, every argument wrong at once.

    The vocabulary is the parameter, and it is the whole of what tells the
    two rules apart: the same walk, the same function, two kinds of wrong
    value.
    """
    module_name, _, name = dotted.rpartition(".")
    function = getattr(importlib.import_module(module_name), name)
    aliases = _DRIVABLE[dotted]
    for round_ in range(max(len(vocabulary[a]) for a in aliases)):
        args = [vocabulary[a][round_ % len(vocabulary[a])] for a in aliases]
        # partial and not a lambda, which would close over the loop
        # variables and be read on a later round
        yield partial(function, *args)


_DRIVEN = sorted(_DRIVABLE)


@pytest.mark.parametrize("dotted", _DRIVEN)
def test_a_wrong_type_leaves_as_a_type_error_of_the_package(dotted: str) -> None:
    """The first rule, and it has no exceptions.

    `CoinAddressesTypeError` and not the base: this is where the class is
    the point. A bare `TypeError` fails here as a `CoinAddressesValueError`
    does -- the first is a leak from underneath the package, the second
    is the package calling a caller's mistake a fact about the input.
    """
    for call in _calls(dotted, _WRONG_TYPE):
        with pytest.raises(CoinAddressesTypeError):
            call()


@pytest.mark.parametrize("dotted", _DRIVEN)
def test_a_wrong_value_leaves_as_a_value_error_of_the_package(dotted: str) -> None:
    """The second rule, over what the walk drives.

    `CoinAddressesValueError` and not the base, as CONTRIBUTING.md's "The
    public surface" states it: a `CoinAddressesTypeError` here would be
    the package calling a fact about the input a caller's mistake. An
    `is_*` function answers `False` instead, as its name promises a bool
    about any value of its declared types.
    """
    for call in _calls(dotted, _WRONG_VALUE):
        if dotted.rpartition(".")[2].startswith("is_"):
            assert call() is False
            continue
        with pytest.raises(CoinAddressesValueError):
            call()


def test_the_vocabulary_is_the_packages_input_types() -> None:
    """A renamed type would narrow the walk without failing anything.

    Every type a parameter of a public function of a public module is
    annotated with is in the vocabulary, so a function taking a new type
    fails here until the vocabulary builds it.
    """
    annotated: set[str] = set()
    for path in sorted(_LIBRARY.rglob("*.py")):
        if path.stem.startswith("_") and path.stem != "__init__":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        annotated |= {
            ast.unparse(a.annotation).replace(" | None", "").strip()
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and not node.name.startswith("_")
            for a in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            if a.annotation is not None
        }

    assert set(_WRONG_TYPE) == set(_WRONG_VALUE)
    assert annotated == set(_WRONG_TYPE)


def test_the_walk_reaches_what_it_claims() -> None:
    """The shapes the walk must find, and those it must not.

    A walk that found nothing would pass every test above. One function
    per type it has to reach, and the `is_*` it answers `False` through,
    and a private name it must leave alone.
    """
    assert _DRIVABLE["coin_addresses.evm.address_from_pub_key"] == ["PubKey"]
    assert _DRIVABLE["coin_addresses.evm.assert_valid_address"] == ["str"]
    assert _DRIVABLE["coin_addresses.evm.is_valid_address"] == ["str"]

    # a private name, whatever its parameters
    assert "coin_addresses.evm._checksum_encode" not in _DRIVABLE

    # the shapes the library does not hold: one behind a keyword it must
    # ignore, a required keyword-only parameter, and a required parameter
    # the vocabulary does not build
    source = (
        "def keyword(a: str, *, k: str = '') -> None: ...\n"
        "def required(a: str, *, k: str) -> None: ...\n"
        "def other(a: str, b: bytes) -> None: ...\n"
    )
    assert _drivable_in("m", source) == {"m.keyword": ["str"]}
