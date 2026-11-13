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

The input types are few: `ecc`'s `PubKey` and `Octets`, and `str`.
`_WRONG_TYPE` and `_WRONG_VALUE` give each of them values of the two
kinds, and the walk finds every function a module's `__all__` lists
whose *required* parameters are all of those types. Those it can call
with no fixture and no knowledge of what the function does.

The list decides, not the underscore, as CONTRIBUTING.md's "The public
surface" defines a public name. A function the list leaves out is not
driven, whatever its name, and a helper of a private module is such a
function.

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

An **async function** the list names fails the walk, which calls and
does not await. The library has none.

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

from . import exported_names
from .all_test import module_scope

_LIBRARY = Path(__file__).parents[1] / "src" / "coin_addresses"

# a value of no type the alias declares: the caller's own mistake, and a
# call mypy refuses. The tuples are read round-robin so that a function
# taking three parameters of one type is called with three different
# wrong values. Constants and not a strategy: what this gate reports has
# to be the same on two runs, the lists below being read as statements
# about the tree
_WRONG_TYPE: dict[str, tuple[Any, ...]] = {
    "PubKey": (None, 1.5, [1, 2]),
    "Octets": (None, 1.5, [1, 2]),
    "str": (None, 1.5, b"0x" + bytes(40)),
}

# a value of a declared type that no valid input carries: a fact about
# the input. Every one of these type checks -- that is what puts it in
# this dict rather than in the one above -- so a `# type: ignore` is never
# needed to build the call, which is the same line drawn twice
_WRONG_VALUE: dict[str, tuple[Any, ...]] = {
    # a hex string that is not hex, octets of no point, a point off the curve
    "PubKey": ("not hex at all", bytes(33), (1, 2)),
    # a hex string that is not hex, octets of another size, and a strided
    # view of the right size
    "Octets": ("not hex at all", bytes(31), memoryview(bytes(64))[::2]),
    # no prefix, and a prefix with no digits
    "str": ("", "0x"),
}


def _alias_of(annotation: ast.expr) -> str | None:
    """Return the input type an annotation names, `X | None` included."""
    name = ast.unparse(annotation).replace(" | None", "").strip()
    return name if name in _WRONG_TYPE else None


def _public_functions(module: str, source: str) -> Iterator[ast.FunctionDef]:
    """Yield the module-level functions the module's `__all__` lists.

    Module level is every statement the module runs in its own namespace,
    a definition under an `if` or a `try` included. A listed async
    function raises, the walk having no way to drive it.
    """
    tree = ast.parse(source)
    exported = exported_names(tree, module)
    for node in module_scope(tree.body):
        if isinstance(node, ast.AsyncFunctionDef) and node.name in exported:
            msg = f"{module}:{node.lineno}: the walk cannot drive async {node.name}"
            raise ValueError(msg)
        if isinstance(node, ast.FunctionDef) and node.name in exported:
            yield node


def _drivable_in(module: str, source: str) -> dict[str, list[str]]:
    """Return every public function of one module the vocabulary can call.

    Required parameters only: what carries a default is what a caller may
    leave out, so a function is driven on the arguments it insists on.
    All of them have to be in the vocabulary -- one `bytes` and the walk
    has nothing to pass.
    """
    found: dict[str, list[str]] = {}
    for node in _public_functions(module, source):
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

    Every type a parameter of a public function is annotated with is in
    the vocabulary, so a function taking a new type fails here until the
    vocabulary builds it.
    """
    annotated: set[str] = set()
    for path in sorted(_LIBRARY.rglob("*.py")):
        annotated |= {
            ast.unparse(a.annotation).replace(" | None", "").strip()
            for node in _public_functions(path.name, path.read_text(encoding="utf-8"))
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
    assert _DRIVABLE["coin_addresses.solana.address_from_pub_key"] == ["Octets"]

    # a private name, whatever its parameters
    assert "coin_addresses.evm._checksum_encode" not in _DRIVABLE

    # the shapes the library does not hold: one behind a keyword it must
    # ignore, a required keyword-only parameter, and a required parameter
    # the vocabulary does not build
    source = (
        "__all__ = ['keyword', 'required', 'other']\n"
        "def keyword(a: str, *, k: str = '') -> None: ...\n"
        "def required(a: str, *, k: str) -> None: ...\n"
        "def other(a: str, b: bytes) -> None: ...\n"
    )
    assert _drivable_in("m", source) == {"m.keyword": ["str"]}


def test_the_list_decides_what_the_walk_drives() -> None:
    """A function is driven because its module's `__all__` lists it.

    `coin_addresses._bitcoin.pub_key_hash` is the control: a public name,
    a parameter the vocabulary builds, and a private module whose list
    leaves it out. The planted modules write the list in each form the
    library uses, and the last has none.
    """
    assert "coin_addresses._bitcoin.pub_key_hash" not in _DRIVABLE

    functions = "def listed(a: str) -> None: ...\ndef unlisted(a: str) -> None: ...\n"
    assert _drivable_in("m", "__all__ = ['listed']\n" + functions) == {
        "m.listed": ["str"]
    }
    assert _drivable_in("m", "__all__: list[str] = ['listed']\n" + functions) == {
        "m.listed": ["str"]
    }
    assert not _drivable_in("m", functions)


# a function listed and defined under each block that runs at module level
_BLOCKS = ("if", "else", "try", "handler", "finally", "with", "for", "while", "case")
_UNDER_BLOCKS = (
    f"__all__ = {[f'in_{block}' for block in _BLOCKS]}\n"
    "if X:\n"
    "    def in_if(a: str) -> None: ...\n"
    "else:\n"
    "    def in_else(a: str) -> None: ...\n"
    "try:\n"
    "    def in_try(a: str) -> None: ...\n"
    "except E:\n"
    "    def in_handler(a: str) -> None: ...\n"
    "finally:\n"
    "    def in_finally(a: str) -> None: ...\n"
    "with C:\n"
    "    def in_with(a: str) -> None: ...\n"
    "for _ in X:\n"
    "    def in_for(a: str) -> None: ...\n"
    "while X:\n"
    "    def in_while(a: str) -> None: ...\n"
    "match X:\n"
    "    case _:\n"
    "        def in_case(a: str) -> None: ...\n"
)


def test_the_walk_reaches_a_function_under_a_block() -> None:
    """A definition under a block is a module-level function all the same."""
    assert _drivable_in("m", _UNDER_BLOCKS) == {
        f"m.in_{block}": ["str"] for block in _BLOCKS
    }


def test_the_reader_takes_the_forms_the_library_writes() -> None:
    """A plain list or tuple, an annotated one, and reads of the list."""
    assert exported_names(ast.parse("__all__ = ['f']\n"), "m") == {"f"}
    assert exported_names(ast.parse("__all__: list[str] = []\n"), "m") == set()
    source = (
        "__all__ = ('f',)\n"
        "def f(name: str) -> bool:\n"
        "    return name in __all__ or name in {*__all__}\n"
    )
    assert exported_names(ast.parse(source), "m") == {"f"}
    assert exported_names(ast.parse("f = 1\n"), "m") == set()


# each a write to `__all__` the reader refuses, with the lines it names
_REFUSED = {
    "chained": ("__all__ = names = ['f']\n", "1"),
    "assigned twice": ("__all__ = ['f']\n__all__ = ['g']\n", "1, 2"),
    "augmented": ("__all__ = ['f']\n__all__ += ['g']\n", "1, 2"),
    "mutated": ("__all__ = ['f']\n__all__.append('g')\n", "1, 2"),
    "item assigned": ("__all__ = ['f']\n__all__[0] = 'g'\n", "1, 2"),
    "deleted": ("__all__ = ['f']\ndel __all__\n", "1, 2"),
    "computed": ("__all__ = sorted(['f'])\n", "1"),
    "not a string": ("__all__ = ['f', 1]\n", "1"),
    "under a block": ("if X:\n    __all__ = ['f']\n", "2"),
    "aliased": ("__all__ = ['f']\nother = __all__\nother.append('g')\n", "1, 2"),
    "passed on": ("__all__ = ['f']\nsorted(__all__)\n", "1, 2"),
    "on the left of in": ("__all__ = ['f']\n__all__ in x\n", "1, 2"),
    "after not in": ("__all__ = ['f']\n'g' not in __all__\n", "1, 2"),
    "unpacked into a call": ("__all__ = ['f']\nprint(*__all__)\n", "1, 2"),
    "imported": ("import __all__\n", "1"),
    "imported as": ("import x as __all__\n", "1"),
    "imported from": ("from m import y as __all__\n", "1"),
    "a function": ("def __all__() -> None: ...\n", "1"),
    "an async function": ("async def __all__() -> None: ...\n", "1"),
    "a class": ("class __all__: ...\n", "1"),
    "a parameter": ("def f(__all__: str) -> None: ...\n", "1"),
    "caught as": ("try:\n    pass\nexcept E as __all__:\n    pass\n", "3"),
    "captured": ("match x:\n    case __all__:\n        pass\n", "2"),
    "star-captured": ("match x:\n    case [*__all__]:\n        pass\n", "2"),
    "captured as": ("match x:\n    case [y] as __all__:\n        pass\n", "2"),
    "mapping rest": ("match x:\n    case {**__all__}:\n        pass\n", "2"),
    "global": ("def f() -> None:\n    global __all__\n", "2"),
    "nonlocal": (
        (
            "def f() -> None:\n    __all__ = 1\n    def g() -> None:\n"
            "        nonlocal __all__\n"
        ),
        "2, 4",
    ),
}


@pytest.mark.parametrize("source, lines", _REFUSED.values(), ids=list(_REFUSED))
def test_the_reader_refuses_any_other_form(source: str, lines: str) -> None:
    """A form the reader does not take raises rather than return a guess."""
    with pytest.raises(ValueError, match=f"^m: .* at line {lines}$"):
        exported_names(ast.parse(source), "m")


def test_the_walk_refuses_a_listed_async_function() -> None:
    """It cannot drive one, so it says so rather than skip it."""
    source = "__all__ = ['f']\nasync def f(a: str) -> None: ...\n"
    with pytest.raises(ValueError, match="^m:2: the walk cannot drive async f$"):
        _drivable_in("m", source)
    # unlisted, it is no business of this walk's
    assert not _drivable_in("m", "__all__ = []\nasync def f(a: str) -> None: ...\n")
