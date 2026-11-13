# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the one rule on a private signature: it carries no default.

A default argument is written for a caller the author cannot see, and a
private function has none: every call site is in this tree and can be
read. What the default buys is therefore nothing, and what it costs
is the value the call is actually made with, which a default leaves
unread at the call site that most needs to state it. Spelled out, a
flag added to a private function is also a question asked again at every
one of its call sites, where a default answers it for all the ones nobody
revisited.

A module-level function is private when its module's `__all__` leaves
it out, as CONTRIBUTING.md's "The public surface" defines a public name,
and that section states this rule beside it. So a helper of a private
module is held to the rule whatever its own name. A method or a nested
function is in no list, and its own leading underscore decides.

Two spellings the rule does not reach: a dunder, whose signature is the
interpreter's protocol and a public constructor's where it is `__init__`,
and a public method of a private class, the rule being about the name a
call site reads. A name-mangled `__two_leading_underscores` is private and
is reached.

The library and not this directory, which is a scope and not an oversight:
a test helper's default is doing the opposite work, a fixture with one
field overridden per case, where naming the others at each site would
bury the field under test.

The walk reads the sources instead of importing the modules, so that a
method and a nested function are reached as well, and a definition under
an `if`, a `try`, a `with`, a loop or a `match` at any of those levels;
the control tests after the gate are what keep it from passing on a walk
that found nothing.
"""

from __future__ import annotations

import ast
from pathlib import Path

from . import exported_names
from .all_test import module_scope

_LIBRARY = Path(__file__).parents[1] / "src" / "coin_addresses"

# the shapes the walk has to be reaching for the gate to mean anything:
# module-level functions of two modules. The library has no private
# method and no nested private function, which `_SOURCE` below holds
# instead. A rename here is a failure worth reading rather than fixing
# blind -- what it asks for is the new name of the same shape
_SHAPES = frozenset({"_checksum_encode", "_permute", "_rotate"})

# every private function of a module, with the parameters it defaults:
# what `_private_functions` answers, and what the checker test pins
_EXPECTED: dict[str, list[str]] = {
    "_plain": ["b"],
    "_positional_only": ["a"],
    "_keyword_only": ["flag"],
    "_no_default": [],
    "unlisted": ["a"],
    "unlisted_async": ["a"],
    "unlisted_in_if": ["a"],
    "_in_else": ["a"],
    "in_try": ["a"],
    "_in_finally": ["a"],
    "Guarded._conditional": ["a"],
    "guarded_outer._nested_in_with": ["b"],
    "__mangled": ["a"],
    "_Private._method": ["a"],
    "Public._method": ["flag"],
    "Public._async_method": ["a"],
    "outer._nested": ["b"],
}

# one function per shape, defaulted and clean, private and public: the
# source the checker is measured on, so that what it reports is a
# statement about the tree and not about the walk
_SOURCE = """
__all__ = ["Guarded", "Public", "guarded_outer", "outer", "public"]


def public(a=1): ...


def unlisted(a=1): ...


async def unlisted_async(a=1): ...


def _plain(a, b=2): ...


def _positional_only(a=1, /): ...


def _keyword_only(*, flag=False): ...


def _no_default(a, b): ...


def __mangled(a=1): ...


class _Private:
    field: int = 0

    def __init__(self, a=1): ...

    def public_method(self, a=1): ...

    def _method(self, a=1): ...


class Public:
    def _method(self, *, flag=True): ...

    async def _async_method(self, a=1): ...


def outer(a=1):
    def _nested(b=2): ...

    return _nested


if X:
    def unlisted_in_if(a=1): ...
else:
    def _in_else(a=1): ...


try:
    def in_try(a=1): ...
except E:
    pass
finally:
    def _in_finally(a=1): ...


class Guarded:
    if X:
        def _conditional(self, a=1): ...

        def conditional_public(self, a=1): ...


def guarded_outer():
    with C:
        def _nested_in_with(b=2): ...
"""


def _is_dunder(name: str) -> bool:
    return name.startswith("__") and name.endswith("__")


def _defaulted(args: ast.arguments) -> list[str]:
    """Return the parameters of a signature that have a default.

    The positional defaults align to the *end* of the positional
    parameters, positional-only ones included, and the keyword-only
    defaults align one-to-one with `kwonlyargs`, `None` where there is
    none -- a shape a `zip` cannot be read off without `strict`.
    """
    positional = args.posonlyargs + args.args
    defaulted = positional[len(positional) - len(args.defaults) :]
    return [arg.arg for arg in defaulted] + [
        arg.arg
        for arg, default in zip(args.kwonlyargs, args.kw_defaults, strict=True)
        if default is not None
    ]


def _private_functions(module: str, source: str) -> dict[str, list[str]]:
    """Return the private functions of a module, each with its defaults.

    Keyed by qualified name, so a failure names the function and not only
    the file, and carrying the clean ones too: which functions the walk
    reached is itself asserted below.
    """
    tree = ast.parse(source)
    exported = exported_names(tree, module)
    found: dict[str, list[str]] = {}

    # `module_scope` yields the statements of any body that run in the
    # scope it opens, a class's or a function's as much as a module's
    def visit(body: list[ast.stmt], prefix: str, *, at_module: bool) -> None:
        for child in module_scope(body):
            if isinstance(child, ast.ClassDef):
                visit(child.body, f"{prefix}{child.name}.", at_module=False)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = f"{prefix}{child.name}"
                # the module's list decides at its top level, and the name
                # below it, where no list reaches
                private = (
                    child.name not in exported
                    if at_module
                    else child.name.startswith("_")
                )
                if private and not _is_dunder(child.name):
                    found[name] = _defaulted(child.args)
                visit(child.body, f"{name}.", at_module=False)

    visit(tree.body, "", at_module=True)
    return found


def test_no_private_function_takes_a_default_argument() -> None:
    """The gate: the library's private signatures are all bare.

    One failure line per parameter rather than per function, the fix
    being per parameter: drop the default, and pass the value at each
    call site -- which is the diff that makes the composition readable,
    not a cost of the rule.
    """
    offenders = [
        f"{path.relative_to(_LIBRARY.parent)}: {name}({parameter}=...)"
        for path in sorted(_LIBRARY.rglob("*.py"))
        for name, parameters in _private_functions(
            path.name, path.read_text(encoding="utf-8")
        ).items()
        for parameter in parameters
    ]
    assert not offenders, (
        "a private function takes no default argument, its callers being"
        " this tree's own: " + ", ".join(offenders)
    )


def test_the_checker_reads_every_shape_a_signature_has() -> None:
    """What the gate is worth, measured on a source with known answers.

    Each half is a way for the gate to pass while enforcing nothing: a
    walk that skips methods, mangled names or nested functions would not
    see a default there, nor one that read a module-level name rather
    than the list, and a walk that took a listed function or a dunder for
    private would report one where the rule allows it.
    """
    assert _private_functions("m", _SOURCE) == _EXPECTED


def test_the_walk_reaches_the_library() -> None:
    """The gate over an empty walk would pass, and say nothing.

    A wrong path, a suffix that matches no file, or a walk that stops at
    module level all read as a library with no private function in it.
    """
    reached: set[str] = set()
    for path in sorted(_LIBRARY.rglob("*.py")):
        reached |= _private_functions(
            path.name, path.read_text(encoding="utf-8")
        ).keys()
    assert reached >= _SHAPES, (
        "the walk no longer reaches: "
        + ", ".join(sorted(_SHAPES - reached))
        + ". If one was renamed, name its replacement -- the shapes are what"
        " the gate above is asserted over"
    )


def test_the_list_decides_what_is_private() -> None:
    """A public name the module's `__all__` leaves out is held to the rule.

    `coin_addresses._bitcoin.base58_address` is the control: a public name
    in a private module, whose keyword `alphabet` is required. The walk
    reaches it bare, and reports the default once one is planted there.
    A function `__all__` lists is not reached.
    """
    source = (_LIBRARY / "_bitcoin.py").read_text(encoding="utf-8")
    assert _private_functions("_bitcoin.py", source)["base58_address"] == []

    planted = source.replace(
        "def base58_address(version: int, digest: bytes, *, alphabet: bytes)",
        "def base58_address(version: int, digest: bytes, *, alphabet: bytes = b'')",
    )
    assert planted != source
    assert _private_functions("_bitcoin.py", planted)["base58_address"] == ["alphabet"]

    evm = (_LIBRARY / "evm.py").read_text(encoding="utf-8")
    assert "address_from_pub_key" not in _private_functions("evm.py", evm)
