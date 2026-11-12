# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The gate for what a public function's name promises about its answer.

CONTRIBUTING.md's "The public surface" states the vocabulary: `assert_*`
refuses and returns None, `is_*` and `verify*` answer a bool about a
value of a declared type, and `check_*` answers a bool *and* refuses
what cannot be an answer -- the one prefix that warns a caller it still
needs an `except`.

A prefix that says several things says nothing, which is what issue
btclib-org/btclib#814 found of `check_`, and a vocabulary kept as a habit
is one nothing notices drifting. So it is a rule here, read off the
annotations rather than off a list of names somebody keeps in step. What
it cannot see is the *contract*: that one `is_` is total over its values
and one `check_` is not is a promise in prose, and only the return type
is here.

There is no exemption list: every name carrying a prefix is held to it,
and every public bool carries one.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_LIBRARY = Path(__file__).parents[1] / "src" / "coin_addresses"

# what each prefix promises the return type is. `verify` is matched anywhere in
# the name and not only at the front: a `batch_verify` is a verification, and
# reading the front alone is what left such names out of issue
# btclib-org/btclib#814's first census
_PROMISED: dict[str, str] = {
    "assert_": "None",
    "check_": "bool",
    "is_": "bool",
    "verify": "bool",
}


def _promised_by(name: str) -> str | None:
    """Return the type the name promises, or None if it promises nothing."""
    return next(
        (
            promised
            for prefix, promised in _PROMISED.items()
            if name.startswith(prefix) or (prefix == "verify" and prefix in name)
        ),
        None,
    )


def _named() -> dict[str, str]:
    """Return every public function whose name promises a return type.

    Methods included, a property being one: an `is_` read off an object
    promises a bool as much as a module-level one does.

    The dotted name is the file's path and keeps the `__init__` of a
    package module, which is what `input_validation_test.py`'s walk does
    and is importable either way: one spelling across the two gates.
    """
    found: dict[str, str] = {}
    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef) or node.name.startswith("_"):
                continue
            if _promised_by(node.name) is None:
                continue
            # every function of this package is annotated, mypy running
            # strict over it, so an unannotated one is a state the tree
            # does not reach
            assert node.returns is not None
            found[f"{module}.{node.name}"] = ast.unparse(node.returns)
    return found


# an argument-less member of a public class is a read, and a read is a
# `@property`. These are the shapes that are not a read, by what they do
# rather than by a list of names -- which is what keeps the rule from
# needing one (issue btclib-org/btclib#814):
#
# - `assert_*` refuses, and a property that refuses is a trap: reading
#   `obj.assert_valid` evaluates the method and throws it away
# - `to_*` converts, and hands back a new object rather than a read of
#   this one
_NOT_A_READ = ("assert_", "to_")


def _is_a_read(decorated: set[str]) -> bool:
    """Return whether the decorators make this a read rather than a call.

    `functools.cached_property` is one as much as `property` is -- it
    computes once and is read thereafter -- and testing the set for
    `"property"` alone would miss it.
    """
    return bool(
        decorated & {"property", "cached_property", "functools.cached_property"}
    )


def _members_of(module: str, source: str) -> dict[str, bool]:
    """Return every argument-less member of a public class of one module.

    A property is a class thing, so a module-level function is out of
    scope however few arguments it takes. Methods of a private class
    are out too: a private class is not API.
    """
    found: dict[str, bool] = {}
    for cls in ast.walk(ast.parse(source)):
        if not isinstance(cls, ast.ClassDef) or cls.name.startswith("_"):
            continue
        for node in cls.body:
            if not isinstance(node, ast.FunctionDef) or node.name.startswith("_"):
                continue
            decorated = {ast.unparse(d) for d in node.decorator_list}
            # no filter for a `@x.setter`: one takes the value it
            # sets, so the argument count below excludes it already
            arguments = [
                a.arg
                for a in [
                    *node.args.posonlyargs,
                    *node.args.args,
                    *node.args.kwonlyargs,
                ]
                if a.arg != "self"
            ]
            # a static or class method is no read of an instance,
            # whatever its arguments
            bound = not {"staticmethod", "classmethod"} & decorated
            if arguments or node.args.vararg or node.args.kwarg or not bound:
                continue
            found[f"{module}.{cls.name}.{node.name}"] = _is_a_read(decorated)
    return found


def _class_members() -> dict[str, bool]:
    """Return every argument-less member of a public class of the library."""
    found: dict[str, bool] = {}
    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        found |= _members_of(module, path.read_text(encoding="utf-8"))
    return found


def _misread(members: dict[str, bool]) -> list[str]:
    """Return the members read where the name says call, or the reverse."""
    return sorted(
        dotted
        for dotted, is_a_read in members.items()
        if is_a_read is dotted.rpartition(".")[2].startswith(_NOT_A_READ)
    )


def _public_bools() -> list[str]:
    """Return every public function that answers a bool, however named.

    The dotted name drops the class, as `_named` above does: a method and
    a module function of one name are one entry, which is the spelling
    `input_validation_test.py` uses too.
    """
    found: list[str] = []
    for path in sorted(_LIBRARY.rglob("*.py")):
        module = ".".join(path.relative_to(_LIBRARY.parent).with_suffix("").parts)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef) or node.name.startswith("_"):
                continue
            if node.returns is not None and ast.unparse(node.returns) == "bool":
                found.append(f"{module}.{node.name}")
    return sorted(found)


_NAMED = _named()
_PUBLIC_BOOLS = _public_bools()
_CLASS_MEMBERS = _class_members()


@pytest.mark.parametrize("dotted", sorted(_NAMED))
def test_the_name_says_what_the_answer_is(dotted: str) -> None:
    """The rule, over every public name that carries one of the prefixes."""
    promised = _promised_by(dotted.rpartition(".")[2])
    assert _NAMED[dotted] == promised, (
        f"{dotted} returns {_NAMED[dotted]} where its name promises {promised}"
    )


def test_the_walk_reaches_what_it_claims() -> None:
    """One name per prefix it must find, and the two kinds it must not.

    A walk that found nothing would pass the test above.
    """
    assert _NAMED["coin_addresses.evm.is_valid_address"] == "bool"
    assert _NAMED["coin_addresses.evm.assert_valid_address"] == "None"

    # a name that promises nothing
    assert "coin_addresses.evm.address_from_pub_key" not in _NAMED


def test_check_says_one_thing() -> None:
    """`check_` is the prefix btclib-org/btclib#814 found meaning four things.

    None is here, and pinning that keeps one from being added without
    the question being asked: a refusal is an `assert_`, a converter is
    named for what it returns, and a query for what it answers.
    """
    checks = {d for d in _NAMED if d.rpartition(".")[2].startswith("check_")}
    assert not checks


@pytest.mark.parametrize("dotted", _PUBLIC_BOOLS)
def test_every_public_bool_is_named_by_the_vocabulary(dotted: str) -> None:
    """A bool carries one of the four prefixes.

    What this closes is the gap the prefixes alone leave: they promise a
    shape to a caller who sees one, and say nothing about a bool that
    carries none.
    """
    name = dotted.rpartition(".")[2]
    assert _promised_by(name) is not None, (
        f"{dotted} answers a bool and its name promises nothing"
    )


def test_an_argument_less_member_is_read_not_called() -> None:
    """Whatever it answers, a member that takes nothing is a `@property`.

    Two reads of one object spelled two ways, one as an attribute and one
    as a call, are one shape more than a reader should have to remember.

    What is not a read is here by shape and not by a list of names, which
    is what keeps this rule from needing one.
    """
    assert _misread(_CLASS_MEMBERS) == [], (
        "a @property where the name says it is not a read, or a method"
        " taking nothing but self where it is"
    )


_SOURCE = """
class Public:
    @property
    def is_read(self) -> bool: ...
    def assert_valid(self) -> None: ...
    def called(self) -> int: ...
    def takes(self, value: int) -> int: ...
    @staticmethod
    def static() -> int: ...
class _Private:
    def called(self) -> int: ...
"""


def test_the_walk_reaches_every_shape_of_member() -> None:
    """What the walk finds, and what it reads the decorators as.

    The package's public classes are its exceptions, which define no
    member, so the walk finds none in the library; a source with every
    shape is what it is asked of instead.
    """
    assert _CLASS_MEMBERS == {}
    members = _members_of("m", _SOURCE)
    assert members == {
        "m.Public.is_read": True,
        "m.Public.assert_valid": False,
        "m.Public.called": False,
    }
    assert _misread(members) == ["m.Public.called"]
    assert _is_a_read({"property"})
    assert _is_a_read({"functools.cached_property"})
    assert not _is_a_read({"staticmethod"})
