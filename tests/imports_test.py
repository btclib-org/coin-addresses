# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""Tests for the import graph of the `coin_addresses` package.

Every module must be importable *first*, with no other module of this
package in sys.modules yet. Nothing else in the suite establishes that: a
test module reaches its subject through whatever the modules imported
before it have already pulled in, so a cycle that only bites the caller
who happens to arrive from the other side stays invisible.

What a module may import is the standard library, this package, and
the packages `dependencies` in pyproject.toml declares: each module is
asked in an interpreter of its own at run time, and each file's import
statements are read statically, which is what a module the suite never
imports is checked by. At run time a declared package may load what it
requires in turn; a file of this package names only what it declares.
btclib is refused whatever declares it, CONTRIBUTING.md's *The public
surface* saying why.
"""

from __future__ import annotations

import ast
import importlib
import re
import subprocess
import sys
from importlib.metadata import packages_distributions, requires
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest

import coin_addresses

from . import module_names

if TYPE_CHECKING:
    from collections.abc import Iterator

_ROOT = Path(__file__).resolve().parents[1]

# the distribution no module of this package may load, whatever declares
# it
_REFUSED = frozenset({"btclib"})


def _normalized(name: str) -> str:
    """Return a distribution's name as PEP 503 compares it."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _required_by(distribution: str) -> set[str]:
    """Return the distributions one installed distribution requires.

    A requirement behind an extra is left out, an extra being what a
    caller asks for and this package does not. Any other marker is kept,
    so that the answer is the same on every interpreter.
    """
    return {
        _normalized(re.split(r"[\s;<>=!~\[(]", requirement, maxsplit=1)[0])
        for requirement in requires(distribution) or []
        if "extra ==" not in requirement
    }


def _declared() -> set[str]:
    """Return the distributions this package declares, from its metadata."""
    return _required_by("coin-addresses")


def _allowed() -> set[str]:
    """Return the declared distributions and what they require, transitively."""
    allowed: set[str] = set()
    pending = _declared()
    while pending:
        distribution = pending.pop()
        allowed.add(distribution)
        pending |= _required_by(distribution) - allowed
    return allowed - _REFUSED


def _distributions_of(module: str) -> set[str]:
    """Return the distributions that install a module's top-level package."""
    top = module.split(".", maxsplit=1)[0]
    return {_normalized(d) for d in packages_distributions().get(top, [top])}


def _is_ours(name: str) -> bool:
    """Answer whether a dotted name is this package or one of its modules.

    `coin_addresses.` and not a bare `startswith`, which would also take
    in a sibling distribution whose name merely begins the same way.
    """
    return name == "coin_addresses" or name.startswith("coin_addresses.")


def loaded_modules() -> list[str]:
    """Return the modules of this package in sys.modules."""
    return [name for name in sys.modules if _is_ours(name)]


@pytest.fixture
def unimported() -> Iterator[None]:
    """Hide every module of this package, then put it back.

    A subprocess per module would be the obvious way to get a virgin
    interpreter, and it costs an interpreter start-up per module for
    nothing: the import machinery decides what to execute by consulting
    sys.modules and nothing else.

    What the modules imported inside the fixture must not do is outlive
    it. They are fresh objects, so a class reimported here is not the
    class the rest of the suite already holds a reference to, and an
    isinstance check across the two would fail.
    """
    saved = {name: sys.modules[name] for name in loaded_modules()}
    for name in saved:
        del sys.modules[name]
    try:
        yield
    finally:
        for name in loaded_modules():
            del sys.modules[name]
        sys.modules.update(saved)


@pytest.mark.parametrize("module_name", module_names())
def test_import_first(module_name: str, unimported: None) -> None:
    """Import each module first, with nothing of this package loaded."""
    assert importlib.import_module(module_name).__name__ == module_name


def _loaded_after_importing(module_name: str) -> list[str]:
    """Import one module in a fresh interpreter and return sorted(sys.modules).

    A fresh subprocess rather than `unimported`: that fixture only hides
    this package's own modules from `sys.modules`, so a third-party
    package an earlier test already imported would still answer present,
    and the absence this module exists to prove would mean nothing.
    """
    probe = f"import {module_name}, sys; print(sorted(sys.modules))"
    stdout = subprocess.run(  # noqa: S603
        [sys.executable, "-c", probe],
        check=True,
        capture_output=True,
        encoding="utf-8",
        cwd=_ROOT,
    ).stdout
    return cast("list[str]", ast.literal_eval(stdout))


def test_the_tests_package_imports_no_submodule() -> None:
    """Importing the `tests` package alone reaches the root and no further.

    `tests/__init__.py` is imported by every test module before that
    module's own body runs -- before any fixture, `unimported` included,
    so this probe is a subprocess rather than that fixture. The coverage
    floor reads what the import itself reaches, so a helper built at the
    module scope of `tests/__init__.py` would be measured as reached by
    every module that asks it nothing.
    """
    loaded = _loaded_after_importing("tests")
    assert [m for m in loaded if _is_ours(m)] == ["coin_addresses"]


# the modules of one interpreter that were loaded from where an installer
# puts a distribution, by name: `__file__` under a directory called
# `site-packages` or `dist-packages`, or under the purelib or the platlib
# directory. The directory name is what finds a package that `uv run --with`
# layers over the environment: it sits in a site-packages directory that
# `sysconfig` does not name. Keyed on the file and not on
# `sys.stdlib_module_names`, which lists the standard library's public
# names: PyPy implements some of it in modules of its own -- `_blake2`,
# `_cffi_ssl`, `_lzma_cffi` -- that the list does not name and that live
# beside the standard library, not in site-packages
_INSTALLED = """
import sys, sysconfig
from pathlib import Path
roots = {Path(sysconfig.get_paths()[key]).resolve() for key in ("purelib", "platlib")}
sites = {"site-packages", "dist-packages"}
def installed(module):
    file = getattr(module, "__file__", None)
    if file is None:
        return False
    path = Path(file)
    return bool(sites.intersection(path.parts)) or any(
        root in path.resolve().parents for root in roots
    )
print(sorted(name for name, module in list(sys.modules.items()) if installed(module)))
"""


def _installed_after_importing(module_name: str) -> set[str]:
    """Import one module in a fresh interpreter; return what was installed."""
    stdout = subprocess.run(  # noqa: S603
        [sys.executable, "-c", f"import {module_name}\n{_INSTALLED}"],
        check=True,
        capture_output=True,
        encoding="utf-8",
        cwd=_ROOT,
    ).stdout
    return set(cast("list[str]", ast.literal_eval(stdout)))


def _installed_by(module_name: str) -> list[str]:
    """Return the installed modules importing one module adds, ours aside.

    The difference from an interpreter that imported nothing, rather than
    the whole of `sys.modules`: site initialization loads modules of its
    own before `-c` runs -- a virtual environment's `_virtualenv`,
    setuptools' `_distutils_hack`, a namespace package's `.pth` -- and
    none of them is something this package imported.
    """
    added = _installed_after_importing(module_name) - _installed_after_importing("sys")
    return sorted(name for name in added if not _is_ours(name))


def _outside(names: set[str]) -> list[str]:
    """Return the names that are not the standard library's, ours or declared.

    Read off the names, which is what a file's import statements give:
    the static half below has no interpreter to ask where a module lives.
    A declared distribution's requirements are not among what is allowed
    here: a file that names one relies on what it has not declared.
    """
    declared = _declared() - _REFUSED
    return sorted(
        name
        for name in names
        if name.split(".")[0] not in sys.stdlib_module_names
        and not _is_ours(name)
        and not _distributions_of(name) & declared
    )


def _undeclared(modules: list[str]) -> list[str]:
    """Return the installed modules no declared distribution accounts for."""
    allowed = _allowed()
    return sorted(m for m in modules if not _distributions_of(m) & allowed)


@pytest.mark.parametrize("module_name", module_names())
def test_the_package_loads_only_what_it_declares(module_name: str) -> None:
    """Each module, imported alone, loads only what `dependencies` accounts for.

    A runtime import of anything else -- a package the test group installs
    included -- would break in every environment but this one, where the
    import happens to resolve.
    """
    assert _undeclared(_installed_by(module_name)) == []


def test_the_runtime_check_sees_an_undeclared_import() -> None:
    """The check names what an import of an undeclared package adds.

    `iniconfig` is installed by the test group, pytest requiring it, and
    declared by nothing the package declares, so importing it is what a
    module of the package importing it would add.
    """
    assert "iniconfig" in _undeclared(_installed_by("iniconfig"))


def test_the_declared_packages_are_allowed() -> None:
    """`ecc` is declared, and what it requires is allowed beside it.

    The allowance is read from the installed metadata, so this is what
    keeps a metadata lookup that found nothing from allowing nothing and
    passing every module that loads no package at all. What ecc requires
    is read from its metadata too, and not named here: a requirement ecc
    drops is no defect of this tree.
    """
    assert "ecc" in _declared()
    assert {"ecc", *_required_by("ecc")} <= _allowed()
    assert _distributions_of("ecc.curves") == {"ecc"}
    assert not _undeclared(["ecc.curves"])


def test_the_allowance_follows_requirements_transitively(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """What a requirement requires is allowed, an extra's requirement not."""
    graph = {
        "coin-addresses": ["first>=1"],
        "first": ["Second_Package ; python_version >= '3.11'", "third ; extra == 'x'"],
    }

    def requiring(distribution: str) -> list[str]:
        return graph.get(distribution, [])

    monkeypatch.setattr(sys.modules[__name__], "requires", requiring)
    assert _allowed() == {"first", "second-package"}


def test_btclib_is_refused_whatever_declares_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A declared package that required btclib would not make it allowed."""

    def requiring_btclib(distribution: str) -> list[str]:
        return ["btclib>=2026.1"] if distribution == "coin-addresses" else []

    monkeypatch.setattr(sys.modules[__name__], "requires", requiring_btclib)
    assert _declared() == {"btclib"}
    assert _allowed() == set()


def _top_level_imports(source: str) -> set[str]:
    """Return the first component of every name one module's imports name.

    Relative imports name this package, so they are recorded as it.
    """
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add(
                "coin_addresses" if node.level else (node.module or "").split(".")[0]
            )
    return names


def test_the_import_scan_finds_a_planted_import() -> None:
    """The scan names each form, and the check refuses what is outside."""
    source = (
        "import hashlib\nimport btclib.utils\nfrom btclib_wallet import bip32\n"
        "from . import exceptions\nfrom typing_extensions import override\n"
        "from ecc.curves import mult\n"
    )
    names = _top_level_imports(source)
    assert names == {
        "hashlib",
        "btclib",
        "btclib_wallet",
        "coin_addresses",
        "ecc",
        "typing_extensions",
    }
    assert _outside(names) == ["btclib", "btclib_wallet", "typing_extensions"]


def test_no_module_imports_what_it_does_not_declare() -> None:
    """Every file of the package, read rather than imported.

    The static half of `test_the_package_loads_only_what_it_declares`: an import
    inside a function or behind `TYPE_CHECKING` is one no interpreter
    runs at import, and it would still fail the day it ran.
    """
    root = Path(coin_addresses.__path__[0])
    found = {
        path.relative_to(root).as_posix(): _outside(
            _top_level_imports(path.read_text(encoding="utf-8"))
        )
        for path in sorted(root.rglob("*.py"))
    }
    assert "exceptions.py" in found
    assert _top_level_imports((root / "evm.py").read_text(encoding="utf-8")) >= {"ecc"}
    assert not {file: names for file, names in found.items() if names}
