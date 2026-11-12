# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""A fuzz/corpus/ seed is still an address of the coin it is named for.

`fuzz/fuzz_<name>.py` and `fuzz/corpus/fuzz_<name>/` are read from disk.
Every harness imports atheris at module level, which is CI-only and
undeclared in `[dependency-groups]`, so this module never runs `import
fuzz.fuzz_<name>`: it parses the source with `ast` and resolves what a
harness *names* against the installed package, and it loads a harness
under an empty stand-in `atheris` to run its `fuzz_target` on every seed,
as section 7 of the organization's standard asks.

`ENTRY_POINTS`, a module-level tuple of `"module:name"` string literals,
is what each harness names, and `fuzz_target`'s own body has to call each
of them. Every published module that has an `is_valid_address` has it in
`ENTRY_POINTS`, and has it and its `assert_valid_address` handed to
`_agree`. A seed is named for its coin, `<module>_<format>.bin`, and that
coin's entry point has to accept it.

What this gate is for is keeping the fuzzer's own starting point honest
as the validators move under it. A crash the fuzzer finds is a test of
the ordinary suite, naming the input and what the validator now does with
it, and never a seed.
"""

from __future__ import annotations

import ast
import importlib
import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

import coin_addresses
from coin_addresses import evm, litecoin

_FUZZ = Path(__file__).parent.parent / "fuzz"
_CORPUS = _FUZZ / "corpus"


def _harness_paths() -> tuple[Path, ...]:
    """Every fuzz/fuzz_*.py, sorted for a stable parametrize order."""
    return tuple(sorted(_FUZZ.glob("fuzz_*.py")))


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _entry_points(tree: ast.Module) -> tuple[str, ...]:
    """Return the one module-level ENTRY_POINTS tuple of strings."""
    (value,) = (
        ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id == "ENTRY_POINTS"
    )
    assert isinstance(value, tuple)
    assert all(isinstance(v, str) for v in value)
    return value


def _target_calls(tree: ast.Module) -> tuple[dict[str, str], list[ast.Call]]:
    """Return the module-level import bindings and `fuzz_target`'s calls."""
    bindings = {
        alias.asname or alias.name: f"{node.module}.{alias.name}"
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module is not None
        for alias in node.names
    }
    (target,) = (
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "fuzz_target"
    )
    return bindings, [node for node in ast.walk(target) if isinstance(node, ast.Call)]


def _spec(node: ast.expr, bindings: dict[str, str]) -> str | None:
    """Return "package.module:function" for a `module.function` node.

    The module is resolved through the `from package import module` that
    binds its name, so a reference is compared with a declared entry point
    in the one spelling both share; anything else is None.
    """
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id in bindings
    ):
        return f"{bindings[node.value.id]}:{node.attr}"
    return None


def _called(tree: ast.Module) -> set[str]:
    """Every `module.function(...)` call `fuzz_target`'s body makes."""
    bindings, calls = _target_calls(tree)
    return {spec for call in calls if (spec := _spec(call.func, bindings))}


def _agreed(tree: ast.Module) -> set[str]:
    """Every `module.function` whose answer or self `_agree` compares.

    `_agree(m.is_valid_address(text), m.assert_valid_address, text)` names
    both: the first as the function of the call it is handed, the second
    as itself.
    """
    bindings, calls = _target_calls(tree)
    return {
        spec
        for call in calls
        if isinstance(call.func, ast.Name) and call.func.id == "_agree"
        for argument in call.args
        if (
            spec := _spec(
                argument.func if isinstance(argument, ast.Call) else argument,
                bindings,
            )
        )
    }


def _resolve(spec: str) -> Any:
    """Import the callable a "module:name" spec names."""
    module_name, _, name = spec.partition(":")
    return getattr(importlib.import_module(module_name), name)


def _seed_paths(name: str) -> tuple[Path, ...]:
    return tuple(sorted((_CORPUS / name).glob("*.bin")))


def _load_harness(path: Path, monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load a harness under an empty stand-in for its CI-only fuzz engine."""
    monkeypatch.setitem(sys.modules, "atheris", ModuleType("atheris"))
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_HARNESSES = _harness_paths()
_SEEDS = tuple((path, seed) for path in _HARNESSES for seed in _seed_paths(path.stem))
_SEED_IDS = [f"{path.stem}/{seed.name}" for path, seed in _SEEDS]


def test_the_corpus_is_not_empty() -> None:
    """Every assertion below quantifies over _HARNESSES and _SEEDS."""
    assert _HARNESSES, f"{_FUZZ} holds no fuzz_*.py"
    assert _SEEDS, f"{_CORPUS} holds no seed"


def test_every_corpus_directory_has_a_harness_and_back() -> None:
    """A harness with no seeds, or seeds with no harness, is unchecked."""
    harnesses = {path.stem for path in _HARNESSES}
    directories = {d.name for d in _CORPUS.iterdir() if d.is_dir()}
    assert harnesses == directories


@pytest.mark.parametrize("path", _HARNESSES, ids=lambda p: p.stem)
def test_entry_points_are_what_the_target_calls(path: Path) -> None:
    """ENTRY_POINTS is declared, resolves, and is what fuzz_target calls."""
    tree = _tree(path)
    declared = _entry_points(tree)
    assert declared, f"{path.name} declares no non-empty ENTRY_POINTS"
    for spec in declared:
        assert callable(_resolve(spec)), spec
    called = _called(tree)
    assert set(declared) <= called, sorted(set(declared) - called)


def test_every_validator_is_fuzzed() -> None:
    """Each published module's validators are a harness's to compare.

    Its `is_valid_address` is an entry point and is called by the target,
    and both it and its `assert_valid_address` are handed to `_agree`. The
    modules are read off `coin_addresses.__all__`, so a coin added to the
    package fails here until a harness validates its addresses.
    """
    trees = [_tree(path) for path in _HARNESSES]
    declared = set().union(*(_entry_points(tree) for tree in trees))
    called = set().union(*(_called(tree) for tree in trees))
    agreed = set().union(*(_agreed(tree) for tree in trees))
    modules = [
        f"coin_addresses.{name}"
        for name in coin_addresses.__all__
        if hasattr(getattr(coin_addresses, name), "is_valid_address")
    ]
    assert modules, "no published module has a validator"
    validators = {f"{module}:is_valid_address" for module in modules}
    asserts = {f"{module}:assert_valid_address" for module in modules}
    assert not validators - declared, sorted(validators - declared)
    assert not validators - called, sorted(validators - called)
    assert not (validators | asserts) - agreed, sorted((validators | asserts) - agreed)


@pytest.mark.parametrize("path, seed", _SEEDS, ids=_SEED_IDS)
def test_every_seed_is_an_address_of_its_coin(path: Path, seed: Path) -> None:
    """The entry point of the coin a seed is named for accepts it."""
    (spec,) = (
        spec
        for spec in _entry_points(_tree(path))
        if seed.stem.startswith(spec.partition(":")[0].rpartition(".")[2] + "_")
    )
    assert _resolve(spec)(seed.read_bytes().decode("utf-8")), spec


@pytest.mark.parametrize("path, seed", _SEEDS, ids=_SEED_IDS)
def test_seed_runs_its_harness(
    monkeypatch: pytest.MonkeyPatch, path: Path, seed: Path
) -> None:
    """A seed passes every check its target makes."""
    _load_harness(path, monkeypatch).fuzz_target(seed.read_bytes())


@pytest.fixture
def addresses_harness(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """Load the address harness under a stand-in atheris."""
    return _load_harness(_FUZZ / "fuzz_addresses.py", monkeypatch)


def _seed(name: str) -> bytes:
    return (_CORPUS / "fuzz_addresses" / f"{name}.bin").read_bytes()


@pytest.mark.parametrize(
    "answer, seed", [(False, "evm_eip55"), (True, "litecoin_p2pkh")]
)
def test_the_harness_refuses_validators_that_disagree(
    addresses_harness: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    answer: bool,
    seed: str,
) -> None:
    """An `is_valid_address` that answers otherwise is a finding.

    The Ethereum one is replaced by a constant: `False` for an Ethereum
    seed, which `assert_valid_address` accepts, and `True` for a Litecoin
    one, which it refuses.
    """
    monkeypatch.setattr(evm, "is_valid_address", lambda _: answer)
    with pytest.raises(
        AssertionError, match="^assert_valid_address and is_valid_address disagree$"
    ):
        addresses_harness.fuzz_target(_seed(seed))


def test_the_harness_propagates_any_other_exception(
    addresses_harness: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the package's refusal leaves a validator quietly."""

    def fail(address: str) -> None:
        raise IndexError("validation failed")

    monkeypatch.setattr(litecoin, "assert_valid_address", fail)
    with pytest.raises(IndexError, match="^validation failed$"):
        addresses_harness.fuzz_target(_seed("evm_eip55"))
