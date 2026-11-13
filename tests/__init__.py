# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The coin_addresses test suite, and the code its modules share.

Here rather than in a `tests/helpers.py`: every Python file under `tests/`
is a test file except `__init__.py` and `conftest.py`, so shared test
code lives in the package `__init__`.

This package is imported by every test module, before that module's own
body runs. Whatever this file executes at import time therefore executes
inside every module's own measured reach: the suite's coverage floor
reads what the import reaches, never what a test body goes on to call. A
literal is safe to share here at module scope. Anything that calls into
the package's own code is shared as a function instead, computed only
when a caller invokes it.
"""

import ast
import pkgutil

import coin_addresses


def module_names() -> list[str]:
    """Return every module of the installed coin_addresses, the root included.

    Here rather than at each site that walks the package, none of which
    owns the walk. What the walk covers -- a second package root, a
    different prefix, a module it has to skip -- is settled here for all
    of them, and a copy that disagreed would be red nowhere: each site
    asserts against whatever its own walk found.
    """
    return [
        "coin_addresses",
        *(
            module.name
            for module in pkgutil.walk_packages(
                coin_addresses.__path__, "coin_addresses."
            )
        ),
    ]


def _names_all(node: ast.AST) -> bool:
    """Return whether a node names `__all__`, as a name or as a binding.

    A binding can hold the name as a string field rather than as a `Name`:
    an import alias, a definition, an `except ... as`, a match capture, a
    parameter, a `global` or `nonlocal`.
    """
    if isinstance(node, ast.Name):
        return node.id == "__all__"
    if isinstance(node, (ast.Global, ast.Nonlocal)):
        return "__all__" in node.names
    return any(
        getattr(node, field, None) == "__all__"
        for field in ("name", "asname", "rest", "arg")
    )


def _read_as_src_reads(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    """Return whether a node reads `__all__` in a shape src uses.

    `name in __all__`, and `*__all__` unpacked into a set display: neither
    can bind the list to another name, so no alias can mutate it.
    """
    parent = parents.get(node)
    match parent:
        case ast.Compare(ops=[ast.In()], comparators=[comparator]):
            return comparator is node
        case ast.Starred(ctx=ast.Load()):
            return isinstance(parents.get(parent), ast.Set)
        case _:
            return False


def exported_names(tree: ast.Module, module: str) -> set[str]:
    """Return the names a module's `__all__` lists, read off its source.

    What a module lists is what CONTRIBUTING.md's "The public surface"
    calls public. A module with no list exports nothing here.

    The reader accepts one write, a single assignment at module level,
    plain or annotated, of a list or a tuple of string literals, and the
    reads src makes, which `_read_as_src_reads` names. It refuses every
    other mention of `__all__` with the module and the lines, because a
    guess would change what the gates reading it cover without failing
    anything.
    """
    parents = {
        child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)
    }
    mentions = [
        node
        for node in ast.walk(tree)
        if _names_all(node) and not _read_as_src_reads(node, parents)
    ]
    if not mentions:
        return set()
    for statement in tree.body:
        match statement:
            case (
                ast.Assign(
                    targets=[target], value=ast.List(elts=elts) | ast.Tuple(elts=elts)
                )
                | ast.AnnAssign(
                    target=target, value=ast.List(elts=elts) | ast.Tuple(elts=elts)
                )
            ) if mentions == [target]:
                names = [
                    e.value
                    for e in elts
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)
                ]
                if len(names) == len(elts):
                    return set(names)
            case _:
                continue
    lines = ", ".join(str(n) for n in sorted(getattr(m, "lineno", 0) for m in mentions))
    msg = (
        f"{module}: __all__ appears in a form the reader does not take, at line {lines}"
    )
    raise ValueError(msg)
