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
