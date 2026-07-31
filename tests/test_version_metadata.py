"""``__version__`` must equal the installed distribution version.

The 0.1.0 wheel shipped ``sm_authority.__version__ == "0.0.1"`` while its dist
metadata correctly said ``0.1.0``. Two hand-maintained copies of one fact, with
nothing comparing them. The practical cost was not cosmetic: a consumer doing a
defensive runtime version check to avoid the vulnerable release (sm-authority#2,
the OIDC confused-deputy) read ``0.0.1`` and could not detect it — the dependency
floor was the only enforcement point left.

These tests fail on that shape rather than on the specific wrong number.
"""

from __future__ import annotations

import re
import tomllib
from importlib.metadata import version as dist_version
from pathlib import Path

import pytest

import sm_authority


def test_dunder_version_equals_installed_distribution_version() -> None:
    assert sm_authority.__version__ == dist_version("sm-authority")


def test_dunder_version_is_not_the_uninstalled_sentinel() -> None:
    # The source-tree fallback must never reach an installed environment; if it
    # does, every consumer's version check silently reads a placeholder.
    assert sm_authority.__version__ != "0.0.0.dev0"


def test_module_source_declares_no_version_literal() -> None:
    """The regression guard proper.

    Equality above passes the moment someone re-adds a literal that happens to
    match today. This fails on the *duplication* — the thing that drifts — so a
    future hand-maintained copy is rejected even while it is still correct.
    """
    src = Path(sm_authority.__file__).read_text(encoding="utf-8")
    literals = re.findall(r'^__version__\s*=\s*["\']', src, flags=re.MULTILINE)
    assert not literals, (
        "__version__ must be derived from distribution metadata, not assigned a "
        "literal — a literal is a second copy of pyproject's version and drifts."
    )


def test_pyproject_remains_the_single_declared_source() -> None:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    if not pyproject.exists():  # installed-only test run
        pytest.skip("source checkout not present")
    declared = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["version"]
    assert declared == dist_version("sm-authority"), (
        "pyproject declares the version; a mismatch here means the installed "
        "wheel was built from a different tree than this checkout."
    )
