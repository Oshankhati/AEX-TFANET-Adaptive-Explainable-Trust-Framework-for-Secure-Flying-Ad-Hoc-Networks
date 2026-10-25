from __future__ import annotations

import os
from pathlib import Path

import pytest

from aex_tfanet.utils.paths import project_root


@pytest.fixture(autouse=True)
def _cwd_project_root() -> None:
    root = project_root()
    os.chdir(root)
    assert Path.cwd() == root
