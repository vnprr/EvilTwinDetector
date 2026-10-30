from __future__ import annotations

import pytest

from wiguard.config import WiGuardConfig


@pytest.fixture
def config() -> WiGuardConfig:
    return WiGuardConfig()
