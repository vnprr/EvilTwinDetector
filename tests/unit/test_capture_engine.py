from __future__ import annotations

import unittest

from wiguard.capture import CaptureConfig, WiGuardCaptureEngine
from wiguard.state import APStateManager


class CaptureEngineTest(unittest.TestCase):
    def test_uses_injected_empty_state_manager(self) -> None:
        manager = APStateManager()
        engine = WiGuardCaptureEngine(CaptureConfig(), state_manager=manager)

        self.assertIs(engine.state_manager, manager)


if __name__ == "__main__":
    unittest.main()
