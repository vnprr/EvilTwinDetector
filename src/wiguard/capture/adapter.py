"""Safe monitor-mode management of the external capture adapter.

Tested with an Alfa RTL8812AU on the in-kernel ``rtw88_8812au`` driver: the
interface is switched directly to monitor mode (a separate monitor interface
cannot tune channels with this driver). The host's internal Wi-Fi is never
touched, and nothing that kills network managers (``airmon-ng check kill``)
is ever run.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


class AdapterError(RuntimeError):
    """The capture adapter cannot be prepared safely."""


class MonitorAdapter:
    def __init__(self, interface: str, internal_interface: str) -> None:
        self.interface = interface
        self.internal_interface = internal_interface

    def preflight(self, *, require_internal_connected: bool = True) -> None:
        for command in ("iw", "ip"):
            if shutil.which(command) is None:
                raise AdapterError(f"required command {command!r} is missing")
        for interface in (self.interface, self.internal_interface):
            if not _interface_exists(interface):
                raise AdapterError(f"network interface {interface!r} does not exist")
        if self.interface == self.internal_interface:
            raise AdapterError("capture and internal interface must be different")
        if os.geteuid() != 0:
            raise AdapterError("monitor-mode capture must run as root")
        if require_internal_connected and not self.internal_connected():
            raise AdapterError(f"internal Wi-Fi {self.internal_interface} is not connected")

    def enter_monitor(self) -> None:
        _run("ip", "link", "set", self.interface, "down", check=False)
        _run("iw", "dev", self.interface, "set", "type", "monitor")
        _run("ip", "link", "set", self.interface, "up")

    def restore_managed(self) -> None:
        if not _interface_exists(self.interface):
            return
        _run("ip", "link", "set", self.interface, "down", check=False)
        _run("iw", "dev", self.interface, "set", "type", "managed", check=False)
        _run("ip", "link", "set", self.interface, "up", check=False)

    def set_channel(self, channel: int) -> str | None:
        """Tune to ``channel``; return the driver's error message on failure."""
        result = _run("iw", "dev", self.interface, "set", "channel", str(channel), check=False)
        return None if result.returncode == 0 else result.stderr.strip() or "unknown error"

    def internal_connected(self) -> bool:
        if shutil.which("nmcli") is None:
            return True  # cannot tell without NetworkManager; do not block the run
        result = _run("nmcli", "-t", "-f", "DEVICE,STATE", "device", "status", check=False)
        for line in result.stdout.splitlines():
            device, _, state = line.partition(":")
            if device == self.internal_interface:
                return state == "connected"
        return False


def _interface_exists(interface: str) -> bool:
    return (Path("/sys/class/net") / interface).exists()


def _run(*argv: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, text=True, capture_output=True, check=False)
    if check and result.returncode != 0:
        raise AdapterError(
            f"{' '.join(argv)} failed ({result.returncode}): {result.stderr.strip()}"
        )
    return result
