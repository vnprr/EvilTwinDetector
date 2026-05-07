"""Safe monitor-mode adapter management."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path


class AdapterError(RuntimeError):
    """Raised when the capture adapter cannot be prepared safely."""


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


class AlfaMonitorAdapter:
    """Manage direct monitor mode on the external Alfa adapter.

    The tested RTL8812AU setup can capture reliably when the Alfa interface is
    switched directly to monitor mode. A simultaneous monitor interface cannot
    tune channels with the current `rtw88_8812au` driver, so this class avoids
    creating one.
    """

    def __init__(self, interface: str, internal_interface: str) -> None:
        self.interface = interface
        self.internal_interface = internal_interface
        self._entered = False

    def preflight(self, *, require_internal_connected: bool = True) -> None:
        self._require_command("iw")
        self._require_command("ip")
        self._require_interface(self.interface)
        self._require_interface(self.internal_interface)
        if os.geteuid() != 0:
            raise AdapterError("monitor-mode capture must run as root")
        if require_internal_connected and not self.internal_wifi_connected():
            raise AdapterError(f"internal Wi-Fi {self.internal_interface} is not connected")

    def enter_monitor(self) -> None:
        self._run(["ip", "link", "set", self.interface, "down"], check=False)
        self._run(["iw", "dev", self.interface, "set", "type", "monitor"])
        self._run(["ip", "link", "set", self.interface, "up"])
        self._entered = True

    def restore_managed(self) -> None:
        if not self._interface_exists(self.interface):
            return
        self._run(["ip", "link", "set", self.interface, "down"], check=False)
        self._run(["iw", "dev", self.interface, "set", "type", "managed"], check=False)
        self._run(["ip", "link", "set", self.interface, "up"], check=False)
        self._entered = False

    def set_channel(self, channel: int) -> CommandResult:
        return self._run(["iw", "dev", self.interface, "set", "channel", str(channel)], check=False)

    def internal_wifi_connected(self) -> bool:
        if not self._command_exists("nmcli"):
            return True
        result = self._run(
            ["nmcli", "-t", "-f", "DEVICE,STATE", "device", "status"],
            check=False,
        )
        for line in result.stdout.splitlines():
            parts = line.split(":", 1)
            if len(parts) == 2 and parts[0] == self.internal_interface:
                return parts[1] == "connected"
        return False

    def _require_interface(self, interface: str) -> None:
        if not self._interface_exists(interface):
            raise AdapterError(f"network interface {interface!r} does not exist")

    def _require_command(self, command: str) -> None:
        if not self._command_exists(command):
            raise AdapterError(f"required command {command!r} is missing")

    @staticmethod
    def _interface_exists(interface: str) -> bool:
        return (Path("/sys/class/net") / interface).exists()

    @staticmethod
    def _command_exists(command: str) -> bool:
        path = os.environ.get("PATH", "")
        return any((Path(part) / command).exists() for part in path.split(os.pathsep))

    @staticmethod
    def _run(argv: list[str], *, check: bool = True) -> CommandResult:
        completed = subprocess.run(argv, text=True, capture_output=True, check=False)
        result = CommandResult(
            argv=tuple(argv),
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
        if check and result.returncode != 0:
            raise AdapterError(
                f"command failed ({result.returncode}): {' '.join(argv)}\n{result.stderr.strip()}"
            )
        return result
