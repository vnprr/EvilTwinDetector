"""Terminal output of the CLI, rendered with Rich."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.padding import Padding
from rich.table import Table
from rich.text import Text

from wiguard.correlation import CorrelatedAlert
from wiguard.detection import TrustedProfile
from wiguard.evaluation.fixtures import VERDICTS
from wiguard.pipeline import PipelineResult

console = Console()

VERDICT_STYLE = {
    "evil_twin": "bold white on red",
    "suspicious": "bold black on yellow",
    "info": "bold blue",
    "clean": "green",
}


def verdict(name: str) -> Text:
    return Text(f" {name.replace('_', ' ').upper()} ", style=VERDICT_STYLE.get(name, ""))


def print_result(result: PipelineResult) -> None:
    frames = result.frames
    console.print(
        f"{frames.packets} packets · {frames.beacons} beacons · "
        f"{frames.disruption} deauth/disassoc · {len(result.access_points)} APs · "
        f"{result.trusted_profiles} trusted profile(s)"
    )
    status = {alert.bssid: alert.classification.value for alert in result.alerts}
    table = Table(title="Access points", title_justify="left", header_style="bold")
    for column in ("", "SSID", "BSSID", "CH"):
        table.add_column(column)
    for column in ("RSSI", "Skew ppm", "Frames"):
        table.add_column(column, justify="right")
    for ap in result.access_points:
        table.add_row(
            verdict(status.get(ap.bssid, "clean")),
            ap.ssid or "<hidden>",
            ap.bssid,
            ",".join(map(str, ap.channels)) or "?",
            "?" if ap.avg_rssi_dbm is None else f"{ap.avg_rssi_dbm:.0f}",
            "-" if ap.clock_skew_ppm is None else f"{ap.clock_skew_ppm:+.1f}",
            str(ap.frames),
        )
    console.print(table)
    print_alerts(result.alerts)
    for note in result.notes:
        console.print(f"[yellow]Note:[/] {note}")


def print_alerts(alerts: Sequence[CorrelatedAlert]) -> None:
    if not alerts:
        console.print("[green]No alerts.[/]")
        return
    for alert in sorted(alerts, key=lambda a: (-a.classification.rank, -a.score)):
        console.print(
            Text.assemble(
                verdict(alert.classification.value),
                f" {alert.score:.3f}  ",
                (alert.ssid or "<hidden>", "bold"),
                f"  {alert.bssid}",
            )
        )
        console.print(Padding(alert.explanation, (0, 0, 1, 2)))


def print_enrolled(profiles: Sequence[TrustedProfile], path: Path, skipped: int) -> None:
    table = Table(title="Trusted profiles", title_justify="left", header_style="bold")
    for column in ("SSID", "BSSID", "Frames", "Skew ppm"):
        table.add_column(column)
    for profile in profiles:
        skew = "-" if profile.clock_skew_ppm is None else f"{profile.clock_skew_ppm:+.1f}"
        table.add_row(profile.ssid or "<hidden>", profile.bssid, str(profile.frames), skew)
    console.print(table)
    console.print(f"Enrolled {len(profiles)} trusted profile(s) into {path}.")
    if skipped:
        console.print(f"[yellow]Skipped {skipped} AP(s)[/] (too few frames or not in --ssid).")


def print_evaluation(report: dict[str, Any]) -> None:
    table = Table(title="Scenarios", title_justify="left", header_style="bold")
    for column in ("", "Scenario", "Expected", "Observed", "Score"):
        table.add_column(column)
    for result in report["results"]:
        table.add_row(
            "[green]PASS[/]" if result["passed"] else "[red]FAIL[/]",
            result["name"],
            result["expected"],
            result["observed"],
            f"{result['score']:.3f}",
        )
    console.print(table)

    matrix = Table(title="Confusion matrix (rows: expected)", title_justify="left")
    matrix.add_column("")
    for label in VERDICTS:
        matrix.add_column(label, justify="right")
    rows = report["confusion_matrix"]["rows_expected_columns_observed"]
    for label, row in zip(VERDICTS, rows, strict=True):
        matrix.add_row(label, *(str(count) for count in row))
    console.print(matrix)
    style = "green" if report["success"] else "red"
    console.print(f"[{style}]{report['passed']}/{report['scenarios']} scenarios passed.[/]")
