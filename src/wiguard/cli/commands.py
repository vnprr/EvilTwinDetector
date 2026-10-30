"""The ``wiguard`` command. Every subcommand reads ``config.yaml`` (or ``--config``);
its options override the file."""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.logging import RichHandler

from wiguard.analysis import analyze_pcap
from wiguard.capture import AdapterError, ChannelHoppingCapture
from wiguard.config import ConfigError, WiGuardConfig, load_config
from wiguard.detection import ProfileError, TrustedProfile, TrustedProfileStore, enroll
from wiguard.pipeline import DetectionPipeline, PipelineResult
from wiguard.runtime import RecordSummary, Sensor, StateWriter, StoreError, replay_pcap

from . import report

app = typer.Typer(
    help="WiGuard: a passive, explainable Evil Twin detector for Wi-Fi.",
    no_args_is_help=True,
    add_completion=False,
)
fixtures = typer.Typer(help="Synthetic test scenarios.", no_args_is_help=True)
app.add_typer(fixtures, name="fixtures")

stderr = Console(stderr=True)

# --- options shared by several commands ----------------------------------------------

Iface = Annotated[
    str | None, typer.Option(help="Monitor-mode capture interface.", rich_help_panel="Capture")
]
Channels = Annotated[
    str | None,
    typer.Option(help="Comma-separated channels, e.g. 1,6,11.", rich_help_panel="Capture"),
]
Dwell = Annotated[
    float | None, typer.Option(help="Seconds per channel.", rich_help_panel="Capture")
]
SavePcap = Annotated[
    Path | None,
    typer.Option(
        "--save-pcap",
        dir_okay=False,
        help="Also write every captured packet to this pcap (to replay the run later).",
        rich_help_panel="Capture",
    ),
]
Profiles = Annotated[Path | None, typer.Option("--profiles", help="Trusted profiles file.")]
StatePath = Annotated[Path | None, typer.Option(help="SQLite state database.")]
Json = Annotated[bool, typer.Option("--json", help="Machine-readable JSON output.")]
Pcap = Annotated[Path, typer.Argument(exists=True, dir_okay=False, help="Capture file.")]


def _settings(ctx: typer.Context, **overrides: Any) -> WiGuardConfig:
    """The loaded configuration with this command's options applied.

    Option names map to config keys; ``None`` (option not given) keeps the file's value.
    """
    keys = {
        "iface": "capture.interface",
        "channels": "capture.channels",
        "dwell": "capture.dwell_seconds",
        "profiles": "detection.identity.trusted_profiles_path",
        "state_path": "runtime.state_path",
        "host": "api.host",
        "port": "api.port",
    }
    if overrides.get("channels"):
        overrides["channels"] = [int(c) for c in str(overrides["channels"]).split(",") if c.strip()]
    config: WiGuardConfig = ctx.obj
    return config.with_overrides({keys[name]: value for name, value in overrides.items()})


@app.callback()
def _global_options(
    ctx: typer.Context,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config", "-c", help="Configuration file (default: ./config.yaml if present)."
        ),
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Show debug logging.")] = False,
) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=stderr, show_path=False)],
        force=True,
    )
    ctx.obj = load_config(config)


# --- live capture ------------------------------------------------------------------------


@app.command()
def scan(
    ctx: typer.Context,
    duration: Annotated[float, typer.Option(help="Seconds to capture.")] = 30.0,
    iface: Iface = None,
    channels: Channels = None,
    dwell: Dwell = None,
    save_pcap: SavePcap = None,
    profiles: Profiles = None,
    as_json: Json = False,
) -> None:
    """Short live scan; prints the APs and alerts. Needs root."""
    config = _settings(ctx, iface=iface, channels=channels, dwell=dwell, profiles=profiles)
    pipeline = DetectionPipeline.from_config(config)
    capture = ChannelHoppingCapture(config.capture)
    with stderr.status(f"Scanning {len(config.capture.channels)} channels for {duration:g} s ..."):
        capture.run(pipeline.process, duration_seconds=duration, save_to=save_pcap)
    _output(pipeline.evaluate(), as_json, capture=capture.stats.to_dict())


@app.command()
def sensor(
    ctx: typer.Context,
    duration: Annotated[float | None, typer.Option(help="Stop after this many seconds.")] = None,
    iface: Iface = None,
    channels: Channels = None,
    dwell: Dwell = None,
    save_pcap: SavePcap = None,
    profiles: Profiles = None,
    state_path: StatePath = None,
    as_json: Json = False,
) -> None:
    """Long-running sensor that keeps the state database up to date. Needs root."""
    config = _settings(
        ctx, iface=iface, channels=channels, dwell=dwell, profiles=profiles, state_path=state_path
    )

    def json_line(summary: RecordSummary) -> None:
        print(json.dumps({"event": "flush", "at": time.time(), **summary.to_dict()}), flush=True)

    runner = Sensor(config, on_flush=json_line if as_json else None)
    logging.info("Sensor writing to %s (Ctrl+C to stop).", runner.state_path)
    final = runner.run(duration_seconds=duration, save_to=save_pcap)
    logging.info("Stopped: %d APs, %d open alert(s).", final.access_points, final.open_alerts)


@app.command("enroll")
def enroll_profiles(
    ctx: typer.Context,
    pcap: Annotated[
        Path | None, typer.Option(exists=True, dir_okay=False, help="Known-good capture.")
    ] = None,
    duration: Annotated[float | None, typer.Option(help="Capture live for N seconds.")] = None,
    ssid: Annotated[
        list[str] | None, typer.Option(help="Only enroll this SSID (repeatable).")
    ] = None,
    min_frames: Annotated[int | None, typer.Option(help="Frames an AP needs.")] = None,
    output: Annotated[
        Path | None, typer.Option(help="Profiles file (default: from config).")
    ] = None,
    iface: Iface = None,
    channels: Channels = None,
    dwell: Dwell = None,
    save_pcap: SavePcap = None,
) -> None:
    """Record trusted profiles of your own APs, from a pcap or a live capture.

    Do this only while the environment is known to be free of attackers.
    """
    if (pcap is None) == (duration is None):
        raise typer.BadParameter("give exactly one of them", param_hint="--pcap / --duration")
    config = _settings(ctx, iface=iface, channels=channels, dwell=dwell, profiles=output)
    if pcap is not None:
        result = analyze_pcap(pcap, config, trusted_profiles=[])
    else:
        pipeline = DetectionPipeline(config)  # no profiles: they are what we are creating
        with stderr.status(f"Capturing for {duration:g} s; keep the environment known-good ..."):
            ChannelHoppingCapture(config.capture).run(
                pipeline.process, duration_seconds=duration, save_to=save_pcap
            )
        result = pipeline.evaluate()

    identity = config.detection.identity
    profiles: list[TrustedProfile] = enroll(
        result.access_points, min_frames=min_frames or identity.enrollment_min_frames
    )
    if ssid:
        profiles = [profile for profile in profiles if profile.ssid in ssid]
    TrustedProfileStore(identity.trusted_profiles_path).save(profiles)
    report.print_enrolled(
        profiles, identity.trusted_profiles_path, len(result.access_points) - len(profiles)
    )


# --- saved captures ---------------------------------------------------------------------


@app.command()
def analyze(
    ctx: typer.Context, pcap: Pcap, profiles: Profiles = None, as_json: Json = False
) -> None:
    """Analyse a saved capture exactly as the live sensor would have."""
    _output(analyze_pcap(pcap, _settings(ctx, profiles=profiles)), as_json)


@app.command()
def replay(
    ctx: typer.Context,
    pcap: Pcap,
    profiles: Profiles = None,
    state_path: StatePath = None,
    step: Annotated[
        float | None,
        typer.Option(help="Seconds of capture time between updates (default: flush interval)."),
    ] = None,
) -> None:
    """Analyse a capture into a state database, on the sensor's update schedule."""
    config = _settings(ctx, profiles=profiles, state_path=state_path)
    with StateWriter.open(config.runtime.state_path) as store:
        summary = replay_pcap(pcap, config, store, step_seconds=step)
    report.console.print(
        f"Replayed {pcap} into {config.runtime.state_path}: "
        f"{summary.access_points} APs, {summary.open_alerts} open alert(s)."
    )


@app.command()
def api(
    ctx: typer.Context,
    host: Annotated[str | None, typer.Option(help="Bind address.")] = None,
    port: Annotated[int | None, typer.Option(help="Port.")] = None,
    profiles: Profiles = None,
    state_path: StatePath = None,
    print_openapi: Annotated[
        bool, typer.Option("--print-openapi", help="Print the OpenAPI document and exit.")
    ] = False,
) -> None:
    """Serve the read-only HTTP API for the dashboard (docs at /docs)."""
    import uvicorn

    from wiguard.api import create_app

    config = _settings(ctx, host=host, port=port, profiles=profiles, state_path=state_path)
    application = create_app(config)
    if print_openapi:
        print(json.dumps(application.openapi(), indent=2))
        return
    uvicorn.run(application, host=config.api.host, port=config.api.port)


@fixtures.command("generate")
def fixtures_generate(directory: Annotated[Path, typer.Argument(file_okay=False)]) -> None:
    """Write the scenario pcaps and their manifest."""
    from wiguard.evaluation import write_synthetic_fixtures

    report.console.print(f"Wrote {write_synthetic_fixtures(directory)}")


@fixtures.command("evaluate")
def fixtures_evaluate(
    ctx: typer.Context,
    manifest: Annotated[Path, typer.Argument(exists=True, dir_okay=False)],
    as_json: Json = False,
) -> None:
    """Run every scenario and compare the verdict with the expected one."""
    from wiguard.evaluation import evaluate_manifest

    result = evaluate_manifest(manifest, ctx.obj)
    if as_json:
        print(json.dumps(result, indent=2))
    else:
        report.print_evaluation(result)
    if not result["success"]:
        raise typer.Exit(1)


# --- helpers ----------------------------------------------------------------------------


def _output(result: PipelineResult, as_json: bool, **extra: Any) -> None:
    if as_json:
        print(json.dumps({**result.to_dict(), **extra}, indent=2))
    else:
        report.print_result(result)


def main(argv: Sequence[str] | None = None) -> None:
    """Entry point: run the app and turn expected failures into one-line errors."""
    try:
        app(args=None if argv is None else list(argv), prog_name="wiguard")
    except ConfigError as error:
        stderr.print(f"[red]wiguard: configuration error:[/] {error}")
        raise SystemExit(2) from None
    except (AdapterError, ProfileError, StoreError, OSError) as error:
        stderr.print(f"[red]wiguard:[/] {error}")
        raise SystemExit(1) from None
