from __future__ import annotations

import json

import pytest

from builders import FIXTURES, MANIFEST
from wiguard.cli import main
from wiguard.runtime import StateReader


def run(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str]:
    with pytest.raises(SystemExit) as exit_info:
        main(argv)
    output = capsys.readouterr()
    return int(exit_info.value.code or 0), output.out + output.err


def test_enroll_then_analyze(tmp_path, capsys) -> None:
    profiles = str(tmp_path / "profiles.json")
    code, out = run(capsys, "enroll", "--pcap", str(FIXTURES / "enroll_home.pcap"),
                    "--output", profiles)  # fmt: skip
    assert code == 0 and "Enrolled 1 trusted profile" in out

    code, out = run(capsys, "analyze", str(FIXTURES / "classic_evil_twin.pcap"),
                    "--profiles", profiles)  # fmt: skip
    assert code == 0
    assert "EVIL TWIN  0.865" in out


def test_analyze_json(capsys) -> None:
    code, out = run(capsys, "analyze", str(FIXTURES / "deauth_storm_only.pcap"), "--json")
    assert code == 0
    assert json.loads(out)["alerts"][0]["classification"] == "suspicious"


def test_replay_writes_a_replay_database(tmp_path, capsys) -> None:
    db = tmp_path / "replay.db"
    code, out = run(capsys, "replay", str(FIXTURES / "enterprise_outlier.pcap"),
                    "--state-path", str(db))  # fmt: skip
    assert code == 0 and "1 open alert" in out
    with StateReader.open(db) as store:
        assert store.status()["mode"] == "replay"  # type: ignore[index]


def test_fixtures_evaluate(capsys) -> None:
    code, out = run(capsys, "fixtures", "evaluate", str(MANIFEST))
    assert code == 0
    assert "10/10 scenarios passed" in out


def test_enroll_needs_exactly_one_source(capsys) -> None:
    code, out = run(capsys, "enroll")
    assert code == 2 and "--pcap / --duration" in out


def test_configuration_errors_exit_with_status_2(tmp_path, capsys) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("capture:\n  dwell: 1\n")
    code, out = run(capsys, "--config", str(bad), "fixtures", "evaluate", str(MANIFEST))
    assert code == 2
    assert "capture.dwell" in out
