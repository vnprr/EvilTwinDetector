from __future__ import annotations

import json

import pytest

from builders import FIXTURES, MANIFEST
from wiguard.cli import main
from wiguard.runtime import RuntimeStore


def run(capsys, *argv: str) -> tuple[int, str]:
    code = main([*argv])
    return code, capsys.readouterr().out


def test_enroll_then_analyze(tmp_path, capsys) -> None:
    profiles = str(tmp_path / "profiles.json")
    code, out = run(capsys, "enroll", "--pcap", str(FIXTURES / "enroll_home.pcap"),
                    "--output", profiles)  # fmt: skip
    assert code == 0 and "Enrolled 1 trusted profile" in out

    code, out = run(capsys, "analyze", str(FIXTURES / "classic_evil_twin.pcap"),
                    "--profiles", profiles)  # fmt: skip
    assert code == 0
    assert "[EVIL TWIN 0.865]" in out


def test_analyze_json(capsys) -> None:
    code, out = run(capsys, "analyze", str(FIXTURES / "deauth_storm_only.pcap"), "--json")
    payload = json.loads(out)
    assert code == 0
    assert payload["alerts"][0]["classification"] == "suspicious"


def test_replay_writes_a_replay_database(tmp_path, capsys) -> None:
    db = tmp_path / "replay.db"
    code, out = run(capsys, "replay", str(FIXTURES / "enterprise_outlier.pcap"),
                    "--state-path", str(db))  # fmt: skip
    assert code == 0 and "1 open alert" in out
    with RuntimeStore.open_readonly(db) as store:
        assert store.status()["mode"] == "replay"


def test_fixtures_evaluate(capsys) -> None:
    code, out = run(capsys, "fixtures", "evaluate", str(MANIFEST))
    assert code == 0
    assert "10/10 scenarios passed" in out


def test_configuration_errors_exit_with_status_2(tmp_path, capsys) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("capture:\n  dwell: 1\n")
    with pytest.raises(SystemExit) as exit_info:
        main(["--config", str(bad), "analyze", "x.pcap"])
    assert exit_info.value.code == 2
    assert "capture.dwell" in capsys.readouterr().err
