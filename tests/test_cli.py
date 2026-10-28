import io
import json
import sys

import pytest

from layerwise import cli
from layerwise.models import CheckResult, Status
from layerwise.registry import Context


@pytest.fixture
def fake_run(monkeypatch):
    outcome = {"status": Status.OK, "summary": "resolved"}

    def run(target, timeout, tls, http):
        results = [CheckResult("DNS", outcome["status"], outcome["summary"], hint="A hint.")]
        return results, Context(target=target, timeout=timeout, tls=False, http=False)

    monkeypatch.setattr(cli, "run_target", run)
    return outcome


@pytest.mark.parametrize(("status", "code"), [(Status.OK, 0), (Status.WARN, 1), (Status.FAIL, 2)])
def test_exit_codes(fake_run, status, code, capsys):
    fake_run["status"] = status
    assert cli.main(["example.com"]) == code


def test_json_output(fake_run, capsys):
    cli.main(["example.com:22", "--json"])
    data = json.loads(capsys.readouterr().out)
    assert data[0]["target"] == "example.com:22"
    assert data[0]["checks"][0]["status"] == "ok"


def test_json_has_tried_and_skipped(monkeypatch, capsys):
    def run(target, timeout, tls, http):
        ctx = Context(target=target, timeout=timeout, tls=True, http=True)
        ctx.tried = ["192.0.2.10", "2001:db8::10"]
        ctx.skipped = [("tls", "tcp"), ("http", "tcp")]
        return [CheckResult("TCP IPv4", Status.FAIL, "no answer")], ctx

    monkeypatch.setattr(cli, "run_target", run)
    cli.main(["example.com", "--json"])
    data = json.loads(capsys.readouterr().out)[0]
    assert data["tried"] == ["192.0.2.10", "2001:db8::10"]
    assert data["skipped"] == [{"check": "tls", "cause": "tcp"}, {"check": "http", "cause": "tcp"}]


def test_hint_is_printed_on_failure(fake_run, capsys):
    fake_run["status"] = Status.FAIL
    cli.main(["example.com", "--no-color"])
    out = capsys.readouterr().out
    assert "[FAIL]" in out
    assert "hint: A hint." in out


@pytest.mark.parametrize("extra", [[], ["--json"]], ids=["text", "json"])
def test_cli_survives_cp1252_stdout(fake_run, monkeypatch, extra):
    # Like `layerwise ... > out.txt` on a Western-European Windows: strict cp1252, and a
    # summary with a character cp1252 does not have (U+4E2D).
    fake_run["summary"] = "issued by 中 CA"
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp1252")
    monkeypatch.setattr(sys, "stdout", stream)
    cli.main(["example.com", "--no-color", *extra])
    stream.flush()
    assert b"\\u4e2d" in raw.getvalue()


def test_report_output(fake_run, capsys):
    fake_run["status"] = Status.FAIL
    assert cli.main(["example.com:22", "--report"]) == 2
    out = capsys.readouterr().out
    assert out.startswith("VERDICT: FAIL at DNS -> suggested team: DNS")
    assert "Target:  example.com:22" in out


def test_report_and_json_are_exclusive(fake_run, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["example.com", "--report", "--json"])
    assert exc.value.code == 2


def test_invalid_target_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["example.com:99999"])
    assert exc.value.code == 2
