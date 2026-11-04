"""CLI tests for scan commands: happy path (mocked Docker) and red-line refusals."""

from datetime import timedelta

import pytest
from typer.testing import CliRunner

from bughunter.app.cli import app
from bughunter.core.models import utcnow
from bughunter.infra.docker import ContainerResult, DockerClient

runner = CliRunner()
# Dynamic window so the suite stays valid regardless of the run date.
_ANCHOR = utcnow()
VF = (_ANCHOR - timedelta(days=1)).replace(microsecond=0).isoformat()
VT = (_ANCHOR + timedelta(days=7)).replace(microsecond=0).isoformat()


def run(*args: str, input: str | None = None):
    return runner.invoke(app, list(args), input=input)


def _activate_target():
    run("target", "add", "-n", "scan-lab")
    run("authz", "add", "-t", "1", "--source", "local-lab", "--scope-ref", "n/a",
        "--grantor", "self", "--valid-from", VF, "--valid-to", VT)
    run("scope", "add-include", "-t", "1", "--rule-type", "host", "--value", "127.0.0.1")
    run("authz", "confirm", "-t", "1", input="y\n")


def test_sast_blocked_without_authorization(engine, tmp_path):
    run("target", "add", "-n", "noauth")
    code = tmp_path / "code"
    code.mkdir()
    r = run("scan", "sast", "-t", "1", "-p", str(code))
    assert r.exit_code == 1
    assert "BLOCKED" in r.output


def test_active_scan_is_hard_refused(engine):
    r = run("scan", "active")
    assert r.exit_code == 1
    assert "BLOCKED" in r.output
    assert "主动扫描" in r.output


def test_sast_happy_path_with_mocked_docker(
    engine, monkeypatch, tmp_path, conftest_sample
):
    _activate_target()
    code = tmp_path / "code"
    code.mkdir()

    monkeypatch.setattr(DockerClient, "server_version", lambda self: "99.0")
    monkeypatch.setattr(DockerClient, "image_exists", lambda self, image: True)
    monkeypatch.setattr(
        DockerClient,
        "run_container",
        lambda self, **kw: ContainerResult(0, conftest_sample, ""),
    )

    r = run("scan", "sast", "-t", "1", "-p", str(code))
    assert r.exit_code == 0, r.output
    assert "新增 finding" in r.output
    assert "2" in r.output

    r = run("scan", "list", "-t", "1")
    assert r.exit_code == 0
    assert "completed" in r.output

    r = run("scan", "show", "-s", "1")
    assert r.exit_code == 0
    assert "eval-exec" in r.output
