"""End-to-end CLI tests for the M1 happy path and red-line rejections."""

import pytest
from typer.testing import CliRunner

from bughunter.app import container
from bughunter.app.cli import app, main

runner = CliRunner()
VF = "2026-10-24T00:00:00"
VT = "2026-10-31T00:00:00"


def run(*args: str, input: str | None = None):
    return runner.invoke(app, list(args), input=input)


def test_full_happy_path(engine, monkeypatch):
    r = run("target", "add", "-n", "juice-lab")
    assert r.exit_code == 0, r.output

    r = run("authz", "add", "-t", "1", "--source", "local-lab",
            "--scope-ref", "n/a", "--grantor", "self",
            "--valid-from", VF, "--valid-to", VT)
    assert r.exit_code == 0, r.output

    r = run("scope", "add-include", "-t", "1", "--rule-type", "host", "--value", "127.0.0.1")
    assert r.exit_code == 0, r.output

    r = run("authz", "confirm", "-t", "1", input="y\n")
    assert r.exit_code == 0, r.output
    assert "active" in r.output

    r = run("target", "show", "-t", "1")
    assert r.exit_code == 0
    assert "ready for scan" in r.output

    r = run("audit", "verify")
    assert r.exit_code == 0
    assert "完整" in r.output


def test_confirm_aborted_leaves_target_draft(engine):
    run("target", "add", "-n", "lab2")
    run("authz", "add", "-t", "1", "--source", "lab", "--scope-ref", "n/a",
        "--grantor", "self", "--valid-from", VF, "--valid-to", VT)
    r = run("authz", "confirm", "-t", "1", input="n\n")
    assert r.exit_code == 1
    r = run("target", "show", "-t", "1")
    assert "BLOCKED" in r.output or "尚无已确认授权" in r.output


def test_ip_suffix_scope_rejected(engine):
    run("target", "add", "-n", "lab3")
    r = run("scope", "add-include", "-t", "1", "--rule-type", "host_suffix",
            "--value", "127.0.0.1")
    assert r.exit_code == 1


def test_invalid_exclude_regex_rejected(engine):
    run("target", "add", "-n", "lab4")
    r = run("scope", "add-exclude", "-t", "1", "--value", "[")
    assert r.exit_code == 1


def test_scope_on_unknown_target_rejected(engine):
    r = run("scope", "add-include", "-t", "42", "--rule-type", "host", "--value", "127.0.0.1")
    assert r.exit_code == 1


def test_authz_invalid_time_range_rejected(engine):
    run("target", "add", "-n", "lab5")
    r = run("authz", "add", "-t", "1", "--source", "lab", "--scope-ref", "n/a",
            "--grantor", "self", "--valid-from", VT, "--valid-to", VF)
    assert r.exit_code == 1


def test_main_wrapper_blocks_with_exit_code(engine, monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        ["bughunter", "scope", "add-include", "-t", "99",
         "--rule-type", "host", "--value", "127.0.0.1"],
    )
    container.reset_cache()
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1
