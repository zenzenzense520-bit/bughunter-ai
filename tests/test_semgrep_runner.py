"""Semgrep runner tests with a fake Docker client (no Docker required)."""

import pytest

from bughunter.core.errors import ScannerError, ToolUnavailableError
from bughunter.infra.docker import ContainerResult
from bughunter.scanners.semgrep_runner import RULES_CONTAINER, SRC_CONTAINER, SemgrepRunner


class FakeDocker:
    def __init__(self, result: ContainerResult, image_present: bool = True):
        self._result = result
        self.image_present = image_present
        self.calls: list[dict] = []

    def server_version(self) -> str:
        return "99.0-test"

    def image_exists(self, image: str) -> bool:
        return self.image_present

    def run_container(self, image, command, mounts, network, mem_limit_mb, timeout_sec):
        self.calls.append(
            {
                "image": image,
                "command": command,
                "mounts": list(mounts),
                "network": network,
                "mem": mem_limit_mb,
            }
        )
        return self._result


def _runner(tmp_path, docker, rules_dir):
    code_dir = tmp_path / "code"
    code_dir.mkdir()
    return SemgrepRunner(
        docker=docker,
        image="semgrep/semgrep:test",
        rules_dir=rules_dir,
        mem_limit_mb=512,
        timeout_sec=60,
    ), code_dir


def test_run_uses_offline_readonly_container(tmp_path, conftest_sample, semgrep_rules_dir):
    docker = FakeDocker(ContainerResult(0, conftest_sample, ""))
    runner, code_dir = _runner(tmp_path, docker, semgrep_rules_dir)

    result = runner.run(code_dir)

    assert result.stats.results_count == 2
    call = docker.calls[0]
    # Red line: container has no network.
    assert call["network"] == "none"
    # Both mounts are read-only and point at the expected container paths.
    mount_args = [m.to_arg() for m in call["mounts"]]
    assert all(m.endswith(":ro") for m in mount_args)
    assert any(m.endswith(f":{SRC_CONTAINER}:ro") for m in mount_args)
    assert any(m.endswith(f":{RULES_CONTAINER}:ro") for m in mount_args)
    # Command: JSON output, telemetry off, bundled rules only, no registry auto.
    command = call["command"]
    assert "--json" in command
    assert "--metrics=off" in command
    assert "--config" in command
    assert RULES_CONTAINER in command
    assert "auto" not in command
    assert command[-1] == SRC_CONTAINER
    assert call["mem"] == 512


def test_missing_image_raises(tmp_path, conftest_sample, semgrep_rules_dir):
    docker = FakeDocker(ContainerResult(0, conftest_sample, ""), image_present=False)
    runner, code_dir = _runner(tmp_path, docker, semgrep_rules_dir)
    with pytest.raises(ToolUnavailableError):
        runner.run(code_dir)


def test_nonzero_exit_without_json_raises(tmp_path, semgrep_rules_dir):
    docker = FakeDocker(
        ContainerResult(2, "", "semgrep: fatal: invalid configuration")
    )
    runner, code_dir = _runner(tmp_path, docker, semgrep_rules_dir)
    with pytest.raises(ScannerError):
        runner.run(code_dir)


def test_parse_skip_exit_code_still_parsed(tmp_path, conftest_sample, semgrep_rules_dir):
    # exit 4 (files skipped) still carries a usable JSON report.
    docker = FakeDocker(ContainerResult(4, conftest_sample, ""))
    runner, code_dir = _runner(tmp_path, docker, semgrep_rules_dir)
    result = runner.run(code_dir)
    assert result.stats.results_count == 2


def test_missing_code_dir_raises(tmp_path, conftest_sample, semgrep_rules_dir):
    docker = FakeDocker(ContainerResult(0, conftest_sample, ""))
    runner = SemgrepRunner(
        docker=docker, image="semgrep/semgrep:test", rules_dir=semgrep_rules_dir
    )
    with pytest.raises(ToolUnavailableError):
        runner.run(tmp_path / "does-not-exist")
