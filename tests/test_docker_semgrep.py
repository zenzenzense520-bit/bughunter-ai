"""Real Docker integration test for Semgrep.

Skipped by default. Run with:
    uv run pytest tests/test_docker_semgrep.py --run-docker

Requires Docker and the semgrep/semgrep image (pulled automatically if missing).
"""

import pytest

from bughunter.infra.docker import DockerClient
from bughunter.scanners.semgrep_runner import SemgrepRunner

from conftest import SEMGREP_RULES, VULN_APP

IMAGE = "semgrep/semgrep:latest"

EXPECTED_RULES = {
    "bughunter.python.eval-exec",
    "bughunter.python.subprocess-shell-true",
    "bughunter.python.sql-string-concat",
    "bughunter.python.pickle-deserialization",
    "bughunter.python.yaml-unsafe-load",
    "bughunter.python.tls-verify-disabled",
    "bughunter.python.hardcoded-secret",
    "bughunter.python.weak-hash-md5-sha1",
    "bughunter.javascript.inner-html-assignment",
    "bughunter.javascript.document-write",
    "bughunter.javascript.eval-call",
    "bughunter.javascript.react-dangerously-set-inner-html",
}


@pytest.mark.docker
def test_semgrep_detects_every_bundled_rule():
    docker = DockerClient()
    try:
        docker.server_version()
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"Docker daemon unavailable: {exc}")

    if not docker.image_exists(IMAGE):
        try:
            docker.pull(IMAGE)
        except Exception as exc:  # pragma: no cover - network dependent
            pytest.skip(f"image missing and pull failed: {exc}")

    runner = SemgrepRunner(
        docker=docker,
        image=IMAGE,
        rules_dir=SEMGREP_RULES,
        mem_limit_mb=2048,
        timeout_sec=300,
    )
    result = runner.run(VULN_APP)

    hit_rules = {f.rule_id for f in result.findings}
    missing = EXPECTED_RULES - hit_rules
    assert not missing, f"bundled rules never triggered: {sorted(missing)}"
    assert result.stats.results_count >= len(EXPECTED_RULES)
