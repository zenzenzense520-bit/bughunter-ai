"""CLI coverage for deterministic triage and human review queue."""

from typer.testing import CliRunner

from bughunter.app.cli import app
from bughunter.core.models import Finding, Scan, Target, Task
from sqlmodel import Session

runner = CliRunner()


def _create_finding(engine):
    with Session(engine) as session:
        target = Target(name="triage-cli")
        session.add(target)
        session.flush()
        assert target.id is not None
        task = Task(target_id=target.id)
        session.add(task)
        session.flush()
        assert task.id is not None
        scan = Scan(task_id=task.id, target_id=target.id)
        session.add(scan)
        session.flush()
        assert scan.id is not None
        finding = Finding(
            target_id=target.id,
            scan_id=scan.id,
            dedup_key="cli-triage",
            title="Potential XSS",
            severity="high",
            rule_id="bughunter.javascript.inner-html-assignment",
            file_path="src/app.js",
            line=9,
            message="Dynamic HTML assignment",
            cwe_id="CWE-79",
        )
        session.add(finding)
        session.commit()
        assert finding.id is not None
        return finding.id


def test_cli_triage_and_review_show(engine):
    finding_id = _create_finding(engine)

    triage = runner.invoke(app, ["finding", "triage", "--finding", str(finding_id)])
    assert triage.exit_code == 0, triage.output
    assert "rules" in triage.output
    assert "confidence=" in triage.output

    queue = runner.invoke(app, ["review", "queue"])
    assert queue.exit_code == 0, queue.output
    assert "待复核: 1" in queue.output
    assert str(finding_id) in queue.output

    show = runner.invoke(app, ["review", "show", "--finding", str(finding_id)])
    assert show.exit_code == 0, show.output
    assert "人工验证清单" in show.output
    assert "授权的本地测试环境" in show.output
