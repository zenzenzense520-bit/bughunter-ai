"""Audit hash-chain tests."""

import json

from sqlmodel import select

from bughunter.core.enums import AuditAction
from bughunter.core.models import AuditLog
from bughunter.infra.audit import AuditLogger, _digest, verify_chain


def test_chain_intact_after_multiple_records(factories, session):
    t = factories.target()
    audit = AuditLogger(session, actor="tester")
    audit.record(AuditAction.TARGET_CREATED.value, t.id, {"name": "lab"})
    audit.record(AuditAction.AUTHORIZATION_CONFIRMED.value, t.id, {"authz_id": 1})
    audit.record(AuditAction.SCOPE_ENTRY_ADDED.value, t.id, {"value": "127.0.0.1"})
    assert verify_chain(session) == []


def test_tampered_detail_detected_at_same_row(factories, session):
    """Changing only detail_json breaks that row's own hash."""
    t = factories.target()
    audit = AuditLogger(session, actor="tester")
    audit.record(AuditAction.TARGET_CREATED.value, t.id, {"name": "lab"})
    audit.record(AuditAction.AUTHORIZATION_CONFIRMED.value, t.id, {"authz_id": 1})
    session.commit()

    first = session.exec(select(AuditLog).where(AuditLog.id == 1)).one()
    first.detail_json = json.dumps({"name": "tampered"}, sort_keys=True)
    session.add(first)
    session.commit()

    assert verify_chain(session) == [1]


def test_rehashed_tamper_breaks_next_row_link(factories, session):
    """An attacker who recomputes row 1's hash is caught at row 2 (prev mismatch)."""
    t = factories.target()
    audit = AuditLogger(session, actor="tester")
    audit.record(AuditAction.TARGET_CREATED.value, t.id, {"name": "lab"})
    audit.record(AuditAction.AUTHORIZATION_CONFIRMED.value, t.id, {"authz_id": 1})
    session.commit()

    first = session.exec(select(AuditLog).where(AuditLog.id == 1)).one()
    fake_detail = json.dumps({"name": "tampered"}, sort_keys=True)
    first.detail_json = fake_detail
    # Attacker tries to hide the tamper by recomputing row 1's hash.
    first.hash = _digest(
        first.hash_prev, first.actor, first.action, first.target_id,
        first.ts.isoformat(), fake_detail,
    )
    session.add(first)
    session.commit()

    broken = verify_chain(session)
    assert 2 in broken  # row 2 hash_prev no longer matches the forged row 1
