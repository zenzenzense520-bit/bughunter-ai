"""Append-only audit logger with a sha256 hash chain (tamper-evident)."""

import hashlib
import json

from sqlmodel import Session, select

from ..core.models import AuditLog, utcnow


def _canonical(detail: dict) -> str:
    return json.dumps(detail, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _digest(prev_hash: str, actor: str, action: str, target_id: int | None,
            ts_iso: str, detail_json: str) -> str:
    payload = "|".join([prev_hash, actor, action, str(target_id or ""), ts_iso, detail_json])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditLogger:
    def __init__(self, session: Session, actor: str = "local"):
        self.session = session
        self.actor = actor

    def record(
        self,
        action: str,
        target_id: int | None = None,
        detail: dict | None = None,
    ) -> AuditLog:
        """Append an audit entry. Caller owns the transaction (commit)."""
        ts = utcnow()
        last = self.session.exec(select(AuditLog).order_by(AuditLog.id.desc())).first()
        prev_hash = last.hash if last else ""
        detail_json = _canonical(detail or {})
        digest = _digest(
            prev_hash, self.actor, action, target_id, ts.isoformat(), detail_json
        )
        entry = AuditLog(
            ts=ts,
            actor=self.actor,
            action=action,
            target_id=target_id,
            detail_json=detail_json,
            hash_prev=prev_hash,
            hash=digest,
        )
        self.session.add(entry)
        self.session.flush()
        return entry


def verify_chain(session: Session) -> list[int]:
    """Verify the hash chain; return ids of broken entries (empty = intact)."""
    broken: list[int] = []
    prev_hash = ""
    for entry in session.exec(select(AuditLog).order_by(AuditLog.id)).all():
        expected = _digest(
            prev_hash,
            entry.actor,
            entry.action,
            entry.target_id,
            entry.ts.isoformat(),
            entry.detail_json,
        )
        if entry.hash_prev != prev_hash or entry.hash != expected:
            broken.append(entry.id if entry.id is not None else -1)
        prev_hash = entry.hash
    return broken
