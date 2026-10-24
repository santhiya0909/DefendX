import hashlib
import json
import uuid
from datetime import datetime
from typing import Optional, Dict, Any, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from app.models.models import AuditEvent

GENESIS_HASH = "0" * 64

def compute_event_hash(
    prev_hash: str,
    event_id: str,
    actor_id: str,
    actor_role: str,
    action: str,
    resource_type: str,
    resource_id: str,
    team_context: str,
    timestamp_iso: str,
    outcome: str,
    correlation_id: str,
    details: Dict[str, Any]
) -> str:
    """Computes SHA-256 hash of an audit event using canonical JSON representation."""
    canonical_payload = {
        "prev_hash": prev_hash,
        "event_id": event_id,
        "actor_id": actor_id,
        "actor_role": actor_role,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "team_context": team_context,
        "timestamp": timestamp_iso,
        "outcome": outcome,
        "correlation_id": correlation_id,
        "details": details
    }
    serialized = json.dumps(canonical_payload, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

async def record_audit_event(
    db: AsyncSession,
    actor_id: str,
    actor_role: str,
    action: str,
    resource_type: str,
    resource_id: str,
    team_context: str,
    outcome: str,
    correlation_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None
) -> AuditEvent:
    """Appends an immutable, SHA-256 hash-linked audit record to the database."""
    if not correlation_id:
        correlation_id = str(uuid.uuid4())
    if details is None:
        details = {}

    # Fetch the latest audit event to get previous hash
    stmt = select(AuditEvent).order_by(desc(AuditEvent.id)).limit(1)
    res = await db.execute(stmt)
    last_event = res.scalars().first()

    prev_hash = last_event.current_hash if last_event else GENESIS_HASH
    event_id = f"EVT-{uuid.uuid4().hex[:12].upper()}"
    timestamp = datetime.utcnow()
    timestamp_iso = timestamp.isoformat() + "Z"

    current_hash = compute_event_hash(
        prev_hash=prev_hash,
        event_id=event_id,
        actor_id=actor_id,
        actor_role=actor_role,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        team_context=team_context,
        timestamp_iso=timestamp_iso,
        outcome=outcome,
        correlation_id=correlation_id,
        details=details
    )

    event = AuditEvent(
        event_id=event_id,
        actor_id=actor_id,
        actor_role=actor_role,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        team_context=team_context,
        timestamp=timestamp,
        outcome=outcome,
        correlation_id=correlation_id,
        prev_hash=prev_hash,
        current_hash=current_hash,
        details_json=details
    )

    db.add(event)
    await db.commit()
    await db.refresh(event)
    return event

async def verify_audit_chain(db: AsyncSession) -> Dict[str, Any]:
    """Verifies the complete SHA-256 hash chain of the audit log."""
    stmt = select(AuditEvent).order_by(AuditEvent.id.asc())
    res = await db.execute(stmt)
    events: List[AuditEvent] = res.scalars().all()

    if not events:
        return {
            "verified": True,
            "total_events": 0,
            "broken_at_event_id": None,
            "status": "EMPTY_CHAIN_VALID",
            "message": "Audit chain is empty. Genesis state intact."
        }

    expected_prev_hash = GENESIS_HASH

    for idx, ev in enumerate(events):
        # 1. Check prev_hash linkage
        if ev.prev_hash != expected_prev_hash:
            return {
                "verified": False,
                "total_events": len(events),
                "broken_at_event_id": ev.event_id,
                "broken_at_index": idx,
                "status": "LINKAGE_BROKEN",
                "message": f"Linkage mismatch at {ev.event_id}: expected prev_hash {expected_prev_hash}, found {ev.prev_hash}"
            }

        # 2. Re-compute hash
        timestamp_iso = ev.timestamp.isoformat() + "Z"
        recomputed = compute_event_hash(
            prev_hash=ev.prev_hash,
            event_id=ev.event_id,
            actor_id=ev.actor_id,
            actor_role=ev.actor_role,
            action=ev.action,
            resource_type=ev.resource_type,
            resource_id=ev.resource_id,
            team_context=ev.team_context,
            timestamp_iso=timestamp_iso,
            outcome=ev.outcome,
            correlation_id=ev.correlation_id,
            details=ev.details_json or {}
        )

        if recomputed != ev.current_hash:
            return {
                "verified": False,
                "total_events": len(events),
                "broken_at_event_id": ev.event_id,
                "broken_at_index": idx,
                "status": "TAMPER_DETECTED",
                "message": f"Hash integrity failure at {ev.event_id}: calculated {recomputed}, recorded {ev.current_hash}"
            }

        expected_prev_hash = ev.current_hash

    return {
        "verified": True,
        "total_events": len(events),
        "broken_at_event_id": None,
        "status": "CHAIN_INTEGRITY_VERIFIED",
        "latest_hash": events[-1].current_hash,
        "message": f"Cryptographic audit chain fully verified across all {len(events)} events."
    }
