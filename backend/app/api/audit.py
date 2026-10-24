import csv
import io
import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from app.core.database import get_db
from app.core.security import require_roles
from app.core.audit import verify_audit_chain
from app.models.models import User, UserRole, AuditEvent
from app.schemas.schemas import AuditEventResponse, AuditChainVerificationResponse

router = APIRouter(prefix="/audit", tags=["Privacy and Audit Centre"])

@router.get("/events", response_model=List[AuditEventResponse])
async def list_audit_events(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action: Optional[str] = None,
    actor_role: Optional[str] = None,
    outcome: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN, UserRole.AUDITOR, UserRole.RED_TEAM, UserRole.BLUE_TEAM]))
):
    stmt = select(AuditEvent)
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    if actor_role:
        stmt = stmt.where(AuditEvent.actor_role == actor_role)
    if outcome:
        stmt = stmt.where(AuditEvent.outcome == outcome)

    stmt = stmt.order_by(desc(AuditEvent.id)).offset(offset).limit(limit)
    res = await db.execute(stmt)
    events = res.scalars().all()
    return [AuditEventResponse.model_validate(e) for e in events]

@router.get("/verify", response_model=AuditChainVerificationResponse)
async def verify_chain(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN, UserRole.AUDITOR]))
):
    """
    Cryptographic verification endpoint:
    Traverses the full SHA-256 hash chain from Genesis, recomputes canonical hashes,
    and returns mathematical proof of audit trail integrity.
    """
    result = await verify_audit_chain(db)
    return AuditChainVerificationResponse(**result)

@router.get("/export")
async def export_audit_log(
    format: str = Query("json", pattern="^(json|csv)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN, UserRole.AUDITOR]))
):
    """Exports immutable audit logs in JSON or CSV format."""
    stmt = select(AuditEvent).order_by(AuditEvent.id.asc())
    res = await db.execute(stmt)
    events = res.scalars().all()

    if format == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "event_id", "actor_id", "actor_role", "action", "resource_type",
            "resource_id", "team_context", "timestamp", "outcome", "correlation_id",
            "prev_hash", "current_hash"
        ])
        for e in events:
            writer.writerow([
                e.event_id, e.actor_id, e.actor_role, e.action, e.resource_type,
                e.resource_id, e.team_context, e.timestamp.isoformat() + "Z",
                e.outcome, e.correlation_id, e.prev_hash, e.current_hash
            ])
        output.seek(0)
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=defendx_audit_trail.csv"}
        )

    # JSON export with canonical structure
    export_data = [
        {
            "event_id": e.event_id,
            "actor_id": e.actor_id,
            "actor_role": e.actor_role,
            "action": e.action,
            "resource_type": e.resource_type,
            "resource_id": e.resource_id,
            "team_context": e.team_context,
            "timestamp": e.timestamp.isoformat() + "Z",
            "outcome": e.outcome,
            "correlation_id": e.correlation_id,
            "prev_hash": e.prev_hash,
            "current_hash": e.current_hash,
            "details": e.details_json or {}
        }
        for e in events
    ]
    return Response(
        content=json.dumps(export_data, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=defendx_audit_trail.json"}
    )
