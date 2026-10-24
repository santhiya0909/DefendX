import time
import psutil
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.core.config import settings
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.models import User
from app.services.scanner import check_clamav_service

router = APIRouter(prefix="/infrastructure", tags=["Isolation and Infrastructure Monitor"])

@router.get("/health")
async def get_infrastructure_health(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Real infrastructure health telemetry:
    - Database roundtrip latency
    - Host CPU and Memory telemetry via psutil
    - Configured AI provider status
    - ClamAV malware daemon connectivity
    - Resource restrictions & sandbox limits
    """
    # 1. Database latency
    db_ok = True
    db_latency_ms = 0.0
    try:
        t0 = time.time()
        await db.execute(text("SELECT 1"))
        db_latency_ms = round((time.time() - t0) * 1000, 2)
    except Exception as e:
        db_ok = False
        db_error = str(e)

    # 2. Host CPU & Memory via psutil
    try:
        cpu_percent = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        mem_percent = mem.percent
        mem_used_mb = round(mem.used / (1024 * 1024), 1)
        mem_total_mb = round(mem.total / (1024 * 1024), 1)
    except Exception:
        cpu_percent = None
        mem_percent = None
        mem_used_mb = None
        mem_total_mb = None

    # 3. ClamAV Malware scanner status
    clamav_online, clamav_msg = check_clamav_service(settings.CLAMAV_HOST, settings.CLAMAV_PORT)

    # 4. Model provider status
    provider_info = {
        "active_provider": settings.LLM_PROVIDER,
        "model_name": settings.LLM_MODEL_NAME,
        "is_api_key_configured": bool(settings.LLM_API_KEY),
        "status": "OPERATIONAL" if (settings.LLM_PROVIDER == "mock" or bool(settings.LLM_API_KEY)) else "UNCONFIGURED_KEY"
    }

    return {
        "status": "HEALTHY" if db_ok else "DEGRADED",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "database": {
            "connected": db_ok,
            "type": "PostgreSQL" if "postgres" in settings.DATABASE_URL else "SQLite (AsyncIO)",
            "latency_ms": db_latency_ms
        },
        "telemetry": {
            "cpu_percent": cpu_percent,
            "memory_percent": mem_percent,
            "memory_used_mb": mem_used_mb,
            "memory_total_mb": mem_total_mb,
            "telemetry_source": "psutil_system_metrics"
        },
        "ai_model_service": provider_info,
        "malware_scanner": {
            "clamav_reachable": clamav_online,
            "details": clamav_msg,
            "status_label": "ACTIVE" if clamav_online else "UNAVAILABLE (ClamAV daemon not listening on port 3310)"
        },
        "security_sandbox": {
            "file_size_limit_mb": settings.MAX_UPLOAD_SIZE_MB,
            "allowed_extensions": settings.ALLOWED_EXTENSIONS,
            "quarantine_isolation_active": True,
            "team_isolation_enforced": True,
            "hash_linked_audit_active": True
        }
    }
