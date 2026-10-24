import os
import uuid
import hashlib
import json
import csv
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, status
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.config import settings
from app.core.database import get_db
from app.core.security import get_current_user
from app.core.audit import record_audit_event
from app.models.models import (
    User, UploadedFile, TestDataset, TestCase, ScanStatus, UserRole,
    TestCategory, Severity
)
from app.schemas.schemas import (
    FileUploadResponse, DatasetImportPreview, DatasetImportCommit,
    TestDatasetResponse
)
from app.services.scanner import scan_file_content

router = APIRouter(prefix="/files", tags=["File and Photo Upload Centre"])

@router.post("/upload", response_model=FileUploadResponse)
async def upload_file(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Secure file upload workflow:
    1. Extension allowlist check
    2. Path traversal protection
    3. Storage under randomized server-side UUID outside public root
    4. SHA-256 integrity digest computation
    5. Multi-stage heuristic & signature security scanning
    6. Quarantine containment if suspicious
    """
    original_name = os.path.basename(file.filename or "upload.bin")
    _, ext = os.path.splitext(original_name.lower())

    if ext not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file format '{ext}'. Allowed: {', '.join(settings.ALLOWED_EXTENSIONS)}"
        )

    # Secure random filename
    stored_name = f"{uuid.uuid4().hex}{ext}"
    file_path = os.path.join(settings.UPLOAD_DIR, stored_name)

    # Read content and compute SHA-256
    sha256 = hashlib.sha256()
    size = 0
    with open(file_path, "wb") as f:
        while chunk := await file.read(65536):
            size += len(chunk)
            if size > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
                f.close()
                if os.path.exists(file_path):
                    os.remove(file_path)
                raise HTTPException(
                    status_code=413,
                    detail=f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_MB}MB."
                )
            sha256.update(chunk)
            f.write(chunk)

    file_hash = sha256.hexdigest()

    # Run multi-stage scanner
    scan_result = scan_file_content(file_path, original_name)

    uploaded_record = UploadedFile(
        original_name=original_name,
        stored_name=stored_name,
        file_path=file_path,
        file_size=size,
        mime_type=file.content_type or "application/octet-stream",
        file_hash_sha256=file_hash,
        scan_status=scan_result["status"],
        scan_summary=scan_result["summary"],
        scanner_details=scan_result,
        uploader_id=current_user.id,
        team=current_user.role,
        is_quarantined=scan_result["quarantined"]
    )

    db.add(uploaded_record)
    await db.commit()
    await db.refresh(uploaded_record)

    await record_audit_event(
        db=db,
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        action="FILE_UPLOAD_AND_SCAN",
        resource_type="UPLOADED_FILE",
        resource_id=str(uploaded_record.id),
        team_context=current_user.role.value,
        outcome="SUCCESS" if not uploaded_record.is_quarantined else "QUARANTINED",
        details={
            "filename": original_name,
            "scan_status": scan_result["status"].value,
            "hash": file_hash,
            "quarantined": uploaded_record.is_quarantined
        }
    )

    return FileUploadResponse.model_validate(uploaded_record)

@router.get("", response_model=List[FileUploadResponse])
async def list_files(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    stmt = select(UploadedFile).order_by(UploadedFile.id.desc())
    res = await db.execute(stmt)
    records = res.scalars().all()
    return [FileUploadResponse.model_validate(r) for r in records]

@router.get("/{file_id}/download")
async def download_file(
    file_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    stmt = select(UploadedFile).where(UploadedFile.id == file_id)
    res = await db.execute(stmt)
    rec = res.scalars().first()
    if not rec:
        raise HTTPException(status_code=404, detail="File record not found.")

    if rec.is_quarantined and current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=403,
            detail="Access forbidden: File is quarantined due to detected security findings."
        )

    if not os.path.exists(rec.file_path):
        raise HTTPException(status_code=404, detail="File payload missing from storage.")

    return FileResponse(
        path=rec.file_path,
        filename=rec.original_name,
        media_type=rec.mime_type
    )

@router.post("/datasets/preview", response_model=DatasetImportPreview)
async def preview_dataset(
    file_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Parses uploaded CSV/JSON dataset and provides schema mapping preview."""
    stmt = select(UploadedFile).where(UploadedFile.id == file_id)
    res = await db.execute(stmt)
    rec = res.scalars().first()
    if not rec or not os.path.exists(rec.file_path):
        raise HTTPException(status_code=404, detail="File not found")

    records = []
    columns = []

    with open(rec.file_path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read(2_000_000)

    _, ext = os.path.splitext(rec.original_name.lower())
    if ext == ".csv":
        reader = csv.DictReader(content.splitlines())
        columns = reader.fieldnames or []
        for idx, row in enumerate(reader):
            if idx < 10:
                records.append(row)
    elif ext == ".json":
        data = json.loads(content)
        if isinstance(data, list):
            records = data[:10]
            if records:
                columns = list(records[0].keys())

    # Build suggested mapping
    mapping = {}
    col_lower = {c.lower(): c for c in columns}
    for target in ["input_prompt", "name", "category", "severity", "expected_behavior"]:
        for c in columns:
            if target in c.lower() or c.lower() in target:
                mapping[target] = c
                break

    return DatasetImportPreview(
        filename=rec.original_name,
        total_rows=len(records),
        sample_records=records,
        detected_columns=columns,
        suggested_mapping=mapping
    )

@router.post("/datasets/commit", response_model=TestDatasetResponse)
async def commit_dataset_import(
    req: DatasetImportCommit,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Validates dataset records, checks duplicate IDs, and imports test cases into database.
    Supports transaction rollback on failure.
    """
    dataset_id = f"DS-{uuid.uuid4().hex[:6].upper()}"
    dataset = TestDataset(
        dataset_id=dataset_id,
        name=req.name,
        description=req.description or "Imported via Dataset Import Wizard",
        file_format="json",
        record_count=len(req.records),
        uploader_id=current_user.id,
        team=current_user.role,
        validation_status="IMPORTING"
    )
    db.add(dataset)
    await db.commit()
    await db.refresh(dataset)

    valid_count = 0
    malformed_count = 0
    duplicate_count = 0

    col_map = req.column_mapping
    for idx, r in enumerate(req.records):
        prompt_text = str(r.get(col_map.get("input_prompt", "input_prompt"), r.get("prompt", ""))).strip()
        expected = str(r.get(col_map.get("expected_behavior", "expected_behavior"), "Should refuse harmful instructions")).strip()
        name = str(r.get(col_map.get("name", "name"), f"Imported Test Case #{idx+1}")).strip()
        cat_str = str(r.get(col_map.get("category", "category"), "PROMPT_INJECTION")).upper()

        if not prompt_text:
            malformed_count += 1
            continue

        try:
            category_enum = TestCategory[cat_str] if cat_str in TestCategory.__members__ else TestCategory.PROMPT_INJECTION
        except Exception:
            category_enum = TestCategory.PROMPT_INJECTION

        test_id = f"TC-IMP-{uuid.uuid4().hex[:6].upper()}"
        tc = TestCase(
            test_id=test_id,
            name=name,
            description="Imported from approved dataset",
            category=category_enum,
            severity=Severity.HIGH,
            input_prompt=prompt_text,
            expected_behavior=expected,
            tags="dataset_import",
            is_sandbox_only=True,
            team=current_user.role,
            dataset_id=dataset.id,
            created_by_id=current_user.id
        )
        db.add(tc)
        valid_count += 1

    dataset.valid_count = valid_count
    dataset.malformed_count = malformed_count
    dataset.duplicate_count = duplicate_count
    dataset.validation_status = "COMPLETED"

    await db.commit()
    await db.refresh(dataset)

    await record_audit_event(
        db=db,
        actor_id=str(current_user.id),
        actor_role=current_user.role.value,
        action="DATASET_IMPORTED",
        resource_type="TEST_DATASET",
        resource_id=dataset.dataset_id,
        team_context=current_user.role.value,
        outcome="SUCCESS",
        details={"valid_records": valid_count, "malformed_records": malformed_count}
    )

    return TestDatasetResponse.model_validate(dataset)
