"""Scan management API: start, status (SSE), list, delete."""
import asyncio
import json
import re
import uuid
from datetime import datetime
from typing import AsyncGenerator, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from ..collectors.scan_orchestrator import ScanOrchestrator
from ..database import get_db
from ..models.db_models import Scan

router = APIRouter(prefix="/api/scan", tags=["scan"])

# Active orchestrators keyed by scan_id (in-process, single worker)
_active_orchestrators: dict[str, ScanOrchestrator] = {}

# Azure subscription ID is always a UUID
_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)


class ScanStartRequest(BaseModel):
    subscription_id: str
    snapshot_label: Optional[str] = None
    reuse_collection: bool = False

    @field_validator("subscription_id")
    @classmethod
    def validate_subscription_id(cls, v: str) -> str:
        v = v.strip()
        if not _UUID_RE.match(v):
            raise ValueError(
                "subscription_id must be a valid Azure subscription UUID "
                "(format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)"
            )
        return v.lower()

    @field_validator("snapshot_label")
    @classmethod
    def sanitize_label(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        # Strip control characters and limit length
        v = re.sub(r"[\x00-\x1f\x7f]", "", v).strip()[:128]
        return v or None


class ScanResponse(BaseModel):
    scan_id: str
    subscription_id: str
    subscription_name: Optional[str]
    tenant_id: Optional[str]
    status: str
    started_at: str
    completed_at: Optional[str]
    progress: dict
    error: Optional[str]
    snapshot_label: Optional[str] = None


def _scan_to_response(scan: Scan) -> ScanResponse:
    return ScanResponse(
        scan_id=scan.id,
        subscription_id=scan.subscription_id,
        subscription_name=scan.subscription_name,
        tenant_id=scan.tenant_id,
        status=scan.status,
        started_at=scan.started_at.isoformat() if scan.started_at else "",
        completed_at=scan.completed_at.isoformat() if scan.completed_at else None,
        snapshot_label=scan.snapshot_label,
        progress=scan.progress or {},
        error=scan.error,
    )


@router.post("/start", response_model=ScanResponse)
async def start_scan(
    body: ScanStartRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    scan_id = str(uuid.uuid4())
    scan = Scan(
        id=scan_id,
        subscription_id=body.subscription_id,
        status="running",
        snapshot_label=body.snapshot_label,
        progress={"phase": "queued", "message": "Scan queued", "current": 0, "total": 5},
    )
    db.add(scan)
    db.commit()

    orchestrator = ScanOrchestrator(scan_id, body.subscription_id, reuse_collection=body.reuse_collection)
    _active_orchestrators[scan_id] = orchestrator

    background_tasks.add_task(_run_scan, orchestrator, scan_id)
    return _scan_to_response(scan)


async def _run_scan(orchestrator: ScanOrchestrator, scan_id: str):
    try:
        await orchestrator.run()
    finally:
        _active_orchestrators.pop(scan_id, None)


@router.get("/stream/{scan_id}")
async def stream_progress(scan_id: str, db: Session = Depends(get_db)):
    """SSE endpoint: streams progress events until scan completes."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    orchestrator = _active_orchestrators.get(scan_id)

    async def _event_generator() -> AsyncGenerator[str, None]:
        if orchestrator:
            q = orchestrator.subscribe()
            try:
                while True:
                    try:
                        event = await asyncio.wait_for(q.get(), timeout=2.0)
                        yield f"data: {json.dumps(event)}\n\n"
                        if event.get("phase") in ("done", "error"):
                            break
                    except asyncio.TimeoutError:
                        # Refresh scan status from DB
                        db.expire_all()
                        s = db.query(Scan).filter(Scan.id == scan_id).first()
                        if s and s.status in ("completed", "failed"):
                            yield f"data: {json.dumps(s.progress or {})}\n\n"
                            break
                        # keepalive
                        yield ": keepalive\n\n"
            except (asyncio.CancelledError, GeneratorExit):
                # Browser disconnected — scan continues in background
                orchestrator.unsubscribe(q)
                return
        else:
            # Scan already done — send final status
            db.expire_all()
            s = db.query(Scan).filter(Scan.id == scan_id).first()
            if s:
                yield f"data: {json.dumps(s.progress or {})}\n\n"

    return StreamingResponse(
        _event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    return _scan_to_response(scan)


@router.get("/", response_model=list[ScanResponse])
def list_scans(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.started_at.desc()).limit(50).all()
    return [_scan_to_response(s) for s in scans]


@router.delete("/{scan_id}")
def delete_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    db.delete(scan)
    db.commit()
    return {"deleted": scan_id}
