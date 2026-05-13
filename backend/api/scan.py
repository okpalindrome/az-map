"""Scan management API: start, status (SSE), list, delete, import."""
import asyncio
import json
import re
import shutil
import uuid
from datetime import datetime
from typing import AsyncGenerator, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from ..collectors.scan_orchestrator import ScanOrchestrator
from ..database import get_db
from ..models.db_models import Edge, Finding, Node, RoleAssignment, Scan

router = APIRouter(prefix="/api/scan", tags=["scan"])

_active_orchestrators: dict[str, ScanOrchestrator] = {}

_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)


def _get_az_cmd() -> str:
    cmd = shutil.which("az")
    if cmd:
        return cmd
    import os
    for candidate in ("/usr/local/bin/az", "/opt/homebrew/bin/az", "/usr/bin/az"):
        if os.path.isfile(candidate):
            return candidate
    return "az"


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


@router.get("/subscriptions")
async def list_subscriptions():
    """Return Azure subscriptions available via the current az login session."""
    az_cmd = _get_az_cmd()
    try:
        proc = await asyncio.create_subprocess_exec(
            az_cmd, "account", "list", "--output", "json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        if proc.returncode == 0 and stdout.strip():
            subs = json.loads(stdout.decode())
            return [
                {
                    "id": s["id"],
                    "name": s["name"],
                    "tenant_id": s.get("tenantId", ""),
                    "is_default": s.get("isDefault", False),
                }
                for s in subs
                if s.get("state", "Enabled").lower() in ("enabled", "")
            ]
    except Exception:
        pass
    return []


@router.get("/current-user")
async def get_current_user():
    """Return info about the currently logged-in az CLI user."""
    az_cmd = _get_az_cmd()
    try:
        proc = await asyncio.create_subprocess_exec(
            az_cmd, "account", "show", "--output", "json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        if proc.returncode != 0 or not stdout.strip():
            return None
        account = json.loads(stdout.decode())
        user = account.get("user", {})
        result = {
            "name": user.get("name", ""),
            "type": user.get("type", "user"),
            "tenant_id": account.get("tenantId", ""),
            "subscription_id": account.get("id", ""),
            "object_id": None,
        }
        if user.get("type") == "user":
            proc2 = await asyncio.create_subprocess_exec(
                az_cmd, "ad", "signed-in-user", "show", "--query", "id", "-o", "tsv",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout2, _ = await asyncio.wait_for(proc2.communicate(), timeout=10)
            if proc2.returncode == 0 and stdout2.strip():
                result["object_id"] = stdout2.decode().strip()
        return result
    except Exception:
        return None


@router.post("/import", response_model=ScanResponse)
async def import_scan(request: Request, db: Session = Depends(get_db)):
    """Import a previously exported az-map JSON and store it as a completed scan."""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON body")

    scan_data = body.get("scan", {})
    sub_id = scan_data.get("subscription_id") or body.get("subscription_id", "unknown")
    sub_name = scan_data.get("subscription_name") or body.get("subscription_name")
    tenant_id = scan_data.get("tenant_id")

    exported_at = body.get("exported_at", "")
    label_suffix = sub_name or sub_id
    snapshot_label = f"Imported: {label_suffix}"
    if exported_at:
        try:
            dt = datetime.fromisoformat(exported_at.replace("Z", "+00:00"))
            snapshot_label = f"Imported: {label_suffix} ({dt.strftime('%Y-%m-%d')})"
        except Exception:
            pass

    scan = Scan(
        id=str(uuid.uuid4()),
        subscription_id=sub_id,
        subscription_name=sub_name,
        tenant_id=tenant_id,
        status="completed",
        snapshot_label=snapshot_label,
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        progress={"phase": "done", "message": "Imported from JSON", "current": 1, "total": 1},
    )
    db.add(scan)
    db.flush()

    for n in body.get("nodes", []):
        node = Node(
            scan_id=scan.id,
            node_id=n["node_id"],
            node_type=n.get("node_type", "unknown"),
            name=n.get("name", n["node_id"]),
            display_name=n.get("display_name"),
            risk_score=float(n.get("risk_score", 0.0)),
            risk_level=n.get("risk_level", "safe"),
            risk_reasons=n.get("risk_reasons", []),
            properties=n.get("properties", {}),
        )
        db.add(node)

    for e in body.get("edges", []):
        edge = Edge(
            scan_id=scan.id,
            source_node_id=e["source_node_id"],
            target_node_id=e["target_node_id"],
            edge_type=e.get("edge_type", "unknown"),
            properties=e.get("properties", {}),
        )
        db.add(edge)

    for f in body.get("findings", []):
        finding = Finding(
            scan_id=scan.id,
            finding_type=f.get("finding_type", "unknown"),
            severity=f.get("severity", "info"),
            title=f.get("title", ""),
            description=f.get("description"),
            affected_node_id=f.get("affected_node_id"),
            affected_node_name=f.get("affected_node") or f.get("affected_node_name"),
            attack_chain=f.get("attack_chain", []),
            why_risky=f.get("why_risky"),
            remediation=f.get("remediation"),
            tags=f.get("tags", []),
            risk_score=float(f.get("risk_score", 0.0)),
            blast_radius=int(f.get("blast_radius", 0)),
        )
        db.add(finding)

    db.commit()
    db.refresh(scan)
    return _scan_to_response(scan)


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
                        db.expire_all()
                        s = db.query(Scan).filter(Scan.id == scan_id).first()
                        if s and s.status in ("completed", "failed"):
                            yield f"data: {json.dumps(s.progress or {})}\n\n"
                            break
                        yield ": keepalive\n\n"
            except (asyncio.CancelledError, GeneratorExit):
                orchestrator.unsubscribe(q)
                return
        else:
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
