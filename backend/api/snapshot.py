"""
Snapshot & Diff API.

Endpoints:
  GET  /api/snapshot/list/{subscription_id}  — list completed scans for a subscription
  GET  /api/snapshot/diff                    — diff two scans
  POST /api/snapshot/label/{scan_id}         — assign/update snapshot label
"""
import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from ..analyzers.diff import compute_diff, diff_to_dict
from ..database import get_db
from ..models.db_models import Scan

router = APIRouter(prefix="/api/snapshot", tags=["snapshot"])


@router.get("/list/{subscription_id}")
def list_snapshots(subscription_id: str, db: Session = Depends(get_db)):
    """List all completed scans for a subscription, ordered by date desc."""
    scans = (
        db.query(Scan)
        .filter(Scan.subscription_id == subscription_id, Scan.status == "completed")
        .order_by(Scan.completed_at.desc())
        .all()
    )
    return [
        {
            "scan_id": s.id,
            "subscription_name": s.subscription_name,
            "snapshot_label": s.snapshot_label,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "started_at": s.started_at.isoformat() if s.started_at else None,
        }
        for s in scans
    ]


@router.get("/diff")
def diff_scans(
    scan_a: str = Query(..., description="Baseline scan ID (older)"),
    scan_b: str = Query(..., description="Current scan ID (newer)"),
    db: Session = Depends(get_db),
):
    """Compute the diff between two completed scans."""
    try:
        result = compute_diff(scan_a, scan_b, db)
        return diff_to_dict(result)
    except ValueError as e:
        raise HTTPException(400, str(e))


class LabelRequest(BaseModel):
    label: str

    @field_validator("label")
    @classmethod
    def sanitize_label(cls, v: str) -> str:
        # Strip control characters, limit length
        v = re.sub(r"[\x00-\x1f\x7f]", "", v).strip()[:128]
        if not v:
            raise ValueError("label must not be empty")
        return v


@router.post("/label/{scan_id}")
def set_label(scan_id: str, body: LabelRequest, db: Session = Depends(get_db)):
    """Assign or update the human-readable snapshot label for a scan."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    scan.snapshot_label = body.label
    db.commit()
    return {"scan_id": scan_id, "label": scan.snapshot_label}
