"""Findings API: list, filter, detail."""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.db_models import Finding, Scan

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("/{scan_id}")
def list_findings(
    scan_id: str,
    severity: Optional[str] = Query(None, description="Comma-separated severities"),
    finding_type: Optional[str] = Query(None, description="Comma-separated finding types"),
    search: Optional[str] = Query(None, max_length=200),
    sort_by: str = Query("risk_score", enum=["risk_score", "severity", "blast_radius", "title"]),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    q = db.query(Finding).filter(Finding.scan_id == scan_id)

    if severity:
        sevs = [s.strip() for s in severity.split(",")]
        q = q.filter(Finding.severity.in_(sevs))
    if finding_type:
        fts = [f.strip() for f in finding_type.split(",")]
        q = q.filter(Finding.finding_type.in_(fts))
    if search:
        s = f"%{search.lower()}%"
        from sqlalchemy import or_
        q = q.filter(or_(
            func.lower(Finding.title).like(s),
            func.lower(Finding.description).like(s),
        ))

    order_col = {
        "risk_score": Finding.risk_score.desc(),
        "severity": Finding.severity,
        "blast_radius": Finding.blast_radius.desc(),
        "title": Finding.title,
    }[sort_by]
    q = q.order_by(order_col)

    total = q.count()
    findings = q.offset(offset).limit(limit).all()

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "findings": [_finding_dict(f) for f in findings],
    }


@router.get("/{scan_id}/summary")
def findings_summary(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    by_severity = (
        db.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.scan_id == scan_id)
        .group_by(Finding.severity)
        .all()
    )
    by_type = (
        db.query(Finding.finding_type, func.count(Finding.id))
        .filter(Finding.scan_id == scan_id)
        .group_by(Finding.finding_type)
        .all()
    )
    top_risk = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id)
        .order_by(Finding.risk_score.desc())
        .limit(5)
        .all()
    )
    return {
        "by_severity": {s: c for s, c in by_severity},
        "by_type": {t: c for t, c in by_type},
        "top_risk": [_finding_dict(f) for f in top_risk],
    }


@router.get("/{scan_id}/finding/{finding_id}")
def get_finding(scan_id: str, finding_id: str, db: Session = Depends(get_db)):
    f = db.query(Finding).filter(
        Finding.scan_id == scan_id, Finding.id == finding_id
    ).first()
    if not f:
        raise HTTPException(404, "Finding not found")
    return _finding_dict(f)


def _finding_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "finding_type": f.finding_type,
        "severity": f.severity,
        "title": f.title,
        "description": f.description,
        "affected_node_id": f.affected_node_id,
        "affected_node_name": f.affected_node_name,
        "attack_chain": f.attack_chain or [],
        "why_risky": f.why_risky,
        "remediation": f.remediation,
        "tags": f.tags or [],
        "risk_score": f.risk_score,
        "blast_radius": f.blast_radius,
    }
