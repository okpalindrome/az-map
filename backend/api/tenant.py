"""
Tenant configuration CRUD.

Tenants are user-defined bookmark groups that map a friendly name to one or
more Azure subscription IDs. Useful for MSP / multi-tenant workflows.
"""
import re
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.db_models import TenantConfig

router = APIRouter(prefix="/api/tenant", tags=["tenant"])

_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE,
)

def _strip_ctrl(v: str, max_len: int = 256) -> str:
    """Remove control characters and enforce length cap."""
    return re.sub(r"[\x00-\x1f\x7f]", "", v).strip()[:max_len]


# ── Pydantic schemas ────────────────────────────────────────────────────────

class TenantCreate(BaseModel):
    display_name: str
    tenant_id: Optional[str] = None
    subscription_ids: list[str] = []
    notes: Optional[str] = None

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, v: str) -> str:
        v = _strip_ctrl(v, 128)
        if not v:
            raise ValueError("display_name must not be empty")
        return v

    @field_validator("tenant_id")
    @classmethod
    def validate_tenant_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        if v and not _UUID_RE.match(v):
            raise ValueError("tenant_id must be a valid UUID")
        return v.lower() if v else None

    @field_validator("subscription_ids")
    @classmethod
    def validate_subscription_ids(cls, v: list[str]) -> list[str]:
        validated = []
        for sid in v:
            sid = sid.strip()
            if sid and not _UUID_RE.match(sid):
                raise ValueError(f"Invalid subscription ID: {sid!r}")
            if sid:
                validated.append(sid.lower())
        return validated

    @field_validator("notes")
    @classmethod
    def sanitize_notes(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return _strip_ctrl(v, 1024) or None


class TenantUpdate(BaseModel):
    display_name: Optional[str] = None
    tenant_id: Optional[str] = None
    subscription_ids: Optional[list[str]] = None
    notes: Optional[str] = None

    @field_validator("display_name")
    @classmethod
    def validate_display_name(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = _strip_ctrl(v, 128)
        if not v:
            raise ValueError("display_name must not be empty")
        return v

    @field_validator("subscription_ids")
    @classmethod
    def validate_subscription_ids(cls, v: Optional[list[str]]) -> Optional[list[str]]:
        if v is None:
            return None
        validated = []
        for sid in v:
            sid = sid.strip()
            if sid and not _UUID_RE.match(sid):
                raise ValueError(f"Invalid subscription ID: {sid!r}")
            if sid:
                validated.append(sid.lower())
        return validated


class TenantResponse(BaseModel):
    id: str
    display_name: str
    tenant_id: Optional[str]
    subscription_ids: list[str]
    notes: Optional[str]
    created_at: str
    updated_at: str


def _to_response(t: TenantConfig) -> TenantResponse:
    return TenantResponse(
        id=t.id,
        display_name=t.display_name,
        tenant_id=t.tenant_id,
        subscription_ids=t.subscription_ids or [],
        notes=t.notes,
        created_at=t.created_at.isoformat() if t.created_at else "",
        updated_at=t.updated_at.isoformat() if t.updated_at else "",
    )


# ── Endpoints ───────────────────────────────────────────────────────────────

@router.get("/", response_model=list[TenantResponse])
def list_tenants(db: Session = Depends(get_db)):
    tenants = db.query(TenantConfig).order_by(TenantConfig.display_name).all()
    return [_to_response(t) for t in tenants]


@router.post("/", response_model=TenantResponse, status_code=201)
def create_tenant(body: TenantCreate, db: Session = Depends(get_db)):
    existing = db.query(TenantConfig).filter(
        TenantConfig.display_name == body.display_name
    ).first()
    if existing:
        raise HTTPException(409, f"Tenant '{body.display_name}' already exists")
    t = TenantConfig(
        display_name=body.display_name,
        tenant_id=body.tenant_id,
        subscription_ids=body.subscription_ids,
        notes=body.notes,
    )
    db.add(t)
    db.commit()
    db.refresh(t)
    return _to_response(t)


@router.get("/{tenant_id_}", response_model=TenantResponse)
def get_tenant(tenant_id_: str, db: Session = Depends(get_db)):
    t = db.query(TenantConfig).filter(TenantConfig.id == tenant_id_).first()
    if not t:
        raise HTTPException(404, "Tenant not found")
    return _to_response(t)


@router.put("/{tenant_id_}", response_model=TenantResponse)
def update_tenant(tenant_id_: str, body: TenantUpdate, db: Session = Depends(get_db)):
    t = db.query(TenantConfig).filter(TenantConfig.id == tenant_id_).first()
    if not t:
        raise HTTPException(404, "Tenant not found")
    if body.display_name is not None:
        t.display_name = body.display_name
    if body.tenant_id is not None:
        t.tenant_id = body.tenant_id
    if body.subscription_ids is not None:
        t.subscription_ids = body.subscription_ids
    if body.notes is not None:
        t.notes = body.notes
    t.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(t)
    return _to_response(t)


@router.delete("/{tenant_id_}", status_code=204)
def delete_tenant(tenant_id_: str, db: Session = Depends(get_db)):
    t = db.query(TenantConfig).filter(TenantConfig.id == tenant_id_).first()
    if not t:
        raise HTTPException(404, "Tenant not found")
    db.delete(t)
    db.commit()
