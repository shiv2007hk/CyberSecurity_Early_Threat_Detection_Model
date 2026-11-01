"""Administration: users, roles, audit trail, classifier quality and system status."""
import platform

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..deps import audit, get_current_user, require_role
from ..models import (
    Alert,
    Asset,
    AuditLog,
    ModelEvaluation,
    Organisation,
    Recommendation,
    Threat,
    ThreatSource,
    User,
    Vulnerability,
    utcnow,
)
from ..schemas import AdminPasswordReset, UserCreate, UserUpdate
from ..security import hash_password, password_problems
from ..serializers import audit_out, user_out
from ..services import classifier, risk
from ..utils import csv_response_bytes
from .common import ensure_range, paginate, split_multi

router = APIRouter(prefix="/admin", tags=["Administration"])


@router.get("/users")
def list_users(
    q: str | None = None,
    role: str | None = None,
    active: bool | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    query = db.query(User)
    if q:
        pattern = f"%{q.strip()}%"
        query = query.filter(or_(User.full_name.ilike(pattern), User.email.ilike(pattern)))
    roles = split_multi(role)
    if roles:
        query = query.filter(User.role.in_(roles))
    if active is not None:
        query = query.filter(User.is_active.is_(active))
    query = query.order_by(User.created_at.desc())
    result = paginate(query, page, size, user_out)
    result["stats"] = {
        "total": db.query(func.count(User.id)).scalar() or 0,
        "admins": db.query(func.count(User.id)).filter(User.role == "admin", User.is_active.is_(True)).scalar() or 0,
        "analysts": db.query(func.count(User.id)).filter(User.role == "analyst", User.is_active.is_(True)).scalar() or 0,
        "viewers": db.query(func.count(User.id)).filter(User.role == "viewer", User.is_active.is_(True)).scalar() or 0,
    }
    result["organisations"] = [
        {"id": org.id, "name": org.name, "sector": org.sector, "country": org.country}
        for org in db.query(Organisation).order_by(Organisation.name).all()
    ]
    return result


@router.post("/users", status_code=201)
def create_user(payload: UserCreate, request: Request, db: Session = Depends(get_db),
                user: User = Depends(require_role("admin"))):
    email = payload.email.lower().strip()
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    problems = password_problems(payload.password)
    if problems:
        raise HTTPException(status_code=422, detail="Password must contain " + ", ".join(problems))
    org = db.get(Organisation, payload.organisation_id) if payload.organisation_id else user.organisation
    created = User(
        email=email,
        full_name=payload.full_name.strip(),
        password_hash=hash_password(payload.password),
        role=payload.role,
        organisation_id=org.id if org else None,
        is_active=True,
        created_at=utcnow(),
    )
    db.add(created)
    db.flush()
    audit(db, request, user, "user.created", "user", str(created.id), f"{email} role={payload.role}")
    db.commit()
    return {"user": user_out(created), "message": "Account created"}


def _active_admin_count(db: Session) -> int:
    return db.query(func.count(User.id)).filter(User.role == "admin", User.is_active.is_(True)).scalar() or 0


def _resolve_user(db: Session, user_id: int) -> User:
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    return target


@router.patch("/users/{user_id}")
def update_user(user_id: int, payload: UserUpdate, request: Request, db: Session = Depends(get_db),
                user: User = Depends(require_role("admin"))):
    target = _resolve_user(db, user_id)
    if target.id == user.id and payload.is_active is False:
        raise HTTPException(status_code=422, detail="You cannot deactivate your own account")
    would_empty_admins = (
        target.role == "admin" and target.is_active
        and ((payload.role is not None and payload.role != "admin") or payload.is_active is False)
        and _active_admin_count(db) <= 1
    )
    if would_empty_admins:
        raise HTTPException(status_code=422, detail="At least one active administrator must remain")
    changes = []
    for field, value in payload.model_dump(exclude_unset=True).items():
        if value is not None:
            setattr(target, field, value)
            changes.append(f"{field}={value}")
    audit(db, request, user, "user.updated", "user", str(target.id), ", ".join(changes) or "no changes")
    db.commit()
    return {"user": user_out(target), "message": "Account updated"}


@router.post("/users/{user_id}/reset-password")
def reset_password(user_id: int, payload: AdminPasswordReset, request: Request,
                   db: Session = Depends(get_db), user: User = Depends(require_role("admin"))):
    target = _resolve_user(db, user_id)
    problems = password_problems(payload.new_password)
    if problems:
        raise HTTPException(status_code=422, detail="Password must contain " + ", ".join(problems))
    target.password_hash = hash_password(payload.new_password)
    audit(db, request, user, "user.password.reset", "user", str(target.id), f"Password reset for {target.email}")
    db.commit()
    return {"message": f"Password reset for {target.email}. Existing tokens remain valid until expiry."}


@router.delete("/users/{user_id}")
def deactivate_user(user_id: int, request: Request, db: Session = Depends(get_db),
                    user: User = Depends(require_role("admin"))):
    target = _resolve_user(db, user_id)
    if target.id == user.id:
        raise HTTPException(status_code=422, detail="You cannot deactivate your own account")
    if target.role == "admin" and _active_admin_count(db) <= 1:
        raise HTTPException(status_code=422, detail="At least one active administrator must remain")
    target.is_active = False
    audit(db, request, user, "user.deactivated", "user", str(target.id), target.email)
    db.commit()
    return {"message": f"{target.email} deactivated"}


@router.get("/audit")
def audit_logs(
    q: str | None = None,
    action: str | None = None,
    entity: str | None = None,
    range_key: str = Query("30d", alias="range"),
    start: str | None = Query(None, alias="from"),
    end: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(require_role("admin")),
):
    start_dt, end_dt = ensure_range(range_key, start, end)
    query = db.query(AuditLog).filter(AuditLog.created_at >= start_dt, AuditLog.created_at <= end_dt)
    if q:
        pattern = f"%{q.strip()}%"
        query = query.filter(or_(AuditLog.user_email.ilike(pattern), AuditLog.detail.ilike(pattern),
                                 AuditLog.action.ilike(pattern), AuditLog.entity_id.ilike(pattern)))
    actions = split_multi(action)
    if actions:
        query = query.filter(AuditLog.action.in_(actions))
    entities = split_multi(entity)
    if entities:
        query = query.filter(AuditLog.entity_type.in_(entities))
    query = query.order_by(AuditLog.created_at.desc())
    result = paginate(query, page, size, lambda row: audit_out(row))
    distinct = db.query(AuditLog.action).distinct().all()
    result["actions"] = sorted({row[0] for row in distinct})
    return result


@router.get("/audit/export.csv")
def export_audit(
    range_key: str = Query("30d", alias="range"), start: str | None = Query(None, alias="from"),
    end: str | None = None, db: Session = Depends(get_db), user: User = Depends(require_role("admin")),
):
    start_dt, end_dt = ensure_range(range_key, start, end)
    rows = db.query(AuditLog).filter(
        AuditLog.created_at >= start_dt, AuditLog.created_at <= end_dt
    ).order_by(AuditLog.created_at.desc()).limit(10000).all()
    headers = ["created_at", "user_email", "action", "entity_type", "entity_id", "detail", "ip_address"]
    data = [[r.created_at.isoformat(), r.user_email, r.action, r.entity_type, r.entity_id, r.detail, r.ip_address]
            for r in rows]
    return StreamingResponse(
        iter([csv_response_bytes(headers, data)]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="cyberguard-audit-{utcnow().date()}.csv"'},
    )


@router.get("/classifier-quality")
def classifier_quality(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    records = db.query(ModelEvaluation).order_by(ModelEvaluation.evaluated_at.desc()).limit(20).all()
    latest = records[0] if records else None
    return {
        "latest": {
            "id": latest.id,
            "model_name": latest.model_name,
            "dataset_name": latest.dataset_name,
            "samples": latest.samples,
            "precision": latest.precision,
            "recall": latest.recall,
            "f1": latest.f1,
            "macro_f1": latest.macro_f1,
            "confusion": latest.confusion,
            "notes": latest.notes,
            "evaluated_at": latest.evaluated_at.isoformat(),
        } if latest else None,
        "history": [
            {
                "id": r.id, "model_name": r.model_name, "samples": r.samples, "precision": r.precision,
                "recall": r.recall, "f1": r.f1, "evaluated_at": r.evaluated_at.isoformat(),
            } for r in records
        ],
        "methods": [
            {"name": "Classification", "description": "Deterministic keyword lexicon with phrase weights over title and description."},
            {"name": "Entity extraction", "description": "Regular expressions for CVE IDs, IPs, domains, URLs, hashes, emails and MITRE technique IDs, plus a product lexicon."},
            {"name": "Summarisation", "description": "Extractive templating grounded in stored fields."},
            {"name": "Correlation", "description": "Weighted Jaccard similarity across entities, indicators, product and time proximity."},
            {"name": "Early warning", "description": "Five deterministic rules plus a two-sigma activity baseline, with evidence attached to every alert."},
        ],
        "note": (
            "Metrics are computed on a curated, author-labelled benchmark that was written alongside the lexicon. "
            "They measure coverage of those phrasings and are reported per run for reproducibility."
        ),
    }


@router.post("/classifier-quality/run")
def run_classifier_quality(request: Request, db: Session = Depends(get_db),
                           user: User = Depends(require_role("analyst"))):
    result = classifier.evaluate()
    record = ModelEvaluation(
        model_name=result["model_name"],
        dataset_name=result["dataset_name"],
        samples=result["samples"],
        precision=result["precision"],
        recall=result["recall"],
        f1=result["f1"],
        macro_f1=result["macro_f1"],
        confusion={"matrix": result["confusion"], "per_category": result["per_category"], "accuracy": result["accuracy"]},
        notes=result["notes"],
        evaluated_at=utcnow(),
    )
    db.add(record)
    audit(db, request, user, "classifier.evaluated", "classifier", result["model_name"],
          f"samples={result['samples']} macro_f1={result['macro_f1']}")
    db.commit()
    return {"evaluation": {**result, "id": record.id, "evaluated_at": record.evaluated_at.isoformat()}}


@router.get("/settings")
def admin_settings(db: Session = Depends(get_db), user: User = Depends(require_role("admin"))):
    configured = settings.connector_status()
    return {
        "environment": {
            "app_env": settings.app_env,
            "production": settings.is_production,
            "live_feeds": settings.enable_live_threat_feeds,
            "deepseek_ai": settings.deepseek_configured,
            "ai_analysis": settings.enable_ai_analysis,
            "email_alerts": settings.enable_email_alerts,
            "correlation": settings.enable_threat_correlation,
            "cors_origins": len(settings.cors_origin_list),
            "token_lifetime_minutes": settings.access_token_minutes,
        },
        "connectors": configured,
        "risk": risk.get_risk_config(db),
        "notification_policy": {
            "email_requires_smtp": True,
            "smtp_configured": bool(settings.smtp_host and settings.email_from),
            "note": "Users control email and critical-only notification preferences on their own profile. Delivery requires SMTP configuration on the server.",
        },
        "secret_policy": "Secrets are only read from environment variables. This endpoint returns configuration flags, never key values.",
    }


@router.get("/system")
def system_status(db: Session = Depends(get_db), user: User = Depends(require_role("admin"))):
    from ..database import engine

    table_counts = {
        "threats": db.query(func.count(Threat.id)).scalar() or 0,
        "vulnerabilities": db.query(func.count(Vulnerability.id)).scalar() or 0,
        "assets": db.query(func.count(Asset.id)).scalar() or 0,
        "alerts": db.query(func.count(Alert.id)).scalar() or 0,
        "recommendations": db.query(func.count(Recommendation.id)).scalar() or 0,
        "sources": db.query(func.count(ThreatSource.id)).scalar() or 0,
        "users": db.query(func.count(User.id)).scalar() or 0,
        "audit_events": db.query(func.count(AuditLog.id)).scalar() or 0,
        "classifier_runs": db.query(func.count(ModelEvaluation.id)).scalar() or 0,
    }
    return {
        "version": "1.0.0",
        "environment": settings.app_env,
        "python": platform.python_version(),
        "platform": platform.system(),
        "database_backend": engine.url.get_backend_name(),
        "table_counts": table_counts,
        "risk_model": risk.get_risk_config(db)["model_version"],
        "generated_at": utcnow().isoformat(),
    }
