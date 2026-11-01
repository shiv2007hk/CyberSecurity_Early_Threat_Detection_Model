"""Packaged threat scenarios that exercise the full detection pipeline."""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import audit, get_current_user, require_role
from ..models import Alert, Asset, AuditLog, Threat, User, Vulnerability
from ..services import scenario_library

router = APIRouter(prefix="/scenarios", tags=["Threat scenarios"])


@router.get("")
def scenarios(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    recent_runs = (
        db.query(AuditLog)
        .filter(AuditLog.action == "scenario.run")
        .order_by(AuditLog.created_at.desc())
        .limit(10)
        .all()
    )
    return {
        "scenarios": [
            {"key": key, "title": value["title"], "description": value["description"]}
            for key, value in scenario_library.SCENARIOS.items()
        ],
        "record_counts": {
            "threat_records": db.query(func.count(Threat.id)).scalar() or 0,
            "vulnerability_records": db.query(func.count(Vulnerability.id)).scalar() or 0,
            "alert_records": db.query(func.count(Alert.id)).scalar() or 0,
            "asset_records": db.query(func.count(Asset.id)).scalar() or 0,
        },
        "recent_runs": [
            {"scenario": row.entity_id, "at": row.created_at.isoformat(), "by": row.user_email, "detail": row.detail}
            for row in recent_runs
        ],
    }


@router.post("/{key}/run")
def run_scenario(key: str, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require_role("analyst"))):
    if key not in scenario_library.SCENARIOS:
        raise HTTPException(status_code=404, detail="Unknown scenario")
    try:
        result = scenario_library.run(db, key, user)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    audit(db, request, user, "scenario.run", "scenario", key, result.get("summary", key))
    db.commit()
    return result
