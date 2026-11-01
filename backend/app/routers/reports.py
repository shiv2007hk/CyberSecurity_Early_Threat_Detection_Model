"""Threat-intelligence report generation and exports."""
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_user
from ..models import User
from ..services import reports
from .common import ensure_range

router = APIRouter(prefix="/reports", tags=["Reports"])

DESCRIPTIONS = {
    "daily": ("1d", "Last 24 hours", "Daily operational digest of new intelligence, alerts and immediate actions."),
    "weekly": ("7d", "Last 7 days", "Weekly trend review with exposure changes, emerging observations and priorities."),
    "monthly": ("30d", "Last 30 days", "Monthly strategic summary of the threat landscape and remediation performance."),
    "critical": ("14d", "Last 14 days", "Focused dossier on critical threats, known-exploited evidence and affected assets."),
    "exposure": ("30d", "Last 30 days", "Inventory exposure report linking validated vulnerabilities to registered assets."),
    "asset-risk": ("30d", "Current inventory", "Ranked asset risk assessment with evidence traceability."),
}


@router.get("")
def list_reports(user: User = Depends(get_current_user)):
    return {
        "types": [
            {
                "kind": kind,
                "title": title,
                "default_range": DESCRIPTIONS[kind][0],
                "range_label": DESCRIPTIONS[kind][1],
                "description": DESCRIPTIONS[kind][2],
                "formats": ["view", "csv", "pdf-print"],
            }
            for kind, (title, _) in reports.REPORT_TYPES.items()
        ],
        "disclaimer": (
            "Reports are generated from stored records. Every entry carries its source and retrieval timestamp, "
            "and each report is advisory: it does not direct or confirm any change to infrastructure."
        ),
    }


@router.get("/{kind}/export.csv")
def export_report(
    kind: str,
    range_key: str | None = Query(None, alias="range"),
    start: str | None = Query(None, alias="from"),
    end: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if kind not in reports.REPORT_TYPES:
        raise HTTPException(status_code=404, detail="Unknown report type")
    start_dt, end_dt = ensure_range(range_key or DESCRIPTIONS[kind][0], start, end)
    filename, payload = reports.report_csv(db, kind, start_dt, end_dt)
    return StreamingResponse(
        iter([payload]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{kind}")
def get_report(
    kind: str,
    range_key: str | None = Query(None, alias="range"),
    start: str | None = Query(None, alias="from"),
    end: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if kind not in reports.REPORT_TYPES:
        raise HTTPException(status_code=404, detail="Unknown report type")
    start_dt, end_dt = ensure_range(range_key or DESCRIPTIONS[kind][0], start, end)
    report = reports.build_report(db, kind, start_dt, end_dt, user)
    return report
