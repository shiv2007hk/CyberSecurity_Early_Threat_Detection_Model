"""Shared helpers: time windows, version comparison, CSV rendering."""
import csv
import io
import re
from datetime import datetime, timedelta, timezone

RANGE_DELTAS = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "90d": timedelta(days=90),
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc).replace(tzinfo=None) if parsed.tzinfo else parsed
    except ValueError:
        return None


def parse_range(range_key: str | None = "30d", start: str | None = None, end: str | None = None):
    end_dt = parse_dt(end) or utcnow()
    if range_key == "custom":
        start_dt = parse_dt(start) or (end_dt - RANGE_DELTAS["30d"])
    else:
        start_dt = end_dt - RANGE_DELTAS.get(range_key or "30d", RANGE_DELTAS["30d"])
    if start_dt > end_dt:
        start_dt, end_dt = end_dt, start_dt
    return start_dt, end_dt


def parse_version(value: str | None) -> tuple[int, ...]:
    if not value:
        return ()
    numbers = re.findall(r"\d+", str(value))
    return tuple(int(n) for n in numbers[:5])


def version_in_range(version: str, start: str | None, end: str | None) -> bool:
    parsed = parse_version(version)
    if not parsed:
        return False
    if start and parsed < parse_version(start):
        return False
    if end and parsed > parse_version(end):
        return False
    return True


def version_matches(version: str, spec: dict) -> bool:
    """Check a version against a structured affected-version spec."""
    if spec.get("all_versions"):
        return True
    exact = spec.get("exact") or []
    if exact and str(version).strip().lower() in {str(v).lower() for v in exact}:
        return True
    if spec.get("start") or spec.get("end"):
        return version_in_range(version, spec.get("start"), spec.get("end"))
    return False


def csv_response_bytes(headers: list[str], rows: list[list]) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(headers)
    for row in rows:
        writer.writerow(["" if v is None else v for v in row])
    return buffer.getvalue().encode("utf-8-sig")


def clamp(value: float, low: float = 0, high: float = 10) -> float:
    return max(low, min(high, value))


def risk_category(score: float) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def severity_from_cvss(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "informational"
