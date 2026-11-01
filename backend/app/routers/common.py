"""Shared router helpers."""
import math
from datetime import datetime

from fastapi import HTTPException


def paginate(query, page: int, size: int, serializer):
    total = query.count()
    pages = max(1, math.ceil(total / size)) if total else 0
    items = query.offset((page - 1) * size).limit(size).all()
    return {
        "items": [serializer(item) for item in items],
        "total": total,
        "page": page,
        "size": size,
        "pages": pages,
    }


def split_multi(value: str | None) -> list[str]:
    if not value:
        return []
    return [part.strip() for part in value.split(",") if part.strip()]


def ensure_range(range_key: str | None, start: str | None, end: str | None):
    from ..utils import parse_range, parse_dt

    if range_key == "all":
        return datetime(2000, 1, 1), parse_dt(end) or datetime(2100, 1, 1)
    if range_key == "custom" and not start:
        raise HTTPException(status_code=422, detail="Custom range requires a start date")
    return parse_range(range_key, start, end)


def serialize_facets(rows, attr: str) -> list[dict]:
    counts: dict[str, int] = {}
    for row in rows:
        value = getattr(row, attr) or "unknown"
        counts[value] = counts.get(value, 0) + 1
    return [{"name": name, "count": count} for name, count in sorted(counts.items(), key=lambda kv: kv[1], reverse=True)]
