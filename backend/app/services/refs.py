"""Collision-safe sequential reference generation."""
from ..models import utcnow


def next_ref(db, model, prefix: str, width: int = 4) -> str:
    year = utcnow().year
    used = {row[0] for row in db.query(model.ref).all()}
    used |= {obj.ref for obj in db.new if isinstance(obj, model) and getattr(obj, "ref", None)}
    number = len(used) + 1
    while f"{prefix}-{year}-{number:0{width}d}" in used:
        number += 1
    return f"{prefix}-{year}-{number:0{width}d}"
