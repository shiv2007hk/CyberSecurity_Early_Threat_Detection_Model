"""FastAPI dependencies: authentication, RBAC, rate limiting, auditing."""
import time
from collections import defaultdict, deque

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .database import get_db
from .models import AuditLog, User, utcnow
from .security import decode_access_token

bearer = HTTPBearer(auto_error=False)

ROLE_RANK = {"viewer": 1, "analyst": 2, "admin": 3}

_attempts: dict[str, deque] = defaultdict(deque)
_LOGIN_WINDOW = 300
_LOGIN_MAX = 9


def login_rate_check(key: str) -> None:
    now = time.time()
    bucket = _attempts[key]
    while bucket and now - bucket[0] > _LOGIN_WINDOW:
        bucket.popleft()
    if len(bucket) >= _LOGIN_MAX:
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again in a few minutes.")


def login_rate_record(key: str) -> None:
    _attempts[key].append(time.time())


def clear_login_rate(key: str) -> None:
    _attempts.pop(key, None)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    payload = decode_access_token(credentials.credentials)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired session")
    user = db.get(User, int(payload.get("sub", 0)))
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account is inactive")
    return user


def require_role(minimum: str):
    def dependency(user: User = Depends(get_current_user)) -> User:
        if ROLE_RANK.get(user.role, 0) < ROLE_RANK[minimum]:
            raise HTTPException(status_code=403, detail=f"Requires {minimum} privileges")
        return user

    return dependency


def audit(db: Session, request: Request | None, user: User | None, action: str, entity_type: str = "",
          entity_id: str = "", detail: str = "") -> None:
    entry = AuditLog(
        user_id=user.id if user else None,
        user_email=user.email if user else "anonymous",
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id),
        detail=detail[:2000],
        ip_address=(request.client.host if request and request.client else ""),
        created_at=utcnow(),
    )
    db.add(entry)
