"""Authentication, registration, profile and role-account endpoints."""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..deps import audit, clear_login_rate, get_current_user, login_rate_check, login_rate_record
from ..models import Organisation, User, utcnow
from ..schemas import LoginRequest, PasswordChange, ProfileUpdate, RegisterRequest
from ..security import create_access_token, hash_password, password_problems, verify_password
from ..serializers import user_out

router = APIRouter(prefix="/auth", tags=["Authentication"])

ROLE_ACCOUNTS = [
    {"role": "Administrator", "email": "admin@aegissentinel.ai", "password": "AegisAdmin#2026"},
    {"role": "Security Analyst", "email": "analyst@aegissentinel.ai", "password": "AegisAnalyst#2026"},
    {"role": "Viewer", "email": "viewer@aegissentinel.ai", "password": "AegisViewer#2026"},
]


@router.post("/login")
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    key = f"{(request.client.host if request.client else 'unknown')}:{email}"
    login_rate_check(key)
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(payload.password, user.password_hash):
        login_rate_record(key)
        audit(db, request, user, "auth.login.failed", "user", str(user.id) if user else "", "Invalid credentials")
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="This account is inactive. Contact an administrator.")
    clear_login_rate(key)
    user.last_login_at = utcnow()
    audit(db, request, user, "auth.login", "user", str(user.id), "Successful login")
    db.commit()
    token, expires_in = create_access_token(user.id, user.email, user.role)
    return {"access_token": token, "token_type": "bearer", "expires_in": expires_in, "user": user_out(user)}


@router.post("/register")
def register(payload: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    email = payload.email.lower().strip()
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    problems = password_problems(payload.password)
    if problems:
        raise HTTPException(status_code=422, detail="Password must contain " + ", ".join(problems))
    org = db.get(Organisation, payload.organisation_id) if payload.organisation_id else db.query(Organisation).first()
    user = User(
        email=email,
        full_name=payload.full_name.strip(),
        password_hash=hash_password(payload.password),
        role="viewer",
        organisation_id=org.id if org else None,
        is_active=True,
        created_at=utcnow(),
        last_login_at=utcnow(),
    )
    db.add(user)
    db.flush()
    audit(db, request, user, "auth.register", "user", str(user.id), "Self-service viewer account created")
    db.commit()
    token, expires_in = create_access_token(user.id, user.email, user.role)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": expires_in,
        "user": user_out(user),
        "note": "New self-service accounts receive viewer permissions. An administrator can elevate the role.",
    }


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return user_out(user)


@router.patch("/profile")
def update_profile(payload: ProfileUpdate, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    changed = []
    for field in ("full_name", "notification_email", "notification_critical_only"):
        value = getattr(payload, field)
        if value is not None:
            setattr(user, field, value)
            changed.append(field)
    audit(db, request, user, "profile.update", "user", str(user.id), f"Updated: {', '.join(changed) or 'none'}")
    db.commit()
    return user_out(user)


@router.post("/change-password")
def change_password(payload: PasswordChange, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    problems = password_problems(payload.new_password)
    if problems:
        raise HTTPException(status_code=422, detail="New password must contain " + ", ".join(problems))
    user.password_hash = hash_password(payload.new_password)
    audit(db, request, user, "auth.password.changed", "user", str(user.id), "Password changed")
    db.commit()
    return {"message": "Password updated. Existing JWTs remain valid until expiry."}


@router.post("/logout")
def logout(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    audit(db, request, user, "auth.logout", "user", str(user.id), "Client session cleared")
    db.commit()
    return {"message": "Signed out"}


@router.get("/role-accounts")
def role_accounts():
    if settings.is_production:
        raise HTTPException(status_code=404, detail="Role accounts are disabled in production")
    return {"accounts": ROLE_ACCOUNTS}
