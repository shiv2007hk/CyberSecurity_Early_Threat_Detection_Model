"""Pydantic request models and validation."""
from typing import Literal

from pydantic import BaseModel, EmailStr, Field, field_validator


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=200)


class RegisterRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(min_length=10, max_length=200)
    organisation_id: int | None = None


class ProfileUpdate(BaseModel):
    full_name: str | None = Field(default=None, min_length=2, max_length=120)
    notification_email: bool | None = None
    notification_critical_only: bool | None = None


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=10, max_length=200)


class ThreatUpdate(BaseModel):
    status: Literal["new", "investigating", "resolved", "dismissed"] | None = None
    is_saved: bool | None = None
    assigned_to: int | None = None


class AssetPayload(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    category: str = Field(min_length=2, max_length=60)
    organisation_id: int | None = None
    identifier: str = Field(default="", max_length=120)
    software: str = Field(min_length=1, max_length=120)
    software_version: str = Field(default="", max_length=60)
    os: str = Field(default="", max_length=100)
    exposure: Literal["internet-facing", "internal", "air-gapped"] = "internal"
    criticality: int = Field(default=3, ge=1, le=5)
    business_importance: str = Field(default="standard", max_length=30)
    owner: str = Field(default="", max_length=120)
    notes: str = Field(default="", max_length=2000)


class AssetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=160)
    category: str | None = None
    organisation_id: int | None = None
    identifier: str | None = None
    software: str | None = None
    software_version: str | None = None
    os: str | None = None
    exposure: Literal["internet-facing", "internal", "air-gapped"] | None = None
    criticality: int | None = Field(default=None, ge=1, le=5)
    business_importance: str | None = None
    owner: str | None = None
    notes: str | None = None


class AssetImport(BaseModel):
    csv_text: str = Field(min_length=5, max_length=500_000)


class MatchUpdate(BaseModel):
    status: Literal["confirmed", "not_affected", "needs_verification", "potentially_exposed"]
    note: str = Field(default="", max_length=1000)


class AlertUpdate(BaseModel):
    status: Literal["new", "acknowledged", "investigating", "resolved", "dismissed"] | None = None
    assignee_id: int | None = None


class RecommendationUpdate(BaseModel):
    status: Literal["open", "in_progress", "done", "dismissed"] | None = None
    owner_id: int | None = None
    due_in_days: int | None = Field(default=None, ge=1, le=365)


class NoteCreate(BaseModel):
    body: str = Field(min_length=2, max_length=4000)
    threat_id: int | None = None
    alert_id: int | None = None
    asset_id: int | None = None


class RiskWeights(BaseModel):
    severity: float = Field(ge=0, le=1)
    exploitability: float = Field(ge=0, le=1)
    exposure: float = Field(ge=0, le=1)
    asset_criticality: float = Field(ge=0, le=1)
    evidence_strength: float = Field(ge=0, le=1)


class RiskThresholds(BaseModel):
    medium: float = Field(ge=0, le=100)
    high: float = Field(gt=0, le=100)
    critical: float = Field(gt=0, le=100)


class RiskConfigUpdate(BaseModel):
    weights: RiskWeights
    thresholds: RiskThresholds


class RiskAssessRequest(BaseModel):
    threat_id: int
    asset_id: int | None = None


class RiskFeedback(BaseModel):
    assessment_id: int
    verdict: Literal["agree", "needs_review", "incorrect"]
    note: str = Field(min_length=5, max_length=2000)


class SourceToggle(BaseModel):
    enabled: bool


class EnrichmentRequest(BaseModel):
    indicator_type: Literal["ip", "domain", "url", "sha256"]
    value: str = Field(min_length=3, max_length=500)


class UserCreate(BaseModel):
    full_name: str = Field(min_length=2, max_length=120)
    email: EmailStr
    password: str = Field(min_length=10, max_length=200)
    role: Literal["admin", "analyst", "viewer"] = "analyst"
    organisation_id: int | None = None


class UserUpdate(BaseModel):
    full_name: str | None = Field(default=None, min_length=2, max_length=120)
    role: Literal["admin", "analyst", "viewer"] | None = None
    is_active: bool | None = None
    notification_email: bool | None = None
    notification_critical_only: bool | None = None


class AdminPasswordReset(BaseModel):
    new_password: str = Field(min_length=10, max_length=200)


class SettingUpdate(BaseModel):
    key: str = Field(pattern=r"^[a-z0-9_.-]{2,80}$")
    value: dict | list | str | int | float | bool | None = None

    @field_validator("key")
    @classmethod
    def protect_keys(cls, value: str) -> str:
        if value in {"risk_weights"}:
            raise ValueError("Use the risk configuration endpoint for this setting")
        return value
