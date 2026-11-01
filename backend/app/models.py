"""SQLAlchemy domain model for the CyberGuard AI platform."""
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from .database import Base
from .utils import utcnow


class Organisation(Base):
    __tablename__ = "organisations"

    id = Column(Integer, primary_key=True)
    name = Column(String(160), unique=True, nullable=False)
    sector = Column(String(80), nullable=False)
    country = Column(String(80), nullable=False, default="India")
    created_at = Column(DateTime, default=utcnow, nullable=False)

    users = relationship("User", back_populates="organisation")
    assets = relationship("Asset", back_populates="organisation")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(120), nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="viewer")  # admin | analyst | viewer
    organisation_id = Column(Integer, ForeignKey("organisations.id", ondelete="SET NULL"))
    is_active = Column(Boolean, default=True, nullable=False)
    notification_email = Column(Boolean, default=True, nullable=False)
    notification_critical_only = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    last_login_at = Column(DateTime)

    organisation = relationship("Organisation", back_populates="users")


class ThreatSource(Base):
    __tablename__ = "threat_sources"

    id = Column(Integer, primary_key=True)
    key = Column(String(40), unique=True, nullable=False)
    name = Column(String(120), nullable=False)
    description = Column(Text, default="")
    url = Column(String(300), default="")
    category = Column(String(40), default="vulnerability")
    requires_key = Column(Boolean, default=False)
    key_configured = Column(Boolean, default=False)
    enabled = Column(Boolean, default=True)
    status = Column(String(30), default="operational")  # operational|degraded|unavailable|disabled|awaiting_key
    reliability = Column(Integer, default=80)
    last_sync_at = Column(DateTime)
    last_success_at = Column(DateTime)
    items_ingested = Column(Integer, default=0)
    latency_ms = Column(Integer)
    last_message = Column(Text, default="")


class Threat(Base):
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True)
    ref = Column(String(24), unique=True, nullable=False, index=True)
    name = Column(String(240), nullable=False)
    category = Column(String(60), nullable=False, index=True)
    description = Column(Text, nullable=False)
    source = Column(String(80), nullable=False, index=True)
    source_url = Column(String(400), default="")
    published_at = Column(DateTime, nullable=False, index=True)
    updated_at = Column(DateTime, nullable=False, default=utcnow)
    cve_id = Column(String(24), index=True)
    cvss_score = Column(Float)
    cvss_severity = Column(String(16))
    epss_score = Column(Float)
    known_exploited = Column(Boolean, default=False)
    affected_technology = Column(String(120))
    affected_versions = Column(String(120))
    indicators = Column(JSON, default=list)
    source_reliability = Column(Integer, default=80)
    evidence_refs = Column(JSON, default=list)
    ai_summary = Column(Text, default="")
    ai_category = Column(String(60))
    ai_confidence = Column(Float)
    ai_keywords = Column(JSON, default=list)
    ai_entities = Column(JSON, default=dict)
    ai_explanation = Column(JSON, default=dict)
    ai_method = Column(String(60), default="keyword-lexicon")
    risk_score = Column(Float, default=0)
    risk_category = Column(String(16), default="Low")
    confidence = Column(Float, default=0)  # evidence confidence 0-100
    urgency = Column(String(16), default="routine")
    exploitation_status = Column(String(30), default="unknown")
    recommended_action = Column(Text, default="")
    severity = Column(String(16), nullable=False, index=True)
    status = Column(String(24), default="new", index=True)  # new|investigating|resolved|dismissed
    assigned_to = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    is_saved = Column(Boolean, default=False)
    is_simulated = Column(Boolean, default=False, index=True)
    retrieval_timestamp = Column(DateTime, default=utcnow)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    __table_args__ = (
        Index("ix_threats_sev_pub", "severity", "published_at"),
        Index("ix_threats_cat_pub", "category", "published_at"),
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True)
    cve_id = Column(String(24), unique=True, nullable=False, index=True)
    title = Column(String(260), nullable=False)
    description = Column(Text, nullable=False)
    cvss_score = Column(Float)
    cvss_severity = Column(String(16), index=True)
    epss_score = Column(Float)
    epss_percentile = Column(Float)
    known_exploited = Column(Boolean, default=False, index=True)
    kev_due_date = Column(DateTime)
    ransomware_use = Column(Boolean, default=False)
    published_at = Column(DateTime, nullable=False, index=True)
    modified_at = Column(DateTime, nullable=False, default=utcnow)
    affected_products = Column(JSON, default=list)
    references = Column(JSON, default=list)
    source = Column(String(80), default="NVD")
    source_url = Column(String(400), default="")
    remediation = Column(Text, default="")
    is_simulated = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True)
    ref = Column(String(24), unique=True, nullable=False, index=True)
    name = Column(String(160), nullable=False)
    category = Column(String(60), nullable=False, index=True)
    organisation_id = Column(Integer, ForeignKey("organisations.id", ondelete="SET NULL"))
    identifier = Column(String(120), default="")
    software = Column(String(120), nullable=False, index=True)
    software_version = Column(String(60), nullable=False)
    os = Column(String(100), default="")
    exposure = Column(String(30), default="internal")  # internet-facing | internal | air-gapped
    internet_facing = Column(Boolean, default=False)
    criticality = Column(Integer, default=3)  # 1-5
    business_importance = Column(String(30), default="standard")
    owner = Column(String(120), default="")
    last_assessed_at = Column(DateTime, default=utcnow)
    notes = Column(Text, default="")
    is_simulated = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    organisation = relationship("Organisation", back_populates="assets")


class AssetVulnerability(Base):
    __tablename__ = "asset_vulnerabilities"

    id = Column(Integer, primary_key=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False)
    match_confidence = Column(Float, default=0)
    match_reason = Column(Text, default="")
    status = Column(String(30), default="potentially_exposed")
    created_at = Column(DateTime, default=utcnow, nullable=False)

    __table_args__ = (UniqueConstraint("asset_id", "vulnerability_id", name="uq_asset_vuln"),)


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id = Column(Integer, primary_key=True)
    ref = Column(String(24), unique=True, nullable=False)
    threat_id = Column(Integer, ForeignKey("threats.id", ondelete="CASCADE"))
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"))
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"))
    severity = Column(Float, default=0)
    exploitability = Column(Float, default=0)
    exposure = Column(Float, default=0)
    asset_criticality = Column(Float, default=0)
    evidence_strength = Column(Float, default=0)
    risk_score = Column(Float, default=0)
    risk_category = Column(String(16), default="Low")
    urgency = Column(String(16), default="routine")
    exploitation_status = Column(String(30), default="unknown")
    evidence_confidence = Column(Float, default=0)
    factors = Column(JSON, default=list)
    explanation = Column(Text, default="")
    model_version = Column(String(30), default="aegis-risk-v1")
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    created_at = Column(DateTime, default=utcnow, nullable=False, index=True)


class ThreatCorrelation(Base):
    __tablename__ = "threat_correlations"

    id = Column(Integer, primary_key=True)
    threat_a_id = Column(Integer, ForeignKey("threats.id", ondelete="CASCADE"), nullable=False)
    threat_b_id = Column(Integer, ForeignKey("threats.id", ondelete="CASCADE"), nullable=False)
    score = Column(Float, default=0)
    reasons = Column(JSON, default=list)
    method = Column(String(40), default="entity-overlap")
    created_at = Column(DateTime, default=utcnow, nullable=False)

    __table_args__ = (UniqueConstraint("threat_a_id", "threat_b_id", name="uq_correlation_pair"),)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)
    ref = Column(String(24), unique=True, nullable=False, index=True)
    title = Column(String(260), nullable=False)
    severity = Column(String(16), nullable=False, index=True)
    category = Column(String(60), nullable=False)
    detected_at = Column(DateTime, default=utcnow, nullable=False, index=True)
    threat_id = Column(Integer, ForeignKey("threats.id", ondelete="SET NULL"))
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id", ondelete="SET NULL"))
    asset_ids = Column(JSON, default=list)
    source = Column(String(80), default="")
    risk_score = Column(Float, default=0)
    confidence = Column(Float, default=0)
    trigger_reason = Column(Text, default="")
    evidence = Column(JSON, default=list)
    recommended_action = Column(Text, default="")
    status = Column(String(24), default="new", index=True)  # new|acknowledged|investigating|resolved|dismissed
    assignee_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    acknowledged_at = Column(DateTime)
    resolved_at = Column(DateTime)
    rule_key = Column(String(40), default="", index=True)
    fingerprint = Column(String(80), default="", index=True)
    is_simulated = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class Recommendation(Base):
    __tablename__ = "recommendations"

    id = Column(Integer, primary_key=True)
    ref = Column(String(24), unique=True, nullable=False)
    title = Column(String(240), nullable=False)
    reason = Column(Text, default="")
    priority = Column(String(16), default="medium", index=True)  # critical|high|medium|low
    threat_id = Column(Integer, ForeignKey("threats.id", ondelete="SET NULL"))
    vulnerability_id = Column(Integer, ForeignKey("vulnerabilities.id", ondelete="SET NULL"))
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="SET NULL"))
    alert_id = Column(Integer, ForeignKey("alerts.id", ondelete="SET NULL"))
    action = Column(Text, nullable=False)
    evidence = Column(JSON, default=list)
    status = Column(String(24), default="open", index=True)  # open|in_progress|done|dismissed
    owner_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    due_at = Column(DateTime)
    source_url = Column(String(400), default="")
    created_at = Column(DateTime, default=utcnow, nullable=False)


class AnalystNote(Base):
    __tablename__ = "analyst_notes"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    threat_id = Column(Integer, ForeignKey("threats.id", ondelete="CASCADE"))
    alert_id = Column(Integer, ForeignKey("alerts.id", ondelete="CASCADE"))
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"))
    body = Column(Text, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)


class IngestionLog(Base):
    __tablename__ = "ingestion_logs"

    id = Column(Integer, primary_key=True)
    source_key = Column(String(40), nullable=False, index=True)
    started_at = Column(DateTime, default=utcnow, nullable=False)
    finished_at = Column(DateTime)
    status = Column(String(20), default="success")
    mode = Column(String(20), default="recorded")  # live | cached | recorded
    items_found = Column(Integer, default=0)
    items_new = Column(Integer, default=0)
    message = Column(Text, default="")
    duration_ms = Column(Integer, default=0)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    user_email = Column(String(255), default="")
    action = Column(String(80), nullable=False, index=True)
    entity_type = Column(String(40), default="")
    entity_id = Column(String(40), default="")
    detail = Column(Text, default="")
    ip_address = Column(String(64), default="")
    created_at = Column(DateTime, default=utcnow, nullable=False, index=True)


class ModelEvaluation(Base):
    __tablename__ = "model_evaluations"

    id = Column(Integer, primary_key=True)
    model_name = Column(String(80), nullable=False)
    dataset_name = Column(String(120), nullable=False)
    samples = Column(Integer, default=0)
    precision = Column(Float, default=0)
    recall = Column(Float, default=0)
    f1 = Column(Float, default=0)
    macro_f1 = Column(Float, default=0)
    confusion = Column(JSON, default=dict)
    notes = Column(Text, default="")
    evaluated_at = Column(DateTime, default=utcnow, nullable=False)


class Setting(Base):
    __tablename__ = "settings"

    key = Column(String(80), primary_key=True)
    value = Column(JSON, nullable=False)
    updated_at = Column(DateTime, default=utcnow, nullable=False)


class ChatConversation(Base):
    """A persisted Aegis AI chat thread, owned by exactly one user."""

    __tablename__ = "chat_conversations"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(200), nullable=False, default="New chat")
    title_source = Column(String(20), default="placeholder")  # placeholder|question
    model = Column(String(60), default="")
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, nullable=False, index=True)

    messages = relationship(
        "ChatMessage",
        back_populates="conversation",
        cascade="all, delete-orphan",
        order_by="ChatMessage.id",
    )


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id = Column(Integer, primary_key=True)
    conversation_id = Column(Integer, ForeignKey("chat_conversations.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String(12), nullable=False)  # user|assistant
    content = Column(Text, nullable=False, default="")
    citations = Column(JSON, default=list)
    record_count = Column(Integer, default=0)
    status = Column(String(16), default="complete")  # complete|failed|stopped|incomplete
    error = Column(Text, default="")
    model = Column(String(60), default="")
    latency_ms = Column(Integer)
    created_at = Column(DateTime, default=utcnow, nullable=False)

    conversation = relationship("ChatConversation", back_populates="messages")

    __table_args__ = (Index("ix_chat_messages_conv_created", "conversation_id", "created_at"),)

