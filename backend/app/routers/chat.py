"""Aegis AI chat: streaming DeepSeek replies grounded in retrieved platform records."""
from __future__ import annotations

import json
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..config import settings
from ..database import SessionLocal, get_db
from ..deps import audit, get_current_user, require_role
from ..models import ChatConversation, ChatMessage, Setting, User, utcnow
from ..services import chat as chat_service
from ..services import chat_retrieval, deepseek

router = APIRouter(prefix="/chat", tags=["Aegis AI"])

PROBE_KEY = "deepseek_probe"
MAX_HISTORY_TURNS = 40
RATE_WINDOW = 60
RATE_MAX = 12
FLUSH_EVERY = 10


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    conversation_id: int | None = None


class ConversationCreate(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=120)


_buckets: dict[int, deque] = defaultdict(deque)


def _rate_limit(user: User) -> None:
    """Chat spends provider credit, so it gets a tighter budget than the global API limit."""
    now = time.time()
    bucket = _buckets[user.id]
    while bucket and now - bucket[0] > RATE_WINDOW:
        bucket.popleft()
    if len(bucket) >= RATE_MAX:
        retry = int(bucket[0] + RATE_WINDOW - now) + 1 if bucket else RATE_WINDOW
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Chat rate limit reached ({RATE_MAX} messages per {RATE_WINDOW}s). Try again in {retry}s.",
            headers={"Retry-After": str(retry)},
        )
    bucket.append(now)


def _iso(value: datetime | None) -> str | None:
    if not value:
        return None
    return value.isoformat() + "Z" if value.tzinfo is None else value.isoformat()


def _stored_probe(db: Session) -> dict | None:
    row = db.get(Setting, PROBE_KEY)
    return row.value if row and isinstance(row.value, dict) else None


def _remember_probe(db: Session, result: dict) -> None:
    payload = {k: v for k, v in result.items() if k in {
        "state", "connected", "kind", "detail", "status_code", "latency_ms", "tested_at", "model", "host"
    }}
    row = db.get(Setting, PROBE_KEY)
    if row:
        row.value = payload
        row.updated_at = utcnow()
    else:
        db.add(Setting(key=PROBE_KEY, value=payload, updated_at=utcnow()))


def _status_payload(db: Session) -> dict:
    """Connection state comes from a real probe. Key presence alone never reports 'connected'."""
    probe = _stored_probe(db)
    payload = {
        "provider": "deepseek",
        "model": settings.deepseek_model,
        "host": settings.deepseek_host,
        "key_configured": settings.deepseek_configured,
        "state": "untested",
        "connected": False,
        "kind": "",
        "detail": "",
        "latency_ms": None,
        "tested_at": None,
        "message": "No connection test has run yet, so connectivity is unknown.",
    }
    if not settings.deepseek_configured:
        payload.update(state="missing_key", kind=deepseek.NOT_CONFIGURED,
                       message=deepseek.message_for(deepseek.NOT_CONFIGURED))
        return payload
    if probe:
        payload.update(
            state="connected" if probe.get("connected") else "error",
            connected=bool(probe.get("connected")),
            kind=probe.get("kind", ""),
            detail="",
            latency_ms=probe.get("latency_ms"),
            tested_at=probe.get("tested_at"),
            message=(
                "Last test succeeded against the configured model."
                if probe.get("connected")
                else deepseek.message_for(probe.get("kind", "") or "provider_error")
            ),
        )
    return payload


def _owned(db: Session, conversation_id: int, user: User) -> ChatConversation:
    conversation = db.get(ChatConversation, conversation_id)
    # A wrong id and someone else's id answer identically: existence is not leaked.
    if not conversation or conversation.user_id != user.id:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return conversation


def _conversation_out(db: Session, conversation: ChatConversation) -> dict:
    count = db.query(ChatMessage).filter(ChatMessage.conversation_id == conversation.id).count()
    return {
        "id": conversation.id,
        "title": conversation.title,
        "model": conversation.model,
        "message_count": count,
        "created_at": _iso(conversation.created_at),
        "updated_at": _iso(conversation.updated_at),
    }


def _message_out(message: ChatMessage) -> dict:
    return {
        "id": message.id,
        "role": message.role,
        "content": message.content,
        "citations": message.citations or [],
        "record_count": message.record_count or 0,
        "status": message.status,
        "error": message.error or "",
        "model": message.model,
        "latency_ms": message.latency_ms,
        "created_at": _iso(message.created_at),
    }


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"


@router.get("/status")
def connection_status(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return _status_payload(db)


@router.post("/status/test")
def test_connection(request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Make one real request to DeepSeek and report exactly what came back."""
    result = deepseek.probe()
    _remember_probe(db, result)
    audit(db, request, user, "chat.status.test", "chat", settings.deepseek_model,
          "connected" if result["connected"] else result["kind"])
    db.commit()
    return {**_status_payload(db), "probe": {
        "connected": result["connected"],
        "kind": result["kind"],
        "detail": result["detail"],
        "status_code": result["status_code"],
        "latency_ms": result["latency_ms"],
    }}


@router.get("/suggestions")
def suggestions(user: User = Depends(get_current_user)):
    """The four entry points the console offers on an empty chat."""
    return {
        "suggestions": [
            "Analyse my highest-risk vulnerabilities.",
            "Summarise the latest threat intelligence.",
            "Identify the most exposed organisational assets.",
            "Explain the latest attack simulation results.",
        ]
    }


@router.get("/conversations")
def list_conversations(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    rows = (
        db.query(ChatConversation)
        .filter(ChatConversation.user_id == user.id)
        .order_by(ChatConversation.updated_at.desc())
        .limit(100)
        .all()
    )
    return {"items": [_conversation_out(db, row) for row in rows]}


@router.post("/conversations")
def create_conversation(payload: ConversationCreate, db: Session = Depends(get_db),
                        user: User = Depends(get_current_user)):
    conversation = ChatConversation(
        user_id=user.id,
        title=(payload.title or "New chat").strip()[:120],
        title_source="placeholder" if not payload.title else "manual",
        model=settings.deepseek_model,
    )
    db.add(conversation)
    db.commit()
    db.refresh(conversation)
    return _conversation_out(db, conversation)


@router.get("/conversations/{conversation_id}")
def get_conversation(conversation_id: int, db: Session = Depends(get_db),
                     user: User = Depends(get_current_user)):
    conversation = _owned(db, conversation_id, user)
    messages = (
        db.query(ChatMessage)
        .filter(ChatMessage.conversation_id == conversation.id)
        .order_by(ChatMessage.id.asc())
        .limit(MAX_HISTORY_TURNS * 2)
        .all()
    )
    return {**_conversation_out(db, conversation), "messages": [_message_out(m) for m in messages]}


@router.delete("/conversations/{conversation_id}")
def delete_conversation(conversation_id: int, request: Request, db: Session = Depends(get_db),
                        user: User = Depends(get_current_user)):
    conversation = _owned(db, conversation_id, user)
    audit(db, request, user, "chat.conversation.delete", "chat", conversation.id, conversation.title)
    db.delete(conversation)
    db.commit()
    return {"deleted": conversation_id}


@router.post("/conversations/{conversation_id}/clear")
def clear_conversation(conversation_id: int, request: Request, db: Session = Depends(get_db),
                       user: User = Depends(get_current_user)):
    conversation = _owned(db, conversation_id, user)
    deleted = db.query(ChatMessage).filter(ChatMessage.conversation_id == conversation.id).delete()
    conversation.title = "New chat"
    conversation.title_source = "placeholder"
    conversation.updated_at = utcnow()
    audit(db, request, user, "chat.conversation.clear", "chat", conversation.id, f"{deleted} messages")
    db.commit()
    return {**_conversation_out(db, conversation), "messages": []}


def _history(db: Session, conversation_id: int) -> list[dict]:
    rows = (
        db.query(ChatMessage)
        .filter(
            ChatMessage.conversation_id == conversation_id,
            ChatMessage.role.in_(["user", "assistant"]),
            ChatMessage.status.in_(["complete", "stopped"]),
        )
        .order_by(ChatMessage.id.desc())
        .limit(MAX_HISTORY_TURNS * 2)
        .all()
    )
    return [{"role": r.role, "content": r.content} for r in reversed(rows)]


@router.post("/stream")
def stream(request: Request, payload: ChatRequest, user: User = Depends(require_role("analyst"))):
    """Stream one grounded reply.

    The request-scoped session closes before a StreamingResponse is consumed, so the
    generator opens and owns its own.
    """
    _rate_limit(user)
    message = payload.message.strip()
    if not message:
        raise HTTPException(status_code=422, detail="Message must not be empty")

    seed = SessionLocal()
    try:
        if payload.conversation_id is None:
            conversation = ChatConversation(user_id=user.id, title="New chat",
                                            title_source="placeholder", model=settings.deepseek_model)
            seed.add(conversation)
            seed.commit()
            seed.refresh(conversation)
        else:
            conversation = _owned(seed, payload.conversation_id, user)
        conversation_id = conversation.id
        needs_title = conversation.title_source == "placeholder"
    finally:
        seed.close()

    def events():
        db = SessionLocal()
        started = time.perf_counter()
        collected: list[str] = []
        assistant_id: int | None = None
        settled = False
        try:
            retrieval = chat_retrieval.retrieve(db, message)
            citations = retrieval["citations"]
            record_count = len(retrieval["records"])
            prior = _history(db, conversation_id)

            db.add(ChatMessage(conversation_id=conversation_id, role="user", content=message,
                               status="complete", model=settings.deepseek_model))
            # The reply row exists before the first token so a disconnect cannot orphan the answer.
            assistant = ChatMessage(conversation_id=conversation_id, role="assistant", content="",
                                    citations=citations, record_count=record_count, status="incomplete",
                                    model=settings.deepseek_model)
            db.add(assistant)
            if needs_title:
                # The title comes from the question alone, so it holds even if the reply is
                # stopped or fails; gating it on completion left first turns titled "New chat".
                head = db.get(ChatConversation, conversation_id)
                if head:
                    head.title = chat_service.generate_title(message)
                    head.title_source = "question"
            db.commit()
            assistant_id = assistant.id

            messages = chat_service.build_messages(message, prior, retrieval)

            yield _sse("meta", {
                "conversation_id": conversation_id,
                "message_id": assistant_id,
                "model": settings.deepseek_model,
                "citations": citations,
                "record_count": record_count,
                "retrieval_ms": int((time.perf_counter() - started) * 1000),
            })

            status_value = "complete"
            error_text = ""
            try:
                for delta in deepseek.chat_stream(messages):
                    collected.append(delta)
                    yield _sse("delta", {"text": delta})
                    if len(collected) % FLUSH_EVERY == 0:
                        assistant.content = "".join(collected)
                        # A row that already carries text is a partial reply rather than a
                        # placeholder, so an abort before the final commit reads back as "stopped".
                        assistant.status = "stopped"
                        db.commit()
            except deepseek.DeepSeekError as exc:
                status_value, error_text = "failed", exc.message
                yield _sse("error", {"kind": exc.kind, "message": exc.message,
                                     "retryable": exc.retryable, "status_code": exc.status_code})
            except Exception:
                status_value = "failed"
                error_text = "The assistant encountered an unexpected error."
                yield _sse("error", {"kind": deepseek.UNKNOWN, "message": error_text,
                                     "retryable": True, "status_code": None})
            else:
                yield _sse("done", {"conversation_id": conversation_id, "status": status_value})

            assistant.content = "".join(collected)
            assistant.status = status_value
            assistant.error = error_text
            assistant.latency_ms = int((time.perf_counter() - started) * 1000)
            conversation = db.get(ChatConversation, conversation_id)
            if conversation:
                conversation.updated_at = utcnow()
            db.commit()
            db.refresh(assistant)
            settled = True
            yield _sse("persisted", {
                "conversation_id": conversation_id,
                "message_id": assistant.id,
                "status": assistant.status,
                "title": conversation.title if conversation else "",
            })
        finally:
            # A disconnect ends the stream without a final frame: the partial answer stays visible.
            if not settled and assistant_id is not None:
                try:
                    row = db.get(ChatMessage, assistant_id)
                    if row and row.status in ("incomplete", "stopped"):
                        row.content = "".join(collected)
                        row.status = "stopped"
                        db.commit()
                except Exception:
                    db.rollback()
            db.close()

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
