import { API_BASE, ApiError, getToken } from "./api";

export interface Citation {
  index: number;
  key: string;
  kind: string;
  title: string;
  provenance: string;
  route: string;
  url: string;
  facts: Record<string, unknown>;
}

export interface ChatMessage {
  id: number;
  role: "user" | "assistant";
  content: string;
  citations: Citation[];
  record_count: number;
  status: "complete" | "failed" | "stopped" | "incomplete";
  error: string;
  model: string;
  latency_ms?: number | null;
  created_at?: string;
}

export interface Conversation {
  id: number;
  title: string;
  model: string;
  message_count: number;
  created_at: string;
  updated_at: string;
  messages?: ChatMessage[];
}

export type ConnectionState = "connected" | "error" | "untested" | "missing_key";

export interface ChatStatus {
  provider: string;
  model: string;
  host: string;
  key_configured: boolean;
  state: ConnectionState;
  connected: boolean;
  kind: string;
  detail: string;
  latency_ms: number | null;
  tested_at: number | null;
  message: string;
}

export type StreamEvent =
  | { type: "meta"; conversation_id: number; message_id: number; model: string; citations: Citation[]; record_count: number; retrieval_ms: number }
  | { type: "delta"; text: string }
  | { type: "done"; conversation_id: number; status: string }
  | { type: "error"; kind: string; message: string; retryable: boolean; status_code: number | null }
  | { type: "persisted"; conversation_id: number; message_id: number; status: string; title: string };

const EVENT_FIELDS = new Set(["meta", "delta", "done", "error", "persisted"]);

function parseFrame(frame: string): StreamEvent | null {
  let event = "message";
  const dataLines: string[] = [];
  for (const line of frame.split("\n")) {
    if (line.startsWith("event:")) event = line.slice(6).trim();
    else if (line.startsWith("data:")) dataLines.push(line.slice(5).trim());
  }
  if (!EVENT_FIELDS.has(event) || dataLines.length === 0) return null;
  try {
    return { type: event, ...(JSON.parse(dataLines.join("\n")) as object) } as StreamEvent;
  } catch {
    return null;
  }
}

/**
 * Streams one reply. `fetch` is used rather than `EventSource` because the endpoint
 * is bearer-authenticated and `EventSource` cannot set that header.
 */
export async function* streamChat(
  body: { message: string; conversation_id: number | null },
  signal: AbortSignal,
): AsyncGenerator<StreamEvent> {
  const token = getToken();
  let response: Response;
  try {
    response = await fetch(`${API_BASE}/chat/stream`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "text/event-stream",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(body),
      signal,
    });
  } catch (error) {
    if ((error as Error)?.name === "AbortError") return;
    throw new ApiError(0, "The API is unreachable. Confirm the backend is running and retry.");
  }

  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    const detail = (payload as { detail?: string } | null)?.detail;
    throw new ApiError(
      response.status,
      detail || `Request failed (${response.status}). Try again in a moment.`,
    );
  }
  if (!response.body) throw new ApiError(0, "The server did not return a response stream.");

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let boundary = buffer.indexOf("\n\n");
      while (boundary !== -1) {
        const frame = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        const event = parseFrame(frame);
        if (event) yield event;
        boundary = buffer.indexOf("\n\n");
      }
    }
  } catch (error) {
    if ((error as Error)?.name !== "AbortError") throw error;
  } finally {
    reader.cancel().catch(() => undefined);
  }
}
