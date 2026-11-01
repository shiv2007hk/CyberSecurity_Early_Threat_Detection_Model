import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import { AnimatePresence, motion } from "framer-motion";
import {
  AlertTriangle,
  ArrowUp,
  Ban,
  Check,
  ChevronDown,
  Copy,
  FileText,
  History,
  Layers,
  Link2,
  Plus,
  RefreshCcw,
  Server,
  Sparkles,
  Square,
  Trash2,
  X,
} from "lucide-react";

import type { ReactNode } from "react";
import { Markdown } from "../../components/Markdown";
import { ReadOnlyHint, useToast } from "../../components/ui";
import { api } from "../../lib/api";
import { useAuth } from "../../context/AuthContext";
import { Citation, ChatMessage, ChatStatus, Conversation, streamChat } from "../../lib/chat";

const SUGGESTIONS = [
  "Analyse my highest-risk vulnerabilities.",
  "Summarise the latest threat intelligence.",
  "Identify the most exposed organisational assets.",
  "Explain the latest attack simulation results.",
];

const KIND_LABEL: Record<string, string> = {
  vulnerability: "CVE",
  threat: "Intelligence",
  asset: "Asset",
  alert: "Alert",
  recommendation: "Action",
  risk_assessment: "Risk",
  simulation_run: "Exercise",
};

const STATE_TONE: Record<string, string> = {
  connected: "border-low/40 bg-low/10 text-low",
  error: "border-crit/40 bg-crit/10 text-crit",
  untested: "border-med/40 bg-med/10 text-med",
  missing_key: "border-line bg-sunken text-dim",
};

const STATE_LABEL: Record<string, string> = {
  connected: "Connected",
  error: "Connection failed",
  untested: "Not verified",
  missing_key: "No API key",
};

function relativeTime(seconds: number | null): string {
  if (!seconds) return "";
  const diff = Math.max(0, Date.now() / 1000 - seconds);
  if (diff < 60) return "under a minute ago";
  if (diff < 3600) return `${Math.floor(diff / 60)} min ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} h ago`;
  return `${Math.floor(diff / 86400)} d ago`;
}

function CitationChip({ citation, flash }: { citation: Citation; flash: boolean }) {
  const external = citation.url;
  const body = (
    <>
      <span className="grid h-4 w-4 shrink-0 place-items-center rounded-[5px] bg-ion/15 font-mono text-[9px] font-semibold text-ion">
        {citation.index}
      </span>
      <span className="min-w-0 flex-1">
        <span className="flex items-center gap-1.5">
          <span className="truncate font-mono text-[10px] text-ink">{citation.key}</span>
          <span className="shrink-0 font-mono text-[8px] uppercase tracking-[0.12em] text-dim">
            {KIND_LABEL[citation.kind] || citation.kind}
          </span>
        </span>
        <span className="mt-0.5 block truncate text-[10px] text-mist">{citation.title}</span>
      </span>
      {external ? <Link2 size={10} className="shrink-0 text-dim" /> : <FileText size={10} className="shrink-0 text-dim" />}
    </>
  );
  const classes = clsx(
    "flex w-full items-center gap-2 rounded-[9px] border border-line bg-surface px-2 py-1.5 text-left transition-colors hover:border-ion/45 hover:bg-sunken",
    flash && "citation-flash",
  );
  const detail = [
    citation.facts.cvss != null && `CVSS ${citation.facts.cvss}`,
    citation.facts.epss && `EPSS ${citation.facts.epss}`,
    citation.facts.severity && `severity ${citation.facts.severity}`,
    citation.facts.risk_score != null && `risk ${citation.facts.risk_score}`,
    citation.facts.published && `published ${citation.facts.published}`,
    citation.facts.source && `source ${citation.facts.source}`,
  ]
    .filter(Boolean)
    .join(" · ");

  return (
    <div className="min-w-0">
      {external ? (
        <a href={external} target="_blank" rel="noopener noreferrer nofollow" className={classes} title={citation.route || external}>
          {body}
        </a>
      ) : (
        <CitationLink classes={classes} citation={citation} title={citation.route || ""}>
          {body}
        </CitationLink>
      )}
      {detail && <p className="mt-1 truncate pl-6 text-[9.5px] text-dim">{detail}</p>}
    </div>
  );
}

function CitationLink({
  classes,
  citation,
  title,
  children,
}: {
  classes: string;
  citation: Citation;
  title: string;
  children: ReactNode;
}) {
  const navigate = useNavigate();
  return (
    <button type="button" className={classes} title={title} onClick={() => citation.route && navigate(citation.route)}>
      {children}
    </button>
  );
}

function MessageRow({
  message,
  streaming,
  onRetry,
}: {
  message: ChatMessage;
  streaming?: boolean;
  onRetry?: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const [showSources, setShowSources] = useState(false);
  const [flash, setFlash] = useState<number | null>(null);
  const isUser = message.role === "user";

  const focusCitation = useCallback((index: number) => {
    setShowSources(true);
    setFlash(index);
    window.setTimeout(() => setFlash(null), 1400);
    document.getElementById(`evidence-${index}`)?.scrollIntoView({ behavior: "smooth", block: "center" });
  }, []);

  if (isUser) {
    return (
      <div className="flex justify-end">
        <div className="max-w-[88%] rounded-[16px] rounded-br-[6px] border border-ion/25 bg-ion/[0.09] px-4 py-2.5 text-[13px] leading-relaxed text-ink sm:max-w-[76%]">
          {message.content}
        </div>
      </div>
    );
  }

  const failed = message.status === "failed";
  const citations = message.citations || [];

  return (
    <div className="flex gap-3">
      <span className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-[9px] border border-ion/30 bg-ion/[0.08]">
        <Sparkles size={13} className="text-ion" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="font-mono text-[9.5px] uppercase tracking-[0.16em] text-dim">Aegis AI</span>
          {message.model && <span className="font-mono text-[9px] text-dim">· {message.model}</span>}
          {message.status === "stopped" && <span className="chip text-med">stopped</span>}
          {message.status === "incomplete" && <span className="chip text-med">interrupted</span>}
          {streaming && <span className="chip text-ion">streaming</span>}
        </div>

        {failed ? (
          <div className="mt-1.5 rounded-[12px] border border-crit/35 bg-crit/[0.07] px-3 py-2.5">
            <div className="flex items-start gap-2">
              <AlertTriangle size={13} className="mt-0.5 shrink-0 text-crit" />
              <div className="min-w-0 flex-1">
                <p className="text-[12px] font-medium text-crit">Aegis AI could not answer</p>
                <p className="mt-0.5 text-[11.5px] leading-relaxed text-mist">{message.error || "No reply was returned."}</p>
              </div>
            </div>
            {onRetry && (
              <button type="button" onClick={onRetry} className="mt-2 flex items-center gap-1.5 rounded-full border border-line bg-surface px-2.5 py-1 font-mono text-[9.5px] uppercase tracking-[0.12em] text-mist transition-colors hover:border-ion/45 hover:text-ion">
                <RefreshCcw size={10} /> Retry
              </button>
            )}
          </div>
        ) : (
          <div className="mt-1 text-[12.5px] text-mist">
            {message.content ? (
              <Markdown text={message.content} onCitation={focusCitation} />
            ) : streaming ? (
              <p className="flex items-center gap-1.5 py-1 text-dim">
                <span className="typing-dot" />
                <span className="typing-dot" style={{ animationDelay: "0.15s" }} />
                <span className="typing-dot" style={{ animationDelay: "0.3s" }} />
                <span className="ml-1 font-mono text-[10px] uppercase tracking-[0.12em]">Waiting for the first token</span>
              </p>
            ) : (
              <p className="text-dim">No content was returned for this turn.</p>
            )}
          </div>
        )}

        {!failed && (message.content || citations.length > 0) && (
          <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1">
            <button
              type="button"
              onClick={() => {
                navigator.clipboard?.writeText(message.content).then(() => {
                  setCopied(true);
                  setTimeout(() => setCopied(false), 1500);
                }).catch(() => undefined);
              }}
              className="flex items-center gap-1.5 font-mono text-[9.5px] uppercase tracking-[0.12em] text-dim transition-colors hover:text-ion"
            >
              {copied ? <Check size={11} /> : <Copy size={11} />} {copied ? "Copied" : "Copy"}
            </button>
            {citations.length > 0 && (
              <button
                type="button"
                onClick={() => setShowSources((v) => !v)}
                aria-expanded={showSources}
                className="flex items-center gap-1.5 font-mono text-[9.5px] uppercase tracking-[0.12em] text-dim transition-colors hover:text-ion"
              >
                <Layers size={11} /> {citations.length} platform record{citations.length === 1 ? "" : "s"}
                <ChevronDown size={10} className={clsx("transition-transform", showSources && "rotate-180")} />
              </button>
            )}
            {message.latency_ms != null && !streaming && (
              <span className="font-mono text-[9px] text-dim">{(message.latency_ms / 1000).toFixed(1)}s</span>
            )}
          </div>
        )}

        <AnimatePresence initial={false}>
          {showSources && citations.length > 0 && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.2 }}
              className="overflow-hidden"
            >
              <div className="mt-2 grid grid-cols-1 gap-1.5 sm:grid-cols-2">
                {citations.map((citation) => (
                  <div key={`${citation.kind}-${citation.key}`} id={`evidence-${citation.index}`}>
                    <CitationChip citation={citation} flash={flash === citation.index} />
                  </div>
                ))}
              </div>
              <p className="mt-1.5 text-[9.5px] leading-relaxed text-dim">
                Every figure above comes from the linked platform record. Explanations between citations are the
                model's, not additional evidence.
              </p>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </div>
  );
}

export default function AegisAI() {
  const { can, user } = useAuth();
  const { push: notify } = useToast();
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();
  const [conversationId, setConversationId] = useState<number | null>(() => {
    const raw = params.get("chat");
    const parsed = raw ? Number(raw) : NaN;
    return Number.isFinite(parsed) && parsed > 0 ? parsed : null;
  });
  const [draft, setDraft] = useState("");
  const [live, setLive] = useState<ChatMessage | null>(null);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [testing, setTesting] = useState(false);
  const [lastQuestion, setLastQuestion] = useState("");
  const abortRef = useRef<AbortController | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const pinnedRef = useRef(true);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const mayChat = can("analyst");

  const statusQuery = useQuery({
    queryKey: ["chat-status"],
    queryFn: () => api<ChatStatus>("/chat/status"),
    staleTime: 30_000,
  });
  const suggestionsQuery = useQuery({
    queryKey: ["chat-suggestions"],
    queryFn: () => api<{ suggestions: string[] }>("/chat/suggestions"),
    staleTime: Infinity,
  });
  const conversationsQuery = useQuery({
    queryKey: ["chat-conversations"],
    queryFn: () => api<{ items: Conversation[] }>("/chat/conversations"),
    staleTime: 15_000,
  });
  const detailQuery = useQuery({
    queryKey: ["chat-conversation", conversationId],
    queryFn: () => api<Conversation>(`/chat/conversations/${conversationId}`),
    enabled: conversationId != null,
  });

  const messages = useMemo<ChatMessage[]>(() => {
    const stored = detailQuery.data?.messages ?? [];
    return live ? [...stored, live] : stored;
  }, [detailQuery.data, live]);

  const status = statusQuery.data;

  useEffect(() => {
    const node = scrollRef.current;
    if (!node || !pinnedRef.current) return;
    node.scrollTop = node.scrollHeight;
  }, [messages, live?.content]);

  const onScroll = () => {
    const node = scrollRef.current;
    if (!node) return;
    pinnedRef.current = node.scrollHeight - node.scrollTop - node.clientHeight < 90;
  };

  const selectConversation = (id: number | null) => {
    setConversationId(id);
    setLive(null);
    const next = new URLSearchParams(params);
    if (id) next.set("chat", String(id));
    else next.delete("chat");
    setParams(next, { replace: true });
  };

  const send = useCallback(
    async (text: string) => {
      const message = text.trim();
      if (!message || live || !mayChat) return;
      setLastQuestion(message);
      setDraft("");
      pinnedRef.current = true;

      const controller = new AbortController();
      abortRef.current = controller;
      setLive({
        id: -1,
        role: "assistant",
        content: "",
        citations: [],
        record_count: 0,
        status: "complete",
        error: "",
        model: status?.model || "",
      });

      let failure = "";
      try {
        for await (const event of streamChat({ message, conversation_id: conversationId }, controller.signal)) {
          if (event.type === "meta") {
            if (conversationId == null) selectConversation(event.conversation_id);
            setLive((prev) => (prev ? { ...prev, citations: event.citations, record_count: event.record_count, model: event.model } : prev));
          } else if (event.type === "delta") {
            setLive((prev) => (prev ? { ...prev, content: prev.content + event.text } : prev));
          } else if (event.type === "error") {
            failure = event.message;
          } else if (event.type === "persisted") {
            queryClient.invalidateQueries({ queryKey: ["chat-conversation", event.conversation_id ?? conversationId] });
            queryClient.invalidateQueries({ queryKey: ["chat-conversations"] });
          }
        }
      } catch (error) {
        failure = (error as Error)?.message || "The request to Aegis AI failed.";
      } finally {
        abortRef.current = null;
      }

      if (failure) {
        setLive((prev) => (prev ? { ...prev, status: "failed", error: failure } : prev));
      } else {
        setLive(null);
      }
      // The persisted row is the source of truth once the stream closes, including on a failure.
      queryClient.invalidateQueries({ queryKey: ["chat-conversation", conversationId] });
      queryClient.invalidateQueries({ queryKey: ["chat-conversations"] });
      textareaRef.current?.focus();
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [conversationId, live, mayChat, queryClient, status?.model, params],
  );

  const stop = () => {
    abortRef.current?.abort();
    notify("info", "Generation stopped. The partial reply is kept in this conversation.");
  };

  const createMutation = useMutation({
    mutationFn: () => api<Conversation>("/chat/conversations", { method: "POST", body: JSON.stringify({}) }),
    onSuccess: (created) => {
      selectConversation(created.id);
      queryClient.invalidateQueries({ queryKey: ["chat-conversations"] });
      textareaRef.current?.focus();
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => api(`/chat/conversations/${id}`, { method: "DELETE" }),
    onSuccess: (_data, id) => {
      if (conversationId === id) selectConversation(null);
      queryClient.invalidateQueries({ queryKey: ["chat-conversations"] });
      notify("success", "Conversation deleted.");
    },
  });

  const clearMutation = useMutation({
    mutationFn: (id: number) => api(`/chat/conversations/${id}/clear`, { method: "POST" }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["chat-conversation", conversationId] });
      queryClient.invalidateQueries({ queryKey: ["chat-conversations"] });
      notify("success", "Conversation cleared.");
    },
  });

  const runTest = async () => {
    setTesting(true);
    try {
      const next = await api<ChatStatus>("/chat/status/test", { method: "POST" });
      queryClient.setQueryData(["chat-status"], next);
      if (next.connected) notify("success", `DeepSeek connected. ${next.model} responded in ${next.latency_ms ?? 0} ms.`);
      else notify("error", `Connection test failed. ${next.message}`);
    } catch (error) {
      notify("error", (error as Error).message || "The connection test could not run.");
    } finally {
      setTesting(false);
    }
  };

  const onKeyDown = (event: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) {
      event.preventDefault();
      void send(draft);
    }
  };

  const welcome = messages.length === 0 && !live;
  const suggestions = suggestionsQuery.data?.suggestions?.length ? suggestionsQuery.data.suggestions : SUGGESTIONS;
  const conversations = conversationsQuery.data?.items ?? [];
  const state = status?.state ?? "untested";

  return (
    <div className="flex h-[calc(100dvh-104px)] min-h-[540px] flex-col lg:flex-row">
      <AnimatePresence initial={false}>
        {historyOpen && (
          <motion.aside
            initial={{ width: 0, opacity: 0 }}
            animate={{ width: 268, opacity: 1 }}
            exit={{ width: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="shrink-0 overflow-hidden lg:pr-3"
            aria-label="Chat history"
          >
            <div className="flex h-full w-[268px] flex-col rounded-[16px] border border-line bg-surface/80">
              <div className="flex items-center justify-between border-b border-line px-3 py-2.5">
                <span className="font-mono text-[9px] uppercase tracking-[0.16em] text-dim">Conversations</span>
                <button type="button" onClick={() => setHistoryOpen(false)} className="text-dim transition-colors hover:text-ink" aria-label="Hide history">
                  <X size={13} />
                </button>
              </div>
              <div className="min-h-0 flex-1 space-y-1 overflow-y-auto p-2">
                {conversations.length === 0 && (
                  <p className="px-2 py-3 text-[11px] leading-relaxed text-dim">
                    No saved conversations yet. Each new chat is stored under your account.
                  </p>
                )}
                {conversations.map((row) => (
                  <div
                    key={row.id}
                    className={clsx(
                      "group flex items-center gap-1 rounded-[10px] border px-2 py-1.5 transition-colors",
                      row.id === conversationId ? "border-ion/40 bg-ion/[0.08]" : "border-transparent hover:border-line hover:bg-sunken",
                    )}
                  >
                    <button type="button" className="min-w-0 flex-1 text-left" onClick={() => { selectConversation(row.id); setHistoryOpen(false); }}>
                      <span className="block truncate text-[11.5px] text-ink">{row.title}</span>
                      <span className="mt-0.5 block font-mono text-[8.5px] uppercase tracking-[0.1em] text-dim">
                        {row.message_count} messages · {new Date(row.updated_at).toLocaleDateString()}
                      </span>
                    </button>
                    <button
                      type="button"
                      onClick={() => deleteMutation.mutate(row.id)}
                      className="shrink-0 text-dim opacity-0 transition-opacity hover:text-crit focus-visible:opacity-100 group-hover:opacity-100"
                      aria-label={`Delete ${row.title}`}
                    >
                      <Trash2 size={12} />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          </motion.aside>
        )}
      </AnimatePresence>

      <section className="flex min-w-0 flex-1 flex-col overflow-hidden rounded-[16px] border border-line bg-surface/70">
        <header className="flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-line px-3 py-2.5 sm:px-4">
          <div className="flex min-w-0 items-center gap-2.5">
            <span className="grid h-8 w-8 shrink-0 place-items-center rounded-[10px] border border-ion/30 bg-ion/[0.1]">
              <Sparkles size={15} className="text-ion" />
            </span>
            <div className="min-w-0">
              <h1 className="truncate font-display text-[15px] font-semibold leading-tight text-ink">Aegis AI</h1>
              <p className="truncate font-mono text-[8.5px] uppercase tracking-[0.14em] text-dim">
                DeepSeek · answers grounded in platform records
              </p>
            </div>
          </div>

          <div className="ml-auto flex flex-wrap items-center gap-1.5">
            <button
              type="button"
              onClick={runTest}
              disabled={testing || state === "missing_key"}
              title={status?.message || "Run a live connection test"}
              className={clsx(
                "flex items-center gap-1.5 rounded-full border px-2.5 py-1 font-mono text-[9px] uppercase tracking-[0.12em] transition-colors disabled:cursor-not-allowed disabled:opacity-70",
                STATE_TONE[state] || STATE_TONE.untested,
              )}
            >
              {testing ? <RefreshCcw size={10} className="animate-spin" /> : <Server size={10} />}
              {testing ? "Testing" : STATE_LABEL[state] || state}
            </button>
            <span className="hidden rounded-full border border-line bg-sunken px-2 py-1 font-mono text-[9px] tracking-[0.06em] text-dim sm:inline">
              {status?.model || "deepseek-chat"}
            </span>
            <button
              type="button"
              onClick={() => setHistoryOpen((v) => !v)}
              aria-pressed={historyOpen}
              className="flex items-center gap-1.5 rounded-full border border-line bg-surface px-2.5 py-1 font-mono text-[9px] uppercase tracking-[0.12em] text-mist transition-colors hover:border-ion/45 hover:text-ion"
            >
              <History size={11} /> History
            </button>
            <button
              type="button"
              onClick={() => createMutation.mutate()}
              className="flex items-center gap-1.5 rounded-full border border-ion/35 bg-ion/[0.09] px-2.5 py-1 font-mono text-[9px] uppercase tracking-[0.12em] text-ion transition-colors hover:bg-ion/15"
            >
              <Plus size={11} /> New chat
            </button>
            {conversationId != null && (
              <button
                type="button"
                onClick={() => clearMutation.mutate(conversationId)}
                className="rounded-full border border-line bg-surface px-2.5 py-1 font-mono text-[9px] uppercase tracking-[0.12em] text-dim transition-colors hover:border-crit/45 hover:text-crit"
              >
                Clear
              </button>
            )}
          </div>
        </header>

        {state === "missing_key" && (
          <div className="border-b border-line bg-med/[0.07] px-4 py-2 text-[11.5px] leading-relaxed text-mist">
            <span className="font-medium text-med">DeepSeek is not configured on this server.</span> Set{" "}
            <code className="rounded bg-sunken px-1 font-mono text-[10.5px] text-ion">DEEPSEEK_API_KEY</code> in{" "}
            <code className="rounded bg-sunken px-1 font-mono text-[10.5px] text-ion">backend/.env</code> and restart the API.
            Chat stays unavailable until a live test succeeds — the status above only reports a verified result.
          </div>
        )}

        <div ref={scrollRef} onScroll={onScroll} className="min-h-0 flex-1 overflow-y-auto px-3 py-4 sm:px-5">
          {welcome ? (
            <div className="mx-auto flex h-full max-w-[720px] flex-col justify-center">
              <p className="font-mono text-[9px] uppercase tracking-[0.2em] text-dim">Aegis AI</p>
              <h2 className="mt-2 font-display text-[26px] font-semibold leading-[1.15] tracking-[-0.01em] text-ink sm:text-[31px]">
                Ask about your exposure.
              </h2>
              <p className="mt-2 max-w-[560px] text-[13px] leading-relaxed text-mist">
                Every answer is built from records retrieved out of this platform — vulnerabilities, asset matches,
                risk assessments, alerts and intelligence — and each claim links back to the record it came from.
              </p>
              <div className="mt-5 grid grid-cols-1 gap-2 sm:grid-cols-2">
                {suggestions.map((question) => (
                  <button
                    key={question}
                    type="button"
                    onClick={() => void send(question)}
                    disabled={!mayChat}
                    className="group rounded-[13px] border border-line bg-surface px-3.5 py-3 text-left transition-colors hover:border-ion/45 hover:bg-sunken disabled:cursor-not-allowed disabled:opacity-55"
                  >
                    <span className="block text-[12.5px] leading-snug text-ink">{question}</span>
                    <span className="mt-1.5 flex items-center gap-1 font-mono text-[8.5px] uppercase tracking-[0.14em] text-dim group-hover:text-ion">
                      Ask this <ArrowUp size={9} className="-rotate-45" />
                    </span>
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <div className="mx-auto flex max-w-[760px] flex-col gap-5">
              {detailQuery.isFetching && messages.length === 0 ? (
                <p className="py-8 text-center font-mono text-[10px] uppercase tracking-[0.14em] text-dim">Loading conversation…</p>
              ) : (
                messages.map((message, index) => (
                  <MessageRow
                    key={message.id === -1 ? "live" : `${message.role}-${message.id}-${index}`}
                    message={message}
                    streaming={index === messages.length - 1 && !!live}
                    onRetry={message.status === "failed" && index === messages.length - 1 ? () => void send(lastQuestion) : undefined}
                  />
                ))
              )}
            </div>
          )}
        </div>

        <footer className="border-t border-line px-3 py-3 sm:px-5">
          {!mayChat ? (
            <ReadOnlyHint role={user?.role || "viewer"} />
          ) : (
            <>
              <div className="relative mx-auto flex max-w-[760px] items-end gap-2 rounded-[15px] border border-line bg-surface px-3 py-2 transition-colors focus-within:border-ion/50">
                <textarea
                  ref={textareaRef}
                  value={draft}
                  onChange={(event) => setDraft(event.target.value)}
                  onKeyDown={onKeyDown}
                  rows={Math.min(6, Math.max(1, draft.split("\n").length))}
                  placeholder="Ask about vulnerabilities, assets, risk scores or recent intelligence…"
                  aria-label="Message Aegis AI"
                  className="min-h-[26px] flex-1 resize-none bg-transparent py-1 text-[13px] leading-relaxed text-ink outline-none placeholder:text-dim"
                />
                {live ? (
                  <button
                    type="button"
                    onClick={stop}
                    className="flex h-8 shrink-0 items-center gap-1.5 rounded-[10px] border border-crit/40 bg-crit/10 px-2.5 font-mono text-[9.5px] uppercase tracking-[0.12em] text-crit transition-colors hover:bg-crit/20"
                  >
                    <Square size={10} /> Stop
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={() => void send(draft)}
                    disabled={!draft.trim()}
                    aria-label="Send message"
                    className="grid h-8 w-8 shrink-0 place-items-center rounded-[10px] border border-ion/40 bg-ion/15 text-ion transition-colors hover:bg-ion/25 disabled:cursor-not-allowed disabled:border-line disabled:bg-sunken disabled:text-dim"
                  >
                    <ArrowUp size={14} />
                  </button>
                )}
              </div>
              <div className="mx-auto mt-1.5 flex max-w-[760px] flex-wrap items-center gap-x-3 gap-y-1 px-1">
                <span className="font-mono text-[8.5px] uppercase tracking-[0.12em] text-dim">Enter sends · Shift+Enter adds a line</span>
                <span className="flex items-center gap-1 font-mono text-[8.5px] uppercase tracking-[0.12em] text-dim">
                  <Ban size={9} /> Advisory only — Aegis AI cannot contain, block or patch
                </span>
                {live && (
                  <span className="ml-auto font-mono text-[8.5px] uppercase tracking-[0.12em] text-ion">
                    {live.content.length} characters streamed
                  </span>
                )}
              </div>
            </>
          )}
        </footer>
      </section>
    </div>
  );
}
