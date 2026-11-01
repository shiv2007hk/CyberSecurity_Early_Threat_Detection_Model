import { Fragment, ReactNode, useMemo, useState } from "react";
import { Check, Copy, ExternalLink } from "lucide-react";

/**
 * Markdown for chat replies, rendered to React elements.
 *
 * There is no HTML path here by design: model output is untrusted text, so nothing is ever
 * injected as markup and link destinations are restricted to absolute http(s) URLs.
 */

const INLINE =
  /(\*\*([^*]+)\*\*)|(__([^_]+)__)|(\*([^*\n]+)\*)|(_([^_\n]+)_)|(`([^`\n]+)`)|(\[([^\]\n]+)\]\(([^)\s]+)\))|(~~([^~]+)~~)|(\[(\d{1,2})\])/g;

export function safeHref(raw: string): string | null {
  const value = raw.trim();
  if (!/^https?:\/\//i.test(value)) return null;
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:" ? url.href : null;
  } catch {
    return null;
  }
}

function inline(text: string, key: string, onCitation?: (index: number) => void): ReactNode[] {
  const nodes: ReactNode[] = [];
  let cursor = 0;
  let match: RegExpExecArray | null;
  let n = 0;
  INLINE.lastIndex = 0;
  while ((match = INLINE.exec(text))) {
    if (match.index > cursor) nodes.push(text.slice(cursor, match.index));
    const id = `${key}-i${n++}`;
    if (match[2]) nodes.push(<strong key={id} className="font-semibold text-ink">{inline(match[2], id, onCitation)}</strong>);
    else if (match[4]) nodes.push(<strong key={id} className="font-semibold text-ink">{inline(match[4], id, onCitation)}</strong>);
    else if (match[6]) nodes.push(<em key={id}>{inline(match[6], id, onCitation)}</em>);
    else if (match[8]) nodes.push(<em key={id}>{inline(match[8], id, onCitation)}</em>);
    else if (match[10]) nodes.push(<code key={id} className="rounded-[5px] bg-sunken px-1.5 py-0.5 font-mono text-[0.9em] text-ion">{match[10]}</code>);
    else if (match[12]) {
      const href = safeHref(match[13]);
      nodes.push(
        href ? (
          <a key={id} href={href} target="_blank" rel="noopener noreferrer nofollow" className="inline-flex items-center gap-1 text-ion underline decoration-ion/40 underline-offset-2 hover:decoration-ion">
            {inline(match[12], id, onCitation)}
            <ExternalLink size={10} className="shrink-0 opacity-60" />
          </a>
        ) : (
          <span key={id} className="text-mist">{match[12]}</span>
        ),
      );
    } else if (match[14]) nodes.push(<s key={id} className="text-dim">{match[14]}</s>);
    else if (match[16]) {
      const index = Number(match[16]);
      nodes.push(
        onCitation ? (
          <button key={id} type="button" onClick={() => onCitation(index)} className="citation-ref" title={`Open evidence ${index}`}>
            {index}
          </button>
        ) : (
          <span key={id}>[{index}]</span>
        ),
      );
    }
    cursor = match.index + match[0].length;
  }
  if (cursor < text.length) nodes.push(text.slice(cursor));
  return nodes;
}

function CodeBlock({ code, lang }: { code: string; lang: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="my-2.5 overflow-hidden rounded-[10px] border border-line bg-sunken">
      <div className="flex items-center justify-between border-b border-line px-3 py-1.5">
        <span className="font-mono text-[9px] uppercase tracking-[0.14em] text-dim">{lang || "code"}</span>
        <button
          type="button"
          onClick={() => {
            navigator.clipboard?.writeText(code).then(() => {
              setCopied(true);
              setTimeout(() => setCopied(false), 1400);
            }).catch(() => undefined);
          }}
          className="flex items-center gap-1 font-mono text-[9px] uppercase tracking-[0.1em] text-dim transition-colors hover:text-ion"
        >
          {copied ? <Check size={10} /> : <Copy size={10} />} {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="overflow-x-auto px-3 py-2.5">
        <code className="font-mono text-[11.5px] leading-[1.6] text-ink">{code}</code>
      </pre>
    </div>
  );
}

function TableBlock({ rows }: { rows: string[][] }) {
  const [head, ...body] = rows;
  return (
    <div className="my-2.5 overflow-x-auto rounded-[10px] border border-line">
      <table className="w-full border-collapse text-[11.5px]">
        <thead>
          <tr className="bg-sunken">
            {head.map((cell, i) => (
              <th key={i} className="border-b border-line px-2.5 py-1.5 text-left font-semibold text-ink">{inline(cell, `th${i}`)}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {body.map((row, r) => (
            <tr key={r} className="even:bg-sunken/40">
              {row.map((cell, c) => (
                <td key={c} className="border-b border-line/60 px-2.5 py-1.5 align-top text-mist last:border-r-0">{inline(cell, `td${r}-${c}`)}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const splitRow = (line: string) =>
  line.replace(/^\s*\|/, "").replace(/\|\s*$/, "").split("|").map((cell) => cell.trim());

const isDivider = (line: string) => /^\s*\|?[\s:|-]*-[\s:|-]*\|?\s*$/.test(line) && line.includes("-");

function parseBlocks(source: string, onCitation?: (index: number) => void): ReactNode[] {
  const lines = source.replace(/\r\n/g, "\n").split("\n");
  const out: ReactNode[] = [];
  let paragraph: string[] = [];
  let key = 0;
  let i = 0;

  const flush = () => {
    if (!paragraph.length) return;
    const text = paragraph.join("\n");
    paragraph = [];
    const id = `p${key++}`;
    out.push(
      <p key={id} className="my-1.5 leading-[1.68] first:mt-0 last:mb-0">
        {text.split("\n").map((segment, s, all) => (
          <Fragment key={s}>
            {inline(segment, `${id}-${s}`, onCitation)}
            {s < all.length - 1 && <br />}
          </Fragment>
        ))}
      </p>,
    );
  };

  while (i < lines.length) {
    const line = lines[i];

    if (/^\s*```/.test(line)) {
      flush();
      const lang = line.trim().replace(/^```/, "").trim();
      const body: string[] = [];
      i += 1;
      while (i < lines.length && !/^\s*```/.test(lines[i])) body.push(lines[i++]);
      i += 1;
      out.push(<CodeBlock key={`c${key++}`} code={body.join("\n")} lang={lang} />);
      continue;
    }

    if (/^\s*(?:-\s*){3,}$|^\s*(?:\*\s*){3,}$|^\s*(?:_\s*){3,}$/.test(line)) {
      flush();
      out.push(<hr key={`h${key++}`} className="my-3 border-line" />);
      i += 1;
      continue;
    }

    const heading = /^(#{1,4})\s+(.*)$/.exec(line);
    if (heading) {
      flush();
      const level = heading[1].length;
      const sizes = ["text-[15px]", "text-[14px]", "text-[13px]", "text-[12.5px]"];
      out.push(
        <p key={`hd${key++}`} className={`mb-1 mt-3 font-semibold text-ink first:mt-0 ${sizes[level - 1]}`}>
          {inline(heading[2], `hd${key}`, onCitation)}
        </p>,
      );
      i += 1;
      continue;
    }

    if (/^\s*>\s?/.test(line)) {
      flush();
      const quote: string[] = [];
      while (i < lines.length && /^\s*>\s?/.test(lines[i])) quote.push(lines[i++].replace(/^\s*>\s?/, ""));
      out.push(
        <blockquote key={`q${key++}`} className="my-2 border-l-2 border-ion/50 bg-sunken/50 py-1.5 pl-3 pr-2 text-mist">
          {inline(quote.join(" "), `q${key}`, onCitation)}
        </blockquote>,
      );
      continue;
    }

    if (line.includes("|") && i + 1 < lines.length && isDivider(lines[i + 1])) {
      flush();
      const rows: string[][] = [splitRow(line)];
      i += 2;
      while (i < lines.length && lines[i].includes("|") && lines[i].trim()) rows.push(splitRow(lines[i++]));
      out.push(<TableBlock key={`t${key++}`} rows={rows} />);
      continue;
    }

    const bullet = /^\s*[-*+]\s+(.*)$/.exec(line);
    if (bullet) {
      flush();
      const items: string[] = [];
      while (i < lines.length) {
        const match = /^\s*[-*+]\s+(.*)$/.exec(lines[i]);
        if (!match) {
          if (/^\s{2,}\S/.test(lines[i]) && items.length) items[items.length - 1] += ` ${lines[i].trim()}`;
          else break;
        } else items.push(match[1]);
        i += 1;
      }
      out.push(
        <ul key={`u${key++}`} className="my-1.5 space-y-1">
          {items.map((item, n) => (
            <li key={n} className="flex gap-2 leading-[1.62]">
              <span className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-ion/70" />
              <span>{inline(item, `u${key}-${n}`, onCitation)}</span>
            </li>
          ))}
        </ul>,
      );
      continue;
    }

    const ordered = /^\s*(\d+)[.)]\s+(.*)$/.exec(line);
    if (ordered) {
      flush();
      const items: string[] = [ordered[2]];
      i += 1;
      while (i < lines.length) {
        const match = /^\s*\d+[.)]\s+(.*)$/.exec(lines[i]);
        if (!match) break;
        items.push(match[1]);
        i += 1;
      }
      out.push(
        <ol key={`o${key++}`} className="my-1.5 space-y-1">
          {items.map((item, n) => (
            <li key={n} className="flex gap-2 leading-[1.62]">
              <span className="min-w-[16px] shrink-0 tnum font-mono text-[10px] text-ion">{n + 1}.</span>
              <span>{inline(item, `o${key}-${n}`, onCitation)}</span>
            </li>
          ))}
        </ol>,
      );
      continue;
    }

    if (!line.trim()) {
      flush();
      i += 1;
      continue;
    }

    paragraph.push(line);
    i += 1;
  }

  flush();
  return out;
}

export function Markdown({ text, onCitation }: { text: string; onCitation?: (index: number) => void }) {
  const rendered = useMemo(() => parseBlocks(text, onCitation), [text, onCitation]);
  return <div className="markdown">{rendered}</div>;
}
