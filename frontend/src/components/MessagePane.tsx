import { useMemo, useState } from "react";

import { jwtCrack, pickFile, type BodyPreview, type CrackResult } from "../ipc";
import { detectLang, prettify, type BodyLang } from "./beautify";
import { highlightCode } from "./highlight";
import { scanInteresting, decodeJwt } from "./interesting";

/**
 * Renders one HTTP message: the head as written, then the body.
 *
 * The head is shown verbatim — original casing, duplicate fields and all — because
 * that is the entire point of the message model underneath. Nothing here re-orders,
 * re-cases or de-duplicates anything.
 *
 * The body may be beautified for reading. When it parses as JSON or markup the pane
 * offers a Pretty view beside the Raw bytes, but the two are the same content: Pretty
 * only re-indents, and Raw is always one click away, so nothing the formatter does can
 * hide what was actually on the wire.
 */
export function MessagePane({
  title,
  head,
  body,
}: {
  title: string;
  head: string;
  body: BodyPreview;
}) {
  const contentType = useMemo(() => extractContentType(head), [head]);
  const scanText = useMemo(
    () => head + "\n" + (body.rendering === "text" ? body.content : ""),
    [head, body],
  );
  return (
    <section className="message">
      <header className="message-header">
        <h3>{title}</h3>
        <span className="muted">{describeBody(body)}</span>
      </header>
      <InterestingValues text={scanText} />
      <pre className="head">{head}</pre>
      <BodyView body={body} contentType={contentType} />
    </section>
  );
}

/**
 * The sensitive values found in this message, surfaced as a short list so they are not
 * buried in the text. Each is a lead to check — copy it, or decode a JWT in place.
 */
function InterestingValues({ text }: { text: string }) {
  const findings = useMemo(() => scanInteresting(text), [text]);
  const [open, setOpen] = useState<number | null>(null);
  const [copied, setCopied] = useState<number | null>(null);
  const [crack, setCrack] = useState<
    Record<number, { busy: boolean; result?: CrackResult; err?: string }>
  >({});
  if (findings.length === 0) return null;

  const copy = (i: number, v: string) => {
    navigator.clipboard?.writeText(v).then(
      () => {
        setCopied(i);
        window.setTimeout(() => setCopied(null), 1000);
      },
      () => undefined,
    );
  };

  const runCrack = async (i: number, value: string, wordlist: string | null) => {
    setCrack((c) => ({ ...c, [i]: { busy: true } }));
    try {
      const result = await jwtCrack(value, wordlist);
      setCrack((c) => ({ ...c, [i]: { busy: false, result } }));
    } catch (e) {
      setCrack((c) => ({ ...c, [i]: { busy: false, err: String(e) } }));
    }
  };

  const crackWithWordlist = async (i: number, value: string) => {
    const path = await pickFile();
    if (path) await runCrack(i, value, path);
  };

  return (
    <div className="iv-panel">
      <div className="iv-head">
        ⚑ Interesting values <span className="muted">· {findings.length}</span>
      </div>
      <ul className="iv-list">
        {findings.map((f, i) => {
          const decoded = f.type === "jwt" ? decodeJwt(f.value) : null;
          const cr = crack[i];
          return (
            <li className="iv-item" key={i}>
              <span className={`iv-badge iv-${f.type}`}>{f.label}</span>
              <span className="iv-value mono">
                {f.value.length > 88 ? f.value.slice(0, 87) + "…" : f.value}
              </span>
              <span className="iv-actions">
                <button className="chip-btn" onClick={() => copy(i, f.value)}>
                  {copied === i ? "Copied" : "Copy"}
                </button>
                {decoded && (
                  <button className="chip-btn" onClick={() => setOpen(open === i ? null : i)}>
                    {open === i ? "Hide" : "Decode"}
                  </button>
                )}
                {f.type === "jwt" && (
                  <>
                    <button
                      className="chip-btn"
                      disabled={cr?.busy}
                      title="Try the common-secrets list (CPU, instant)"
                      onClick={() => void runCrack(i, f.value, null)}
                    >
                      {cr?.busy ? "Cracking…" : "Crack"}
                    </button>
                    <button
                      className="chip-btn"
                      disabled={cr?.busy}
                      title="Pick a wordlist — runs on the GPU via hashcat when installed"
                      onClick={() => void crackWithWordlist(i, f.value)}
                    >
                      Wordlist…
                    </button>
                  </>
                )}
              </span>
              {decoded && open === i && <pre className="iv-decoded">{decoded}</pre>}
              {cr?.result && (
                <div className={`iv-crack${cr.result.found ? " iv-crack-hit" : ""}`}>
                  {cr.result.found ? (
                    <>
                      <strong>secret:</strong> <span className="mono">{cr.result.secret}</span>{" "}
                      <span className="muted">· via {cr.result.tool}</span>
                    </>
                  ) : (
                    <span className="muted">
                      {cr.result.note}
                      {!cr.result.hashcat_available &&
                        " — install hashcat + pick a wordlist for a GPU crack"}
                    </span>
                  )}
                </div>
              )}
              {cr?.err && <div className="iv-crack muted">{cr.err}</div>}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function BodyView({
  body,
  contentType,
}: {
  body: BodyPreview;
  contentType: string | null;
}) {
  const lang: BodyLang = useMemo(
    () => (body.rendering === "text" ? detectLang(body.content, contentType) : null),
    [body.rendering, body.content, contentType],
  );
  const pretty = useMemo(
    () => (lang ? prettify(body.content, lang) : null),
    [lang, body.content],
  );

  const [mode, setMode] = useState<"pretty" | "raw">(pretty ? "pretty" : "raw");
  const [wrap, setWrap] = useState(false);
  const [copied, setCopied] = useState(false);

  if (body.rendering === "empty") {
    return <p className="muted empty-body">No body.</p>;
  }

  const shown = mode === "pretty" && pretty ? pretty : body.content;
  const isHex = body.rendering === "binary";

  const copy = () => {
    navigator.clipboard?.writeText(shown).then(
      () => {
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1200);
      },
      () => undefined,
    );
  };

  return (
    <div className="body-view">
      <div className="body-toolbar">
        {pretty && (
          <div className="seg">
            <button
              className={mode === "pretty" ? "seg-btn on" : "seg-btn"}
              onClick={() => setMode("pretty")}
            >
              Pretty
            </button>
            <button
              className={mode === "raw" ? "seg-btn on" : "seg-btn"}
              onClick={() => setMode("raw")}
            >
              Raw
            </button>
          </div>
        )}
        {lang && <span className="lang-badge">{lang.toUpperCase()}</span>}
        <div className="body-toolbar-right">
          {!isHex && (
            <button
              className={wrap ? "chip-btn on" : "chip-btn"}
              onClick={() => setWrap((w) => !w)}
              title="Toggle word wrap"
            >
              Wrap
            </button>
          )}
          <button className="chip-btn" onClick={copy}>
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
      </div>

      {body.truncated && (
        <p className="notice">
          Showing the first {body.content.length.toLocaleString()} of{" "}
          {body.total_bytes.toLocaleString()} bytes.
        </p>
      )}

      {isHex ? (
        <pre className="body hex">{shown}</pre>
      ) : (
        <CodeBlock text={shown} lang={lang} wrap={wrap} />
      )}
    </div>
  );
}

/** A body with a line-number gutter, the way a request pane is read line by line. */
function CodeBlock({ text, lang, wrap }: { text: string; lang: BodyLang; wrap: boolean }) {
  const lineCount = useMemo(() => text.split("\n").length, [text]);
  const gutter = useMemo(
    () => Array.from({ length: lineCount }, (_, i) => i + 1).join("\n"),
    [lineCount],
  );
  const html = useMemo(() => highlightCode(text, lang), [text, lang]);
  return (
    <div className={wrap ? "code-block wrap" : "code-block"}>
      <pre className="code-gutter" aria-hidden="true">
        {gutter}
      </pre>
      {html ? (
        // Safe: highlight.js escapes the source, so no markup from the body can execute.
        <pre className="code-body hljs" dangerouslySetInnerHTML={{ __html: html }} />
      ) : (
        <pre className="code-body">{text}</pre>
      )}
    </div>
  );
}

/** Pull the Content-Type value out of a raw head, case-insensitively. */
function extractContentType(head: string): string | null {
  for (const line of head.split(/\r?\n/)) {
    const m = line.match(/^content-type\s*:\s*(.+)$/i);
    if (m && m[1]) return m[1].trim();
  }
  return null;
}

function describeBody(body: BodyPreview): string {
  if (body.rendering === "empty") return "no body";
  const size = `${body.total_bytes.toLocaleString()} bytes`;
  // "binary" is said out loud rather than implied by the hex, so nobody reads a hex
  // dump as the tool having failed to decode something it should have.
  return body.rendering === "binary" ? `${size}, binary` : size;
}
