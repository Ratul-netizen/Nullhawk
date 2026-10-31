/**
 * Body pretty-printing for the message panes.
 *
 * The aim is only to make a captured body legible — indent JSON, break markup onto its
 * own lines — never to change what it says. Every function is pure and total: if the
 * content will not parse, it returns null and the caller shows the bytes as they came,
 * because a body we cannot format is exactly the case where guessing would mislead.
 */

import { js as beautifyJs, css as beautifyCss } from "js-beautify";

export type BodyLang =
  | "json"
  | "xml"
  | "html"
  | "plist"
  | "js"
  | "ts"
  | "css"
  | "java"
  | "kotlin"
  | "swift"
  | "objc"
  | "csharp"
  | "cpp"
  | "c"
  | "go"
  | "rust"
  | "python"
  | "ruby"
  | "php"
  | "bash"
  | "sql"
  | "yaml"
  | "properties"
  | "groovy"
  | "dockerfile"
  | "ini"
  | null;

/** HTML elements that never have a closing tag, so they must not open an indent level. */
const VOID_ELEMENTS = new Set([
  "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
  "param", "source", "track", "wbr",
]);

/** Guess the body's language from a Content-Type hint first, then the content itself. */
export function detectLang(
  content: string,
  contentType?: string | null,
  name?: string | null,
): BodyLang {
  const fromCt = langFromContentType((contentType ?? "").toLowerCase());
  if (fromCt) return fromCt;

  const fromName = name ? langFromName(name) : null;
  if (fromName) return fromName;

  // Content fallback for the structured web bodies only — guessing a source language from
  // its text alone is unreliable, so those rely on the content-type or filename.
  const trimmed = content.trimStart();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    return tryJson(content) !== null ? "json" : null;
  }
  if (trimmed.startsWith("<")) {
    const head = trimmed.slice(0, 200).toLowerCase();
    if (head.includes("<!doctype html") || head.includes("<html")) return "html";
    if (head.includes("<!doctype plist") || head.includes("<plist")) return "plist";
    return "xml";
  }
  return null;
}

/** The language a Content-Type implies, across web and app-source media types. */
function langFromContentType(ct: string): BodyLang {
  if (!ct) return null;
  if (ct.includes("json")) return "json";
  if (ct.includes("typescript")) return "ts";
  if (ct.includes("javascript") || ct.includes("ecmascript")) return "js";
  if (ct.includes("css")) return "css";
  if (ct.includes("html")) return "html";
  if (ct.includes("xml")) return "xml";
  if (ct.includes("yaml")) return "yaml";
  if (ct.includes("x-sh") || ct.includes("shellscript")) return "bash";
  if (ct.includes("x-python")) return "python";
  if (ct.includes("x-ruby")) return "ruby";
  if (ct.includes("x-php") || ct.includes("/php")) return "php";
  if (ct.includes("x-java")) return "java";
  if (ct.includes("x-kotlin")) return "kotlin";
  if (ct.includes("x-swift")) return "swift";
  if (ct.includes("x-csharp")) return "csharp";
  if (ct.includes("x-go")) return "go";
  if (ct.includes("x-rust")) return "rust";
  if (ct.includes("sql")) return "sql";
  return null;
}

const EXT_LANG: Record<string, BodyLang> = {
  json: "json", js: "js", jsx: "js", mjs: "js", cjs: "js",
  ts: "ts", tsx: "ts",
  html: "html", htm: "html", xml: "xml", plist: "plist", css: "css",
  java: "java", kt: "kotlin", kts: "kotlin",
  swift: "swift", m: "objc", mm: "objc",
  cs: "csharp", cpp: "cpp", cc: "cpp", cxx: "cpp", hpp: "cpp", hh: "cpp",
  c: "c", h: "c", go: "go", rs: "rust",
  py: "python", rb: "ruby", php: "php",
  sh: "bash", bash: "bash", zsh: "bash",
  sql: "sql", yaml: "yaml", yml: "yaml",
  properties: "properties", gradle: "groovy", groovy: "groovy",
  ini: "ini", cfg: "ini", toml: "ini",
};

/** The language implied by a filename or path — its extension, or a known basename. Use
 *  this when viewing extracted or decompiled app files (Android/iOS/desktop), where the
 *  name carries the type that an HTTP Content-Type would otherwise give. */
export function langFromName(name: string): BodyLang {
  const base = (name.split(/[\\/?#]/).pop() ?? name).toLowerCase();
  if (base === "dockerfile") return "dockerfile";
  if (base === "androidmanifest.xml") return "xml";
  if (base.endsWith(".plist")) return "plist";
  const ext = base.includes(".") ? base.slice(base.lastIndexOf(".") + 1) : "";
  return EXT_LANG[ext] ?? null;
}

/** Pretty-print for the detected language, or null if it cannot be formatted. */
export function prettify(content: string, lang: BodyLang): string | null {
  if (content.length > 500_000) return null; // too large to reformat responsively
  if (lang === "json") return prettyJson(content);
  if (lang === "xml" || lang === "html") return prettyMarkup(content);
  if (lang === "js") {
    return safeBeautify(() => beautifyJs(content, { indent_size: 2, end_with_newline: false }));
  }
  if (lang === "css") return safeBeautify(() => beautifyCss(content, { indent_size: 2 }));
  return null;
}

/** Run a beautifier, returning null rather than throwing on input it cannot format. */
function safeBeautify(fn: () => string): string | null {
  try {
    const out = fn();
    return out && out.length ? out : null;
  } catch {
    return null;
  }
}

function tryJson(content: string): unknown | null {
  try {
    return JSON.parse(content);
  } catch {
    return null;
  }
}

function prettyJson(content: string): string | null {
  const parsed = tryJson(content);
  if (parsed === null && content.trim() !== "null") return null;
  try {
    return JSON.stringify(parsed, null, 2);
  } catch {
    return null;
  }
}

/**
 * Indent markup by putting each tag on its own line and tracking nesting depth. It is a
 * viewer's formatter, not a parser: it leaves text content intact and treats void and
 * self-closing tags as level-neutral, which is enough to read a response by eye.
 */
function prettyMarkup(input: string): string | null {
  const source = input.trim();
  if (!source.startsWith("<")) return null;

  // Break between adjacent tags so each lands on its own line.
  const withBreaks = source.replace(/>\s*</g, ">\n<");
  const lines = withBreaks.split("\n");
  const pad = "  ";
  let depth = 0;
  const out: string[] = [];

  for (const raw of lines) {
    const node = raw.trim();
    if (!node) continue;

    const isClosing = /^<\//.test(node);
    const isComment = /^<!--/.test(node);
    const isDecl = /^<[!?]/.test(node); // <!doctype ...>, <?xml ...?>
    const tagName = node.match(/^<\/?\s*([a-zA-Z0-9-]+)/)?.[1]?.toLowerCase() ?? "";
    const isVoid = VOID_ELEMENTS.has(tagName);
    const isSelfClosing = /\/>$/.test(node);
    // A one-line element that opens and closes on the same node, e.g. <title>x</title>.
    const opensAndCloses = /^<[^/!?][^>]*>.*<\/[^>]+>$/.test(node);

    if (isClosing) depth = Math.max(depth - 1, 0);

    out.push(pad.repeat(depth) + node);

    const opensLevel =
      !isClosing &&
      !isComment &&
      !isDecl &&
      !isVoid &&
      !isSelfClosing &&
      !opensAndCloses &&
      /^<[a-zA-Z]/.test(node);
    if (opensLevel) depth += 1;
  }

  return out.join("\n");
}
