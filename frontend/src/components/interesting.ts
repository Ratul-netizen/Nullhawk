/**
 * Spotting the sensitive values in a message.
 *
 * A tester scanning a response by eye is looking for the handful of things that matter —
 * a token, a key, an address, a hash — in a wall of text. This finds them: it scans the
 * head and body for high-signal patterns and returns what it saw, so the pane can surface
 * them as a short list rather than leaving them buried. Detection only; it changes nothing
 * and sends nothing, and a value it flags is a lead to check, not a proven secret.
 */

export type IvType = "jwt" | "secret" | "email" | "ip" | "uuid" | "hash";

export interface IvFinding {
  type: IvType;
  label: string;
  value: string;
}

const MAX_SCAN = 200_000;

// Order matters: the most specific / highest-signal patterns first, so a JWT is a JWT and
// not three base64 fragments. Values are de-duplicated across rules by (type, value).
const RULES: { type: IvType; label: string; re: RegExp }[] = [
  { type: "jwt", label: "JWT", re: /eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/g },
  { type: "secret", label: "Private key", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g },
  { type: "secret", label: "AWS key", re: /\bAKIA[0-9A-Z]{16}\b/g },
  { type: "secret", label: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { type: "secret", label: "GitHub token", re: /\bgh[pousr]_[0-9A-Za-z]{36,}\b/g },
  { type: "secret", label: "Slack token", re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g },
  { type: "secret", label: "Stripe key", re: /\b[rsp]k_(?:live|test)_[0-9A-Za-z]{10,}\b/g },
  { type: "email", label: "Email", re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
  { type: "ip", label: "IPv4", re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g },
  { type: "uuid", label: "UUID", re: /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g },
  { type: "hash", label: "SHA-256", re: /\b[0-9a-fA-F]{64}\b/g },
  { type: "hash", label: "SHA-1", re: /\b[0-9a-fA-F]{40}\b/g },
];

export function scanInteresting(text: string): IvFinding[] {
  const src = text.length > MAX_SCAN ? text.slice(0, MAX_SCAN) : text;
  const seen = new Set<string>();
  const out: IvFinding[] = [];
  for (const rule of RULES) {
    const re = new RegExp(rule.re.source, "g");
    let m: RegExpExecArray | null;
    while ((m = re.exec(src)) !== null) {
      const value = m[0];
      const key = rule.type + ":" + value;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ type: rule.type, label: rule.label, value });
      if (out.length >= 60) return out;
    }
  }
  return out;
}

/** base64url (or base64) → UTF-8 text, or null if it is not decodable/printable. */
function b64decode(part: string): string | null {
  try {
    let b = part.replace(/-/g, "+").replace(/_/g, "/");
    while (b.length % 4) b += "=";
    const bin = atob(b);
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}

/** Decode a JWT's header and payload to pretty JSON (the signature is left as-is). */
export function decodeJwt(token: string): string | null {
  const parts = token.split(".");
  if (parts.length < 2) return null;
  const pretty = (p: string): string => {
    const raw = b64decode(p);
    if (raw === null) return "(undecodable)";
    try {
      return JSON.stringify(JSON.parse(raw), null, 2);
    } catch {
      return raw;
    }
  };
  return `header\n${pretty(parts[0] ?? "")}\n\npayload\n${pretty(parts[1] ?? "")}`;
}
