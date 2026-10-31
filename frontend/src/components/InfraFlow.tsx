import type { CSSProperties } from "react";

import type { SitemapHost } from "../ipc";
import type { DeviceType } from "./TopologyGraph";
import { classifyDevice, endpointKind, type HostSignals } from "../lib/appgraph";

/**
 * Infrastructure as the request path, not a node cloud.
 *
 * A node-link hairball tells you nothing about how an app is deployed. This lays the hosts
 * out left-to-right along the path a request actually takes — Client → Edge (a WAF or CDN,
 * if one answered) → Application → Data / services — placing each host in a tier from the
 * stack its responses advertised. Each card carries what we could read: the server and
 * framework, the zone, and the endpoint mix. A host that serves `/api` routes implies a
 * service tier behind it, shown as an inferred card rather than left unsaid.
 *
 * Everything here is a read of captured signals; nothing is probed. Inferred cards say so.
 */

const TYPE_COLOR: Record<string, string> = {
  server: "#5bb5aa",
  database: "#8098d9",
  router: "#d9b061",
  endpoint: "#7fa8c9",
  cloud: "#b48ad6",
  firewall: "#e0917a",
  unknown: "#8a93a3",
};

type Tier = "Client" | "Edge" | "Application" | "Data / services";

function tierOf(type: DeviceType): Tier {
  if (type === "firewall" || type === "router" || type === "cloud") return "Edge";
  if (type === "database") return "Data / services";
  return "Application";
}

interface Card {
  title: string;
  type: DeviceType;
  tech: string;
  zone: string;
  sub: string;
  inferred?: boolean;
}

function typeBreakdown(host: SitemapHost): string {
  const counts = new Map<string, number>();
  for (const p of host.paths) {
    const k = endpointKind(p);
    counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  const order = ["api", "page", "form", "asset", "redirect"];
  const parts = order
    .filter((k) => counts.get(k))
    .map((k) => `${counts.get(k)} ${k}`);
  return parts.join(" · ");
}

function buildTiers(
  hosts: SitemapHost[],
  signals: Map<string, HostSignals>,
): { tier: Tier; cards: Card[] }[] {
  const byTier = new Map<Tier, Card[]>([
    ["Client", [{ title: "Browser / API client", type: "endpoint", tech: "", zone: "", sub: "the caller" }]],
    ["Edge", []],
    ["Application", []],
    ["Data / services", []],
  ]);

  let anyApi = false;
  let appTech = "";
  for (const h of hosts) {
    const dev = classifyDevice(h.host, signals.get(h.host));
    const card: Card = {
      title: h.host,
      type: dev.type,
      tech: dev.tech,
      zone: dev.zone,
      sub: `${h.paths.length} endpoint${h.paths.length === 1 ? "" : "s"}${
        typeBreakdown(h) ? " · " + typeBreakdown(h) : ""
      }`,
    };
    byTier.get(tierOf(dev.type))!.push(card);
    if (h.paths.some((p) => endpointKind(p) === "api" || /\/api(\/|$)/.test(p.path))) {
      anyApi = true;
      if (!appTech && dev.tech) appTech = dev.tech;
    }
  }

  // A host that serves /api routes implies a service/API tier behind the app it is served
  // from — shown as inferred, since the backend host itself was not captured directly.
  if (anyApi && byTier.get("Data / services")!.length === 0) {
    byTier.get("Data / services")!.push({
      title: "API / service tier",
      type: "server",
      tech: appTech || "application server",
      zone: "backend",
      sub: "serves the /api routes",
      inferred: true,
    });
  }

  const order: Tier[] = ["Client", "Edge", "Application", "Data / services"];
  return order
    .map((tier) => ({ tier, cards: byTier.get(tier) ?? [] }))
    .filter((t) => t.cards.length > 0);
}

export function InfraFlow({
  hosts,
  signals,
  height = 430,
}: {
  hosts: SitemapHost[];
  signals: Map<string, HostSignals>;
  height?: number;
}) {
  const tiers = buildTiers(hosts, signals);

  return (
    <div style={{ ...wrap, minHeight: height }}>
      {tiers.map((t, ti) => (
        <div key={t.tier} style={tierWrapStyle}>
          <div style={tierColStyle}>
            <div style={tierLabel}>{t.tier}</div>
            {t.cards.map((c, i) => (
              <div key={c.title + i} style={cardStyle(c)}>
                <div style={cardHead}>
                  <span style={{ ...dot, background: TYPE_COLOR[c.type] ?? TYPE_COLOR.unknown }} />
                  <span style={cardTitle}>{c.title}</span>
                  {c.inferred && <span style={inferredTag}>inferred</span>}
                </div>
                {c.tech && <div style={cardLine}>{c.tech}</div>}
                <div style={cardSub}>{c.sub}</div>
                {c.zone && <div style={cardZone}>{c.zone}</div>}
              </div>
            ))}
          </div>
          {ti < tiers.length - 1 && <div style={arrow}>→</div>}
        </div>
      ))}
    </div>
  );
}

const wrap: CSSProperties = {
  display: "flex",
  alignItems: "flex-start",
  gap: 0,
  padding: "18px 14px",
  overflowX: "auto",
  width: "100%",
};

const tierWrapStyle: CSSProperties = { display: "flex", alignItems: "center", gap: 0 };

const tierColStyle: CSSProperties = {
  display: "flex",
  flexDirection: "column",
  gap: 10,
  minWidth: 190,
  maxWidth: 230,
};

const tierLabel: CSSProperties = {
  fontSize: 11,
  letterSpacing: "0.08em",
  textTransform: "uppercase",
  color: "var(--text-muted, #8a93a3)",
  fontFamily: "ui-monospace, monospace",
  marginBottom: 2,
};

function cardStyle(c: Card): CSSProperties {
  return {
    background: "var(--bg-raised, #141a21)",
    border: `1px solid ${c.inferred ? "var(--border, #2a3340)" : "var(--border, #2a3340)"}`,
    borderLeft: `3px solid ${TYPE_COLOR[c.type] ?? TYPE_COLOR.unknown}`,
    borderRadius: 7,
    padding: "9px 11px",
    opacity: c.inferred ? 0.78 : 1,
    borderStyle: c.inferred ? "dashed" : "solid",
  };
}

const cardHead: CSSProperties = { display: "flex", alignItems: "center", gap: 7 };
const dot: CSSProperties = { width: 9, height: 9, borderRadius: "50%", flex: "0 0 auto" };
const cardTitle: CSSProperties = {
  fontFamily: "ui-monospace, monospace",
  fontSize: 12.5,
  color: "var(--text, #e7eef4)",
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
};
const inferredTag: CSSProperties = {
  fontSize: 9.5,
  textTransform: "uppercase",
  letterSpacing: "0.05em",
  color: "var(--text-muted, #8a93a3)",
  border: "1px solid var(--border, #2a3340)",
  borderRadius: 4,
  padding: "0 4px",
  marginLeft: "auto",
};
const cardLine: CSSProperties = {
  fontSize: 11.5,
  color: "var(--text, #cdd6df)",
  marginTop: 5,
  fontFamily: "ui-monospace, monospace",
};
const cardSub: CSSProperties = { fontSize: 11, color: "var(--text-muted, #8a93a3)", marginTop: 4 };
const cardZone: CSSProperties = {
  fontSize: 10,
  color: "var(--text-muted, #8a93a3)",
  marginTop: 5,
  textTransform: "uppercase",
  letterSpacing: "0.05em",
};
const arrow: CSSProperties = {
  color: "var(--text-muted, #6b7683)",
  fontSize: 20,
  padding: "0 10px",
  alignSelf: "center",
  flex: "0 0 auto",
};
