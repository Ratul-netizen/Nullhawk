import { useMemo, useState, type CSSProperties } from "react";

import type { SitemapHost, SitemapPath } from "../ipc";
import type { DeviceType } from "./TopologyGraph";
import { endpointKind } from "../lib/appgraph";

/**
 * The application's shape as a treemap, not a node-link cloud.
 *
 * A real app serves hundreds or thousands of resources; an orbiting graph of them is a
 * pretty hairball you cannot read. A treemap stays legible at that scale: every endpoint
 * is a cell coloured by type, nested under its URL path (`/api/v1`, `/src/components`), and
 * sized by how many endpoints sit under it — so the type mix and the heavy areas of the
 * surface are both visible at a glance. The top couple of levels are outlined and labelled;
 * click a group to drill into it, the breadcrumb walks back out.
 *
 * Sizing is endpoint count — the sitemap carries no per-path byte or request total yet.
 * When the engine exposes those, swap `value` for them and the layout is unchanged.
 */

const TYPE_COLOR: Record<string, string> = {
  page: "#5bb5aa",
  api: "#8098d9",
  form: "#d9b061",
  asset: "#8a93a3",
  redirect: "#7fa8c9",
  server: "#5bb5aa",
};

interface TNode {
  name: string;
  key: string;
  value: number;
  type?: DeviceType;
  path?: SitemapPath;
  children?: TNode[];
  x0: number;
  y0: number;
  x1: number;
  y1: number;
}

function newNode(name: string, key: string): TNode {
  return { name, key, value: 0, x0: 0, y0: 0, x1: 0, y1: 0 };
}

function buildTree(hosts: SitemapHost[]): TNode {
  const root = newNode("", "");
  root.children = [];
  const multi = hosts.length > 1;

  const child = (parent: TNode, name: string, key: string): TNode => {
    parent.children ??= [];
    let c = parent.children.find((n) => n.name === name);
    if (!c) {
      c = newNode(name, key);
      parent.children.push(c);
    }
    return c;
  };

  for (const host of hosts) {
    const hostNode = multi ? child(root, host.host, `host:${host.host}`) : root;
    for (const p of host.paths) {
      const segs = (p.path.split("?")[0] ?? p.path).split("/").filter(Boolean);
      let node = hostNode;
      let acc = multi ? `host:${host.host}` : "";
      for (const s of segs) {
        acc += "/" + s;
        node = child(node, s, acc);
      }
      node.type = endpointKind(p);
      node.path = p;
    }
  }

  // A path that is also a prefix of others gets a synthetic "·" leaf for its own cell, and
  // every node's value is the endpoint count beneath it.
  const normalize = (n: TNode): number => {
    if (n.children && n.children.length) {
      if (n.path) {
        const leaf = newNode("·", n.key + "#index");
        leaf.value = 1;
        if (n.type) leaf.type = n.type;
        leaf.path = n.path;
        n.children.push(leaf);
      }
      n.value = n.children.reduce((s, c) => s + normalize(c), 0);
    } else {
      n.value = 1;
    }
    return n.value;
  };
  normalize(root);
  return root;
}

const HEADER = 16; // group label strip, reserved only on labelled groups

const labelled = (n: TNode, depth: number) =>
  depth < 2 && n.x1 - n.x0 > 30 && n.y1 - n.y0 > 26;

/** Squarified treemap of ONE node's direct children into [x0,y0,x1,y1]. No recursion. */
function squarifyInto(node: TNode, x0: number, y0: number, x1: number, y1: number): void {
  const kids = (node.children ?? []).filter((c) => c.value > 0).sort((a, b) => b.value - a.value);
  const w = x1 - x0;
  const h = y1 - y0;
  const total = kids.reduce((s, c) => s + c.value, 0);
  if (!kids.length || total <= 0 || w <= 0 || h <= 0) return;
  const scale = (w * h) / total;

  const worst = (row: TNode[], side: number, s: number): number => {
    const areas = row.map((c) => c.value * s);
    const sum = areas.reduce((a, b) => a + b, 0);
    const max = Math.max(...areas);
    const min = Math.min(...areas);
    const side2 = side * side;
    const sum2 = sum * sum;
    return Math.max((side2 * max) / sum2, sum2 / (side2 * min));
  };

  let ax = x0;
  let ay = y0;
  let aw = w;
  let ah = h;
  let i = 0;
  while (i < kids.length) {
    const vertical = aw >= ah;
    const side = vertical ? ah : aw;
    const row: TNode[] = [];
    let best = Infinity;
    while (i < kids.length) {
      const cand = kids[i];
      if (!cand) break;
      const ratio = worst([...row, cand], side, scale);
      if (row.length && ratio > best) break;
      row.push(cand);
      best = worst(row, side, scale);
      i++;
    }
    const rowSum = row.reduce((a, c) => a + c.value, 0);
    const rowThick = side > 0 ? (rowSum * scale) / side : 0;
    let off = vertical ? ay : ax;
    for (const c of row) {
      const cLen = (rowSum > 0 ? c.value / rowSum : 0) * side;
      if (vertical) {
        c.x0 = ax;
        c.y0 = off;
        c.x1 = ax + rowThick;
        c.y1 = off + cLen;
      } else {
        c.x0 = off;
        c.y0 = ay;
        c.x1 = off + cLen;
        c.y1 = ay + rowThick;
      }
      off += cLen;
    }
    if (vertical) {
      ax += rowThick;
      aw -= rowThick;
    } else {
      ay += rowThick;
      ah -= rowThick;
    }
  }
}

/** Lay out the whole subtree. Leaves are drawn; groups recurse fully, reserving a label
 *  strip only on the shallow, roomy ones. */
function layout(node: TNode, x0: number, y0: number, x1: number, y1: number, depth: number): void {
  squarifyInto(node, x0, y0, x1, y1);
  for (const c of node.children ?? []) {
    if (c.children && c.children.length) {
      const head = labelled(c, depth) ? HEADER : 0;
      const ix0 = c.x0 + 1;
      const iy0 = c.y0 + head + 1;
      const ix1 = c.x1 - 1;
      const iy1 = c.y1 - 1;
      if (ix1 > ix0 && iy1 > iy0) layout(c, ix0, iy0, ix1, iy1, depth + 1);
    }
  }
}

function collect(
  node: TNode,
  depth: number,
  groups: TNode[],
  cells: TNode[],
): void {
  for (const c of node.children ?? []) {
    const w = c.x1 - c.x0;
    const h = c.y1 - c.y0;
    if (c.children && c.children.length) {
      if (labelled(c, depth)) groups.push(c);
      collect(c, depth + 1, groups, cells);
    } else if (w >= 1.2 && h >= 1.2) {
      cells.push(c);
    }
  }
}

export function AppTreemap({ hosts, height = 430 }: { hosts: SitemapHost[]; height?: number }) {
  const [focusKey, setFocusKey] = useState<string>("");
  const [hover, setHover] = useState<{ node: TNode; x: number; y: number } | null>(null);
  const [w, setW] = useState(820);

  const root = useMemo(() => buildTree(hosts), [hosts]);

  const { focus, trail } = useMemo(() => {
    if (!focusKey) return { focus: root, trail: [root] };
    const path: TNode[] = [];
    const find = (n: TNode): boolean => {
      path.push(n);
      if (n.key === focusKey) return true;
      for (const c of n.children ?? []) if (find(c)) return true;
      path.pop();
      return false;
    };
    find(root);
    const last = path[path.length - 1];
    return last ? { focus: last, trail: path } : { focus: root, trail: [root] };
  }, [root, focusKey]);

  const { groups, cells } = useMemo(() => {
    // Reserve a strip at the top for the breadcrumb so it never sits over a group's label.
    layout(focus, 0, 24, w, height, 0);
    const groups: TNode[] = [];
    const cells: TNode[] = [];
    collect(focus, 0, groups, cells);
    return { groups, cells };
  }, [focus, w, height]);

  const color = (n: TNode) => TYPE_COLOR[n.type ?? "page"] ?? "#8a93a3";
  const drill = (key: string) => setFocusKey(key);

  return (
    <div
      className="treemap-wrap"
      ref={(el) => {
        if (el && el.clientWidth && Math.abs(el.clientWidth - w) > 2) setW(el.clientWidth);
      }}
      style={{ position: "relative", width: "100%", height }}
      onMouseLeave={() => setHover(null)}
    >
      <svg width="100%" height={height} style={{ display: "block" }}>
        {/* leaf cells — every endpoint, coloured by type */}
        {cells.map((c) => {
          const cw = c.x1 - c.x0;
          const ch = c.y1 - c.y0;
          const isHover = hover?.node.key === c.key;
          return (
            <g
              key={c.key}
              onMouseMove={(e) => {
                const host = e.currentTarget.ownerSVGElement?.parentElement as HTMLElement | null;
                const r = host?.getBoundingClientRect();
                setHover({ node: c, x: e.clientX - (r?.left ?? 0), y: e.clientY - (r?.top ?? 0) });
              }}
            >
              <rect
                x={c.x0}
                y={c.y0}
                width={Math.max(0, cw)}
                height={Math.max(0, ch)}
                rx={1.5}
                fill={color(c)}
                fillOpacity={isHover ? 1 : 0.82}
                stroke={isHover ? "var(--text, #e7eef4)" : "var(--bg, #0e1319)"}
                strokeWidth={isHover ? 1.5 : 0.5}
              />
              {cw > 44 && ch > 15 && (
                <text
                  x={c.x0 + 4}
                  y={c.y0 + 12}
                  fontSize={10.5}
                  fontFamily="ui-monospace, monospace"
                  fill="#0c0f14"
                  style={{ pointerEvents: "none" }}
                >
                  {clip(c.name || "/", (cw - 8) / 6)}
                </text>
              )}
            </g>
          );
        })}

        {/* group outlines + labels (over leaves); the header strip is the drill target */}
        {groups.map((g) => (
          <g key={"g" + g.key}>
            <rect
              x={g.x0}
              y={g.y0}
              width={Math.max(0, g.x1 - g.x0)}
              height={Math.max(0, g.y1 - g.y0)}
              rx={3}
              fill="none"
              stroke="var(--border, #2a3340)"
              strokeWidth={1}
              pointerEvents="none"
            />
            <rect
              x={g.x0}
              y={g.y0}
              width={Math.max(0, g.x1 - g.x0)}
              height={HEADER}
              fill="var(--bg-raised, rgba(14,19,25,0.82))"
              fillOpacity={0.82}
              style={{ cursor: "pointer" }}
              onClick={() => drill(g.key)}
            />
            <text
              x={g.x0 + 5}
              y={g.y0 + 11.5}
              fontSize={11}
              fontFamily="ui-monospace, monospace"
              fill="var(--text-muted, #9aa6b2)"
              style={{ pointerEvents: "none" }}
            >
              {clip((g.name || "/") + " · " + g.value, (g.x1 - g.x0 - 10) / 6.2)}
            </text>
          </g>
        ))}
      </svg>

      <div className="treemap-crumbs" style={crumbStyle}>
        {trail.map((t, i) => (
          <span key={t.key || "root"}>
            {i > 0 && <span style={{ opacity: 0.5, margin: "0 4px" }}>›</span>}
            <button type="button" onClick={() => drill(t.key)} style={crumbBtn}>
              {i === 0 ? "all" : t.name || "/"}
            </button>
          </span>
        ))}
      </div>

      {hover && (
        <div
          style={{
            position: "absolute",
            left: Math.min(hover.x + 12, w - 230),
            top: Math.min(hover.y + 12, height - 56),
            pointerEvents: "none",
            background: "var(--bg-raised, #141a21)",
            border: "1px solid var(--border, #2a3340)",
            borderRadius: 6,
            padding: "6px 9px",
            fontSize: 12,
            maxWidth: 250,
            boxShadow: "0 4px 16px rgba(0,0,0,0.4)",
            zIndex: 5,
          }}
        >
          <div
            style={{
              fontFamily: "ui-monospace, monospace",
              color: "var(--text, #e7eef4)",
              wordBreak: "break-all",
            }}
          >
            {hover.node.path?.path ?? hover.node.name}
          </div>
          <div style={{ color: "var(--text-muted, #8a93a3)", marginTop: 3 }}>
            {hover.node.type ?? "endpoint"}
            {hover.node.path &&
              ` · ${hover.node.path.methods.join(", ")} · ${hover.node.path.statuses.join(", ")}`}
          </div>
        </div>
      )}
    </div>
  );
}

function clip(s: string, maxChars: number): string {
  const n = Math.max(1, Math.floor(maxChars));
  return s.length > n ? s.slice(0, Math.max(1, n - 1)) + "…" : s;
}

const crumbStyle: CSSProperties = {
  position: "absolute",
  top: 6,
  left: 8,
  display: "flex",
  flexWrap: "wrap",
  gap: 2,
  alignItems: "center",
  fontSize: 12,
  background: "var(--bg-raised, rgba(20,26,33,0.9))",
  border: "1px solid var(--border, #2a3340)",
  borderRadius: 6,
  padding: "2px 7px",
};

const crumbBtn: CSSProperties = {
  background: "none",
  border: "none",
  color: "var(--accent, #5bb5aa)",
  cursor: "pointer",
  font: "inherit",
  padding: 0,
};
