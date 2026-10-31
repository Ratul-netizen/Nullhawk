import { useCallback, useEffect, useState } from "react";

import {
  listIdentities,
  renewIdentity,
  type IdentityView,
  type ProjectSummary,
} from "../ipc";

/**
 * Session tokens, at hand from every view.
 *
 * A captured token expires mid-engagement and every authorization result then reads "the
 * credential may no longer be valid". The fix should not be a trip to the Setup tab and a
 * form: this sits in the top bar, shows each identity's remaining validity, and renews a
 * session in one click — replaying the login this identity recorded and adopting the fresh
 * token, never touching a browser dev tool. The credential itself never reaches here; only
 * its expiry does.
 */
export function SessionWidget({ project }: { project: ProjectSummary | null }) {
  const [identities, setIdentities] = useState<IdentityView[]>([]);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [, setTick] = useState(0);

  const reload = useCallback(() => {
    if (!project) {
      setIdentities([]);
      return;
    }
    listIdentities()
      .then(setIdentities)
      .catch(() => setIdentities([]));
  }, [project]);

  useEffect(() => {
    reload();
  }, [reload]);

  // Re-render periodically so the "valid 9m" countdown stays honest.
  useEffect(() => {
    const t = window.setInterval(() => setTick((n) => n + 1), 20_000);
    return () => window.clearInterval(t);
  }, []);

  const auth = identities.filter((i) => i.credential !== "none");
  if (!project || auth.length === 0) return null;

  const now = Math.floor(Date.now() / 1000);
  const remaining = (i: IdentityView): number =>
    i.expires === null ? Number.POSITIVE_INFINITY : i.expires - now;
  const klass = (secs: number): "ok" | "soon" | "expired" =>
    secs <= 0 ? "expired" : secs < 120 ? "soon" : "ok";
  const short = (secs: number): string => {
    if (!Number.isFinite(secs)) return "—";
    if (secs <= 0) return "expired";
    const m = Math.floor(secs / 60);
    return m >= 60 ? `${Math.floor(m / 60)}h ${m % 60}m` : m >= 1 ? `${m}m` : `${secs}s`;
  };

  const worst = auth.reduce((w, i) => Math.min(w, remaining(i)), Number.POSITIVE_INFINITY);

  const doRenew = async (id: string) => {
    setBusy(id);
    setNote(null);
    try {
      const u = await renewIdentity({
        who: id,
        from: "",
        cookie: null,
        header: null,
        jsonField: null,
        insecure: false,
      });
      setNote(`Renewed ${u.label}'s session.`);
      reload();
    } catch (e) {
      setNote(String(e));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="session-widget">
      <button
        className={`chip session-chip session-${klass(worst)}`}
        onClick={() => setOpen((o) => !o)}
        title="Session tokens — click to view and renew"
      >
        ⏱ sessions · {short(worst)}
      </button>
      {open && (
        <div className="session-pop" onMouseLeave={() => setOpen(false)}>
          {auth.map((i) => {
            const secs = remaining(i);
            const cls = klass(secs);
            return (
              <div className="session-row" key={i.id}>
                <span className="session-name mono">{i.label}</span>
                <span className={`sess-badge sess-${cls}`}>
                  {!Number.isFinite(secs)
                    ? "no expiry"
                    : secs <= 0
                      ? "expired"
                      : `valid ${short(secs)}`}
                </span>
                <button
                  className="chip-btn"
                  disabled={!i.has_login || busy === i.id}
                  title={
                    i.has_login
                      ? "Replay the recorded login and adopt the fresh token"
                      : "No recorded login to replay — capture one with browse --record-login"
                  }
                  onClick={() => void doRenew(i.id)}
                >
                  {busy === i.id ? "renewing…" : "renew"}
                </button>
              </div>
            );
          })}
          {note && <div className="session-note muted small">{note}</div>}
        </div>
      )}
    </div>
  );
}
