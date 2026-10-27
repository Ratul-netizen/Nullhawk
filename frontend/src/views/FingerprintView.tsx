import { useCallback, useEffect, useState } from "react";

import {
  describeError,
  scanFingerprint,
  type FingerprintReport,
} from "../ipc";

/**
 * The stack behind each host, named from traffic the project already captured.
 *
 * Read-only recon: it reads the stored responses and reports the web server, language,
 * framework, CMS, CDN or WAF it can name, citing the header or cookie behind every line.
 * A header is only a claim and a trivially spoofed one, so each line is a lead to confirm
 * rather than a settled fact. It sends nothing.
 */
export function FingerprintView({ hasProject }: { hasProject: boolean }) {
  const [data, setData] = useState<FingerprintReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setBusy(true);
    setError(null);
    try {
      setData(await scanFingerprint(null));
    } catch (e) {
      setError(describeError(e));
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    if (hasProject) void load();
  }, [hasProject, load]);

  if (!hasProject) {
    return <p className="placeholder">Open a project to fingerprint the hosts it has seen.</p>;
  }

  const techTotal = data?.hosts.reduce((n, h) => n + h.techs.length, 0) ?? 0;

  return (
    <div className="fingerprint">
      <div className="toolbar">
        <button disabled={busy} onClick={() => load()}>
          {busy ? "Reading…" : "Rescan"}
        </button>
        {data && (
          <span className="muted small">
            {data.responses} response(s) read, {data.hosts.length} host(s), {techTotal}{" "}
            technolog{techTotal === 1 ? "y" : "ies"} named
          </span>
        )}
      </div>

      {error && <p className="callout danger">{error}</p>}

      {data && data.hosts.length === 0 && (
        <p className="placeholder">
          No stack could be named from the captured headers and cookies. Bounded by what the
          responses advertised — proxy some traffic, then rescan.
        </p>
      )}

      {data?.hosts.map((host) => (
        <section className="card" key={host.host}>
          <h2>{host.host}</h2>
          <table className="tree">
            <tbody>
              {host.techs.map((tech) => (
                <tr key={tech.name}>
                  <td className="mono">{tech.name}</td>
                  <td className="muted">{tech.category}</td>
                  <td className="mono small">{tech.evidence}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ))}

      {data && data.hosts.length > 0 && (
        <p className="muted small">
          Each line is named by a header or cookie, which can be spoofed — treat it as a lead
          to confirm, not a settled fact.
        </p>
      )}
    </div>
  );
}
