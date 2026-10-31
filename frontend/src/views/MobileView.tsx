import { useCallback, useEffect, useState } from "react";

import {
  mobileSetup,
  mobileOnboardingStart,
  mobileOnboardingStop,
  type MobileSetup,
} from "../ipc";

/**
 * Mobile app testing, from the network side.
 *
 * A phone's traffic is just traffic, so the proxy and the CA that already read a
 * browser's HTTPS read an app's too — the work is pointing the device at them and
 * trusting the certificate. This view removes the two slow parts of that: it shows the
 * machine's real LAN IP (no digging in settings), and runs a small on-LAN server so the
 * phone fetches the CA and the setup steps from a single URL rather than by email or
 * `adb push`. The off-the-wire parts of a mobile assessment (pinning, the binary, local
 * storage) are said plainly so nobody mistakes an intercepting proxy for the whole job.
 */
export function MobileView() {
  const [setup, setSetup] = useState<MobileSetup | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(() => {
    mobileSetup()
      .then(setSetup)
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    refresh();
    // The proxy can be started/stopped on the Setup tab, so keep this in step.
    const t = setInterval(refresh, 4000);
    return () => clearInterval(t);
  }, [refresh]);

  const toggleOnboarding = async () => {
    setBusy(true);
    setError(null);
    try {
      const next = setup?.onboarding_running
        ? await mobileOnboardingStop()
        : await mobileOnboardingStart();
      setSetup(next);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const lanIp = setup?.lan_ip ?? null;
  const proxyPort = setup?.proxy_port ?? null;
  const proxyEndpoint = lanIp && proxyPort ? `${lanIp}:${proxyPort}` : null;

  return (
    <div className="mobile">
      <header className="dash-head">
        <div>
          <h1>Mobile app testing</h1>
          <p className="muted">
            Route a device's traffic through Nullhawk's proxy and trust its certificate,
            and every tool here — history, repeater, scanner, authz — works on the app's
            API the same as on a website.
          </p>
        </div>
      </header>

      <section className="card identity-card">
        <h2>1 · Point the device at the proxy</h2>
        {setup?.proxy_running ? (
          setup.proxy_loopback ? (
            <p className="notice warn">
              The proxy is bound to <code>127.0.0.1</code>, which a phone cannot reach.
              Restart it on the <strong>Setup</strong> tab bound to{" "}
              <code>0.0.0.0:{proxyPort}</code> so devices on the network can connect.
            </p>
          ) : proxyEndpoint ? (
            <>
              <p className="muted">
                On the device's Wi-Fi settings, set a <strong>manual HTTP proxy</strong>{" "}
                to:
              </p>
              <p className="mobile-endpoint">
                <code>{proxyEndpoint}</code>
              </p>
            </>
          ) : (
            <p className="muted">
              The proxy is listening on port <code>{proxyPort}</code>. Set the device's
              manual HTTP proxy to this machine's LAN IP and that port.
              {!lanIp && " (Could not detect the LAN IP automatically — read it from your network settings.)"}
            </p>
          )
        ) : (
          <p className="notice warn">
            The proxy is not running. Start it on the <strong>Setup</strong> tab first,
            then come back.
          </p>
        )}
        <ul className="steps">
          <li>
            <strong>Android</strong> — Settings → Wi-Fi → long-press the network → Modify →
            Advanced → Proxy: Manual.
          </li>
          <li>
            <strong>iOS</strong> — Settings → Wi-Fi → (i) → Configure Proxy → Manual.
          </li>
          {lanIp ? (
            <li className="muted small">
              Detected LAN IP: <code>{lanIp}</code>. The phone must be on the same network.
            </li>
          ) : (
            <li className="muted small">
              A phone needs this machine's IP on the shared network (e.g.{" "}
              <code>192.168.x.x</code>), not <code>127.0.0.1</code>.
            </li>
          )}
        </ul>
      </section>

      <section className="card identity-card">
        <h2>2 · Trust the CA certificate</h2>
        <p className="muted">
          Run the on-LAN setup server, then open its page on the phone's browser to
          download the CA and follow the per-OS steps — no email or <code>adb push</code>.
        </p>

        <div className="row-actions" style={{ marginBottom: 12 }}>
          <button onClick={toggleOnboarding} disabled={busy}>
            {setup?.onboarding_running ? "Stop setup server" : "Start setup server"}
          </button>
        </div>
        {error && <p className="notice warn">{error}</p>}

        {setup?.onboarding_running && (
          <p className="mobile-endpoint">
            On the phone, open{" "}
            <code>{setup.onboarding_url ?? `http://<this machine>:${setup.onboarding_port}/`}</code>
            {!setup.onboarding_url && (
              <span className="muted small">
                {" "}
                (LAN IP unknown — use this machine's IP with port {setup.onboarding_port})
              </span>
            )}
          </p>
        )}

        <dl className="facts">
          <dt>Fingerprint</dt>
          <dd className="mono small">{setup?.ca_fingerprint ?? "—"}</dd>
          <dt>Certificate file</dt>
          <dd className="mono small">{setup?.ca_path ?? "—"}</dd>
        </dl>
        <ul className="steps">
          <li>
            <strong>Android</strong> — the page's download opens the CA-install flow:
            Settings → Security → Install a certificate → CA certificate. Since Android 7,
            apps trust <em>user</em> CAs only if their network-security config opts in —
            otherwise patch the app or use a rooted device with the CA in the system store.
          </li>
          <li>
            <strong>iOS</strong> — install the downloaded profile, then Settings → General →
            About → Certificate Trust Settings and enable full trust for it.
          </li>
          <li className="muted small">
            Prefer to transfer it yourself? The <code>.crt</code> is at the path above.
          </li>
        </ul>
      </section>

      <section className="card identity-card">
        <h2>3 · Certificate pinning</h2>
        <p className="muted">
          A pinned app rejects even a trusted CA, so interception shows nothing until the
          pin is defeated. That is done off Nullhawk, on the device or the binary:
        </p>
        <ul className="steps">
          <li>
            <strong>Frida / objection</strong> — <code>objection --gadget &lt;app&gt;
            explore</code> then <code>android sslpinning disable</code> (or the iOS
            equivalent) on a rooted/jailbroken device or a re-signed build.
          </li>
          <li>
            <strong>Patch the app</strong> — repackage the APK with a network-security
            config that trusts user CAs, or hook the pinning class.
          </li>
          <li className="muted small">
            These use external tooling. Once the pin is down, the traffic lands in History
            like any other.
          </li>
        </ul>
      </section>

      <section className="card identity-card">
        <h2>4 · Off the wire</h2>
        <p className="muted">
          Interception covers the network. A full mobile assessment also looks at what the
          proxy never sees — and some of it comes back here:
        </p>
        <ul className="steps">
          <li>
            <strong>The binary</strong> — decompile the APK/IPA (jadx, apktool, unzip) and
            paste the strings into the <strong>Toolkit → Secret &amp; endpoint miner</strong>
            to pull hardcoded keys, endpoints and versioned libraries out of it.
          </li>
          <li>
            <strong>Local storage</strong> — shared preferences, SQLite, keychain/keystore
            entries, cached files: check for tokens and PII stored in the clear.
          </li>
          <li>
            <strong>Platform surface</strong> — exported activities/services, deep links
            and app-links, WebView <code>addJavascriptInterface</code>, cleartext-traffic
            flags, backup flags.
          </li>
          <li>
            <strong>The API</strong> — once traffic is flowing, treat it as any web API:
            replay as other identities on the Authorization tab, fuzz parameters, scan.
          </li>
        </ul>
      </section>
    </div>
  );
}
