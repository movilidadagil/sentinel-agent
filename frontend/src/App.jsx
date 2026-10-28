import React, { useEffect, useRef, useState } from "react";
import { getHealth, validateTarget, streamScan } from "./api.js";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const STAGES = ["recon", "plan", "execute", "triage", "enrich", "report"];

function Badge({ ok, label }) {
  return (
    <span className={`badge ${ok ? "badge-on" : "badge-off"}`}>
      <span className="dot" /> {label} {ok ? "on" : "off"}
    </span>
  );
}

function SeverityBar({ findings }) {
  const counts = SEV_ORDER.reduce((acc, s) => ((acc[s] = 0), acc), {});
  findings
    .filter((f) => f.verdict !== "false_positive")
    .forEach((f) => (counts[f.severity] = (counts[f.severity] || 0) + 1));
  const total = Object.values(counts).reduce((a, b) => a + b, 0) || 1;

  return (
    <div className="sevbar">
      <div className="sevbar-track">
        {SEV_ORDER.map((s) =>
          counts[s] ? (
            <div
              key={s}
              className={`sev-seg sev-${s}`}
              style={{ width: `${(counts[s] / total) * 100}%` }}
              title={`${counts[s]} ${s}`}
            />
          ) : null
        )}
      </div>
      <div className="sev-legend">
        {SEV_ORDER.map((s) => (
          <span key={s} className="sev-legend-item">
            <span className={`swatch sev-${s}`} /> {s} · {counts[s]}
          </span>
        ))}
      </div>
    </div>
  );
}

function FindingCard({ f }) {
  const [open, setOpen] = useState(f.severity === "critical");
  return (
    <div className={`finding verdict-${f.verdict}`}>
      <button className="finding-head" onClick={() => setOpen(!open)}>
        <span className={`pill sev-${f.severity}`}>{f.severity}</span>
        <span className="finding-title">{f.title}</span>
        <span className={`verdict-tag v-${f.verdict}`}>{f.verdict}</span>
        <span className="cwe">{f.cwe}</span>
        <span className="chev">{open ? "▾" : "▸"}</span>
      </button>
      {open && (
        <div className="finding-body">
          <div className="meta-row">
            <span className="cat">{f.category}</span>
            <span className="endpoint">{f.endpoint}</span>
          </div>
          {f.triage_rationale && (
            <p className="rationale">
              <strong>Triage:</strong> {f.triage_rationale}
            </p>
          )}
          <div className="evidence">
            <div className="ev-label">Evidence</div>
            <code>{f.evidence.request_line}</code>
            {f.evidence.request_body && <code>{f.evidence.request_body}</code>}
            {f.evidence.response_status != null && (
              <div className="ev-status">
                HTTP {f.evidence.response_status}
                {f.evidence.indicator ? ` — ${f.evidence.indicator}` : ""}
              </div>
            )}
            {f.evidence.response_snippet && (
              <pre className="snippet">{f.evidence.response_snippet}</pre>
            )}
          </div>
          {f.remediation && (
            <div className="remediation">
              <div className="ev-label">Remediation</div>
              <p>{f.remediation}</p>
            </div>
          )}
          {f.sources?.length > 0 && (
            <div className="sources">
              <div className="ev-label">Live sources</div>
              <ul>
                {f.sources.map((s, i) => (
                  <li key={i}>
                    <a href={s.url} target="_blank" rel="noreferrer">
                      {s.title}
                    </a>
                    {s.published ? <span className="pub"> · {s.published}</span> : null}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function App() {
  const [health, setHealth] = useState(null);
  const [target, setTarget] = useState("http://localhost:3000");
  const [log, setLog] = useState([]);
  const [stageState, setStageState] = useState({});
  const [findings, setFindings] = useState([]);
  const [report, setReport] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState(null);
  const [allowed, setAllowed] = useState(null);
  const abortRef = useRef(null);
  const logEndRef = useRef(null);

  useEffect(() => {
    getHealth().then(setHealth).catch(() => setHealth(null));
  }, []);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [log]);

  useEffect(() => {
    if (!target) return;
    const t = setTimeout(() => {
      validateTarget(target)
        .then((r) => setAllowed(r.allowed))
        .catch(() => setAllowed(null));
    }, 300);
    return () => clearTimeout(t);
  }, [target]);

  function pushLog(ev) {
    setLog((l) => [...l, ev]);
  }

  function startScan() {
    setLog([]);
    setFindings([]);
    setReport(null);
    setError(null);
    setStageState({});
    setScanning(true);

    abortRef.current = streamScan(
      target,
      (ev) => {
        pushLog(ev);
        setStageState((s) => ({ ...s, [ev.stage]: ev.kind }));
        if (ev.stage === "triage" && ev.kind === "result" && ev.data) {
          setFindings((prev) => [...prev, ev.data]);
        }
        if (ev.stage === "enrich" && ev.kind === "result" && ev.data) {
          setFindings((prev) =>
            prev.map((f) => (f.id === ev.data.id ? ev.data : f))
          );
        }
        if (ev.stage === "report" && ev.kind === "done") {
          setReport(ev.data);
          setScanning(false);
        }
        if (ev.stage === "error") {
          setError(ev.message);
          setScanning(false);
        }
      },
      (err) => {
        setError(err.message);
        setScanning(false);
      }
    );
  }

  function stopScan() {
    abortRef.current?.();
    setScanning(false);
  }

  const sorted = [...findings].sort(
    (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
  );

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="logo">◆</span>
          <div>
            <h1>Sentinel</h1>
            <p className="tag">Autonomous application-security testing agent</p>
          </div>
        </div>
        {health && (
          <div className="health">
            <Badge ok={health.nebius_enabled} label="Nemotron" />
            <Badge ok={health.tavily_enabled} label="Tavily" />
            <span className="hosts" title="Allowlisted hosts">
              🛡 {health.allowed_hosts?.join(", ") || "none"}
            </span>
          </div>
        )}
      </header>

      <section className="control">
        <div className="target-row">
          <input
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="http://localhost:3000"
            disabled={scanning}
          />
          {!scanning ? (
            <button
              className="scan-btn"
              onClick={startScan}
              disabled={allowed === false}
            >
              Run scan
            </button>
          ) : (
            <button className="scan-btn stop" onClick={stopScan}>
              Stop
            </button>
          )}
        </div>
        {allowed === false && (
          <p className="warn">
            ⚠ This host is not on the allowlist. Add it to <code>ALLOWED_HOSTS</code>{" "}
            only if you are authorized to test it.
          </p>
        )}
        {error && <p className="warn">⚠ {error}</p>}
      </section>

      <section className="stages">
        {STAGES.map((st) => (
          <div
            key={st}
            className={`stage-chip ${stageState[st] ? "active" : ""} ${
              stageState[st] === "done" ? "done" : ""
            }`}
          >
            {st}
          </div>
        ))}
      </section>

      <div className="grid">
        <section className="panel feed">
          <h2>Agent activity</h2>
          <div className="log">
            {log.length === 0 && (
              <p className="muted">
                Point Sentinel at an authorized target and run a scan to watch it
                reason and test.
              </p>
            )}
            {log.map((ev, i) => (
              <div key={i} className={`log-line stage-${ev.stage}`}>
                <span className="stage-label">{ev.stage}</span>
                <span className="log-msg">{ev.message}</span>
              </div>
            ))}
            <div ref={logEndRef} />
          </div>
        </section>

        <section className="panel results">
          <h2>
            Findings{" "}
            {report && (
              <span className="muted small">
                · {report.stats.findings_total} real ·{" "}
                {report.stats.duration_seconds}s
              </span>
            )}
          </h2>
          {findings.length > 0 && <SeverityBar findings={findings} />}
          <div className="findings">
            {sorted.length === 0 && <p className="muted">No findings yet.</p>}
            {sorted.map((f) => (
              <FindingCard key={f.id} f={f} />
            ))}
          </div>
        </section>
      </div>

      <footer className="foot">
        Authorized testing only · host-allowlisted · evidence-backed · sourced
        remediation
      </footer>
    </div>
  );
}
