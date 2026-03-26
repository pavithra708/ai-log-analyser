import { useState } from "react";

const INPUT_TYPES = ["text", "log", "sql", "chat", "file"];
const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

const PLACEHOLDERS = {
  text: "Paste your text here...",
  log: "2026-03-10 10:00:01 INFO password=admin123\napi_key=sk-prod-xyz\nERROR NullPointerException at service.java:45",
  sql: "SELECT * FROM users WHERE password='admin123';",
  chat: "User: my password is secret123\nBot: I can help you with that"
};

const RISK_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };

export default function App() {
  const [currentType, setCurrentType] = useState("text");
  const [content, setContent] = useState("");
  const [selectedFile, setSelectedFile] = useState(null);
  const [options, setOptions] = useState({
    mask: true,
    block_high_risk: true,
    log_analysis: true
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);

  const readApiResponse = async (res) => {
    const raw = await res.text();
    const contentType = res.headers.get("content-type") || "";
    let data = null;

    if (raw) {
      if (contentType.includes("application/json")) {
        try {
          data = JSON.parse(raw);
        } catch {
          throw new Error(`Server returned invalid JSON (HTTP ${res.status})`);
        }
      } else {
        try {
          data = JSON.parse(raw);
        } catch {
          if (!res.ok) {
            throw new Error(`HTTP ${res.status}: ${raw.slice(0, 200)}`);
          }
          throw new Error(`Expected JSON response but received non-JSON (HTTP ${res.status})`);
        }
      }
    }

    if (!res.ok) {
      const detail = data?.detail;
      if (typeof detail === "string" && detail.trim()) {
        throw new Error(detail);
      }
      throw new Error(`Request failed with status ${res.status}`);
    }

    if (!data) {
      throw new Error(`Empty response from server (HTTP ${res.status})`);
    }

    return data;
  };

  const onAnalyze = async () => {
    setLoading(true);
    setError("");
    setResult(null);

    try {
      let data;

      if (currentType === "file") {
        if (!selectedFile) {
          throw new Error("Please select a file");
        }
        const formData = new FormData();
        formData.append("file", selectedFile);
        const res = await fetch(`${API_BASE_URL}/analyze/file`, {
          method: "POST",
          body: formData
        });
        data = await readApiResponse(res);
      } else {
        const trimmed = content.trim();
        if (!trimmed) {
          throw new Error("Please enter some content to analyze");
        }
        const res = await fetch(`${API_BASE_URL}/analyze`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            input_type: currentType,
            content: trimmed,
            options
          })
        });
        data = await readApiResponse(res);
      }

      setResult(data);
    } catch (err) {
      setError(err.message || "Unexpected error");
    } finally {
      setLoading(false);
    }
  };

  const lineRiskMap = {};
  if (result?.findings?.length && currentType !== "file") {
    result.findings.forEach((finding) => {
      const existing = lineRiskMap[finding.line];
      if (!existing || RISK_ORDER[finding.risk] > RISK_ORDER[existing]) {
        lineRiskMap[finding.line] = finding.risk;
      }
    });
  }

  const inputLines = currentType !== "file" ? content.split("\n") : [];

  return (
    <div className="page">
      <div className="container">
        <header className="header">
          <h1>AI Secure Data Intelligence Platform</h1>
          <p>Detect sensitive data, analyze logs, and get AI-powered security insights</p>
        </header>

        <section className="card">
          <h2>Analyze Input</h2>

          <div className="typeRow">
            {INPUT_TYPES.map((type) => (
              <button
                key={type}
                className={`typeBtn ${currentType === type ? "active" : ""}`}
                onClick={() => setCurrentType(type)}
              >
                {type.toUpperCase()}
              </button>
            ))}
          </div>

          {currentType === "file" ? (
            <div className="fileBox">
              <input
                type="file"
                accept=".log,.txt,.sql,.pdf,.docx"
                onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
              />
              <p className="fileName">{selectedFile ? selectedFile.name : "No file selected"}</p>
            </div>
          ) : (
            <textarea
              className="contentInput"
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder={PLACEHOLDERS[currentType] || ""}
            />
          )}

          <div className="optionsRow">
            <label>
              <input
                type="checkbox"
                checked={options.mask}
                onChange={(e) => setOptions((v) => ({ ...v, mask: e.target.checked }))}
              />
              Mask sensitive values
            </label>
            <label>
              <input
                type="checkbox"
                checked={options.block_high_risk}
                onChange={(e) => setOptions((v) => ({ ...v, block_high_risk: e.target.checked }))}
              />
              Block high risk
            </label>
            <label>
              <input
                type="checkbox"
                checked={options.log_analysis}
                onChange={(e) => setOptions((v) => ({ ...v, log_analysis: e.target.checked }))}
              />
              Deep log analysis
            </label>
          </div>

          <button className="analyzeBtn" onClick={onAnalyze} disabled={loading}>
            {loading ? "Analyzing..." : "Analyze"}
          </button>
        </section>

        {error ? <div className="errorBox">{error}</div> : null}

        {result ? (
          result.action === "blocked" ? (
            <section className="card">
              <h2>Scan Summary</h2>
              <div className="summaryRow">
                <div>
                  <div className="score">{result.risk_score}</div>
                  <div className="muted">Risk Score</div>
                </div>
                <div className={`badge risk ${result.risk_level}`}>{result.risk_level}</div>
                <div className="badge action blocked">BLOCKED</div>
              </div>
              <div className="summaryText" style={{ color: "#fca5a5" }}>
                🚫 {result.reason || "Request blocked due to high risk level"}
              </div>
            </section>
          ) : (
            <>
              <section className="card">
                <h2>Scan Summary</h2>
                <div className="summaryRow">
                  <div>
                    <div className="score">{result.risk_score}</div>
                    <div className="muted">Risk Score</div>
                  </div>
                  <div className={`badge risk ${result.risk_level}`}>{result.risk_level}</div>
                  <div className={`badge action ${result.action}`}>{result.action}</div>
                  <div className="muted">
                    {result.total_lines} lines scanned - {result.findings?.length || 0} findings
                  </div>
                </div>

                <div className="summaryText">{result.summary || "No summary available"}</div>

                {result.breakdown ? (
                  <div className="pillRow">
                    {Object.entries(result.breakdown).map(([type, count]) => (
                      <span key={type} className="pill">
                        {type} <strong>{count}</strong>
                      </span>
                    ))}
                  </div>
                ) : null}
              </section>

              {result.insights?.length ? (
                <section className="card">
                  <h2>AI Security Insights</h2>
                  <ul className="list">
                    {result.insights.map((insight, idx) => (
                      <li key={`${insight}-${idx}`}>{insight}</li>
                    ))}
                  </ul>
                </section>
              ) : null}

              {result.anomalies?.length ? (
                <section className="card">
                  <h2>Anomalies Detected</h2>
                  <div className="anomalyList">
                    {result.anomalies.map((anomaly, idx) => (
                      <article key={`${anomaly.type}-${idx}`} className="anomalyItem">
                        <h3>{anomaly.type.replaceAll("_", " ")}</h3>
                        <p>{anomaly.description}</p>
                      </article>
                    ))}
                  </div>
                </section>
              ) : null}

              {result.findings?.length ? (
                <section className="card">
                  <h2>Findings</h2>
                  <div className="tableWrap">
                    <table className="table">
                      <thead>
                        <tr>
                          <th>Line</th>
                          <th>Type</th>
                          <th>Value</th>
                          <th>Risk</th>
                          <th>Description</th>
                        </tr>
                      </thead>
                      <tbody>
                        {result.findings.map((finding, idx) => (
                          <tr key={`${finding.type}-${finding.line}-${idx}`}>
                            <td>L{finding.line}</td>
                            <td>{finding.type}</td>
                            <td className="mono">{finding.value}</td>
                            <td>
                              <span className={`badge risk ${finding.risk}`}>{finding.risk}</span>
                            </td>
                            <td>{finding.description}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
              ) : null}

              {currentType !== "file" && inputLines.length ? (
                <section className="card">
                  <h2>Log Visualization</h2>
                  <div className="logViewer">
                    {inputLines.map((line, idx) => {
                      const lineNo = idx + 1;
                      const risk = lineRiskMap[lineNo];
                      return (
                        <div className={`logLine ${risk ? `hl-${risk}` : ""}`} key={lineNo}>
                          <span className="lineNo">{lineNo}</span>
                          <span className="lineContent">{line || " "}</span>
                          {risk ? <span className={`badge risk ${risk}`}>{risk}</span> : null}
                        </div>
                      );
                    })}
                  </div>
                </section>
              ) : null}
            </>
          )
        ) : null}
      </div>
    </div>
  );
}
