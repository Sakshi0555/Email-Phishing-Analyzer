"""Email Phishing Analyzer - Modern Flask Dashboard."""

from __future__ import annotations

import os

from dotenv import load_dotenv
from flask import Flask, render_template_string, request

from phishing_analyzer.parser import parse_eml_bytes
from phishing_analyzer.scoring import RiskScoreResult, score_email
from phishing_analyzer.ti import (
    URLHausClient,
    VirusTotalClient,
    VirusTotalRateLimiter,
    init_cache_db,
    run_threat_intel,
)

_LEVEL_COLORS = {
    "low": "#16a36a",
    "medium": "#e99a28",
    "high": "#e34d59",
}

_STYLE = """
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800&family=Space+Grotesk:wght@500;600;700&display=swap');

:root {
  --bg: #f4f7fc;
  --surface: #ffffff;
  --text: #17243a;
  --muted: #718096;
  --blue: #3867e8;
  --border: #e7edf5;
  --green: #159b69;
  --red: #df4b5a;
  --orange: #dc9226;
}

* { box-sizing: border-box; }

body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: 'DM Sans', sans-serif;
}

.topbar {
  background: #111e36;
  color: white;
  padding: 19px 7%;
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.brand {
  font-family: 'Space Grotesk', sans-serif;
  font-size: 20px;
  font-weight: 700;
}

.brand span { color: #6c91ff; }

.top-tag {
  color: #b8c8e7;
  font-size: 12px;
  background: #243653;
  padding: 8px 13px;
  border-radius: 20px;
}

.container {
  max-width: 1100px;
  margin: 42px auto;
  padding: 0 22px;
}

h1, h2, h3 {
  font-family: 'Space Grotesk', sans-serif;
}

.page-heading {
  font-size: 30px;
  margin: 0 0 8px;
}

.subtitle {
  color: var(--muted);
  margin-bottom: 28px;
  line-height: 1.6;
}

.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 16px;
  padding: 25px;
  margin-bottom: 20px;
  box-shadow: 0 5px 20px rgba(25, 45, 80, .035);
}

.card-title {
  font-size: 18px;
  margin: 0 0 7px;
}

.card-description {
  font-size: 13px;
  color: var(--muted);
  margin: 0 0 20px;
}

.upload-box {
  border: 2px dashed #cbd7ed;
  border-radius: 14px;
  padding: 42px 20px;
  text-align: center;
  background: #f8faff;
  transition: .2s;
}

.upload-box:hover {
  border-color: var(--blue);
  background: #f1f5ff;
}

.upload-icon {
  font-size: 40px;
  margin-bottom: 12px;
}

input[type=file] {
  display: block;
  margin: 20px auto;
  max-width: 100%;
}

button {
  background: var(--blue);
  color: white;
  border: none;
  border-radius: 9px;
  padding: 13px 25px;
  font-size: 15px;
  font-weight: 700;
  cursor: pointer;
  font-family: inherit;
}

button:hover { background: #2853ce; }

.primary-button {
  width: 100%;
  margin-top: 18px;
}

.checkbox-row {
  display: flex;
  align-items: center;
  gap: 9px;
  color: #52627b;
  font-size: 13px;
  margin-top: 20px;
}

.error {
  background: #fff0f1;
  color: #bd3546;
  padding: 13px;
  border-radius: 9px;
  margin-bottom: 15px;
}

.back-link {
  display: inline-block;
  color: var(--blue);
  text-decoration: none;
  font-weight: 600;
  margin-bottom: 22px;
}

.back-link:hover { text-decoration: underline; }

.file-name {
  color: var(--muted);
  font-size: 13px;
  overflow-wrap: anywhere;
}

.summary-grid {
  display: grid;
  grid-template-columns: 1.1fr 1fr 1fr;
  gap: 17px;
  margin-bottom: 20px;
}

.summary-card {
  background: white;
  border: 1px solid var(--border);
  border-radius: 15px;
  padding: 22px;
  box-shadow: 0 5px 20px rgba(25,45,80,.035);
}

.summary-label {
  color: var(--muted);
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: .6px;
}

.summary-value {
  font-family: 'Space Grotesk', sans-serif;
  font-size: 27px;
  font-weight: 700;
  margin-top: 12px;
}

.summary-note {
  color: var(--muted);
  font-size: 12px;
  margin-top: 5px;
}

.risk-card {
  border-top: 4px solid var(--risk-color);
}

.risk-score {
  color: var(--risk-color);
  font-size: 38px;
  font-family: 'Space Grotesk', sans-serif;
  font-weight: 700;
  margin-top: 10px;
}

.risk-label {
  display: inline-block;
  background: var(--risk-bg);
  color: var(--risk-color);
  padding: 6px 12px;
  border-radius: 20px;
  font-size: 12px;
  font-weight: 800;
  margin-top: 8px;
}

.progress {
  height: 8px;
  background: #edf0f6;
  border-radius: 20px;
  overflow: hidden;
  margin-top: 15px;
}

.progress-fill {
  height: 100%;
  border-radius: 20px;
  background: var(--risk-color);
}

.check-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 13px;
}

.check-item {
  border: 1px solid var(--border);
  border-radius: 11px;
  padding: 15px;
}

.check-name {
  font-size: 13px;
  font-weight: 700;
}

.check-description {
  color: var(--muted);
  font-size: 11px;
  margin-top: 5px;
  line-height: 1.5;
}

.status {
  display: inline-block;
  margin-top: 12px;
  padding: 5px 10px;
  border-radius: 20px;
  font-size: 11px;
  font-weight: 800;
}

.status-good { background: #e5f7ef; color: #128254; }
.status-bad { background: #ffeaec; color: #c23c4d; }
.status-neutral { background: #edf1f7; color: #65738a; }
.status-warning { background: #fff4df; color: #a96b0d; }

.reason-item {
  display: flex;
  gap: 12px;
  padding: 14px;
  border-radius: 10px;
  background: #fff8ed;
  margin-top: 10px;
  color: #80551b;
  font-size: 14px;
  line-height: 1.5;
}

.reason-icon { font-size: 18px; }

.clean-message {
  padding: 16px;
  background: #eaf8f1;
  border-radius: 10px;
  color: #147c52;
  font-size: 14px;
}

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
}

th {
  color: #718096;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: .5px;
  background: #f7f9fc;
}

th, td {
  padding: 14px 12px;
  text-align: left;
  border-bottom: 1px solid var(--border);
}

td { overflow-wrap: anywhere; }

tr:last-child td { border-bottom: none; }

code {
  background: #edf2fb;
  color: #3556a0;
  padding: 4px 7px;
  border-radius: 5px;
  overflow-wrap: anywhere;
}

.table-wrap { overflow-x: auto; }

.explain {
  color: var(--muted);
  font-size: 12px;
  margin-top: 14px;
  line-height: 1.6;
}

.footer {
  text-align: center;
  color: #8a98ac;
  font-size: 12px;
  padding: 25px;
}

@media(max-width: 700px) {
  .summary-grid { grid-template-columns: 1fr; }
  .check-grid { grid-template-columns: 1fr; }
  .container { margin-top: 25px; }
  .page-heading { font-size: 24px; }
  .topbar { padding: 17px 20px; }
  .top-tag { display: none; }
  .card { padding: 18px; }
}
</style>
"""

_INDEX_TEMPLATE = (
    """
<!DOCTYPE html>
<html>
<head>
  <title>Email Phishing Analyzer</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  """
    + _STYLE
    + """
</head>
<body>
<header class="topbar">
  <div class="brand">Shield<span>Scan</span></div>
  <div class="top-tag">CYBERSECURITY ANALYSIS TOOL</div>
</header>

<main class="container">
  <h1 class="page-heading">Email Phishing Analyzer</h1>
  <p class="subtitle">
    Investigate suspicious emails and identify potential phishing threats.
    Upload an email file to begin your security analysis.
  </p>

  <section class="card">
    <h2 class="card-title">Analyze an email</h2>
    <p class="card-description">
      Upload a raw email file (.eml) for automated security inspection.
    </p>

    {% if error %}
      <div class="error">{{ error }}</div>
    {% endif %}

    <form method="post" action="/analyze" enctype="multipart/form-data">
      <div class="upload-box">
        <div class="upload-icon">📩</div>
        <strong>Upload your email file</strong>
        <p class="card-description">
          Select an .eml file from your computer
        </p>
        <input type="file" name="eml_file" accept=".eml" required>
      </div>

      {% if ti_available %}
      <label class="checkbox-row">
        <input type="checkbox" name="ti" {% if ti_default %}checked{% endif %}>
        Check links against external threat databases
      </label>
      {% else %}
      <p class="explain">
        External threat database checking is currently disabled.
        Configure your API keys to enable it.
      </p>
      {% endif %}

      <button class="primary-button" type="submit">
        🔍 Analyze Email
      </button>
    </form>
  </section>

  <section class="card">
    <h3 class="card-title">What does this tool check?</h3>
    <div class="check-grid">
      <div class="check-item">
        <div class="check-name">✉️ Sender identity</div>
        <div class="check-description">
          Checks sender and reply addresses for inconsistencies.
        </div>
      </div>
      <div class="check-item">
        <div class="check-name">🔗 Suspicious links</div>
        <div class="check-description">
          Checks for shortened links, IP addresses and misleading destinations.
        </div>
      </div>
      <div class="check-item">
        <div class="check-name">🛡️ Email security</div>
        <div class="check-description">
          Checks email authentication and domain protection results.
        </div>
      </div>
    </div>
  </section>
</main>
<footer class="footer">ShieldScan · Email Security & Digital Forensics</footer>
</body>
</html>
"""
)

_RESULT_TEMPLATE = (
    """
<!DOCTYPE html>
<html>
<head>
  <title>Analysis Results - ShieldScan</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  """
    + _STYLE
    + """
</head>
<body>
<header class="topbar">
  <div class="brand">Shield<span>Scan</span></div>
  <div class="top-tag">CYBERSECURITY ANALYSIS TOOL</div>
</header>

<main class="container">
  <a class="back-link" href="/">← Analyze another email</a>

  <h1 class="page-heading">Analysis Results</h1>
  <p class="subtitle">
    Here is the security analysis of your uploaded email.
  </p>

  <p class="file-name">📄 Analyzed file: {{ filename }}</p>

  <div class="summary-grid">
    <div class="summary-card risk-card"
         style="--risk-color:{{ color }}; --risk-bg:{{ risk_bg }}">
      <div class="summary-label">Overall phishing risk</div>
      <div class="risk-score">{{ result.score }}<span style="font-size:17px">/100</span></div>
      <span class="risk-label">{{ result.level|upper }} RISK</span>
      <div class="progress">
        <div class="progress-fill" style="width:{{ result.score }}%"></div>
      </div>
      <div class="summary-note">
        Higher scores indicate more suspicious characteristics.
      </div>
    </div>

    <div class="summary-card">
      <div class="summary-label">Suspicious indicators</div>
      <div class="summary-value">{{ result.reasons|length }}</div>
      <div class="summary-note">Warnings identified during analysis</div>
    </div>

    <div class="summary-card">
      <div class="summary-label">Links found</div>
      <div class="summary-value">{{ result.link_results|length }}</div>
      <div class="summary-note">Website links extracted from the email</div>
    </div>
  </div>

  <section class="card">
    <h2 class="card-title">Email security checks</h2>
    <p class="card-description">
      These checks help verify whether the email came from an authenticated sender.
    </p>

    {% if result.header_result %}
    <div class="check-grid">
      {% for name, value, description in checks %}
      <div class="check-item">
        <div class="check-name">{{ name }}</div>
        <div class="check-description">{{ description }}</div>
        <span class="status {{ value[1] }}">{{ value[0] }}</span>
      </div>
      {% endfor %}
    </div>
    {% else %}
      <p class="explain">No email authentication results were available.</p>
    {% endif %}
  </section>

  <section class="card">
    <h2 class="card-title">⚠️ Suspicious findings</h2>
    <p class="card-description">
      These are the reasons that contributed to the risk assessment.
    </p>

    {% if reasons %}
      {% for reason in reasons %}
      <div class="reason-item">
        <span class="reason-icon">⚠️</span>
        <span>{{ reason }}</span>
      </div>
      {% endfor %}
    {% else %}
      <div class="clean-message">
        ✓ No suspicious indicators were reported by the analysis engine.
      </div>
    {% endif %}
  </section>

  {% if result.link_results %}
  <section class="card">
    <h2 class="card-title">🔗 Link security analysis</h2>
    <p class="card-description">
      Each link is checked for characteristics commonly associated with phishing.
    </p>

    <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Website domain</th>
          <th>Found in</th>
          <th>IP address link</th>
          <th>Shortened link</th>
          <th>Misleading link</th>
        </tr>
      </thead>
      <tbody>
        {% for link in result.link_results %}
        <tr>
          <td><code>{{ link.domain }}</code></td>
          <td>{{ link.source }}</td>
          <td>
            <span class="status {{ 'status-warning' if link.is_ip_literal else 'status-good' }}">
              {{ 'Yes' if link.is_ip_literal else 'No' }}
            </span>
          </td>
          <td>
            <span class="status {{ 'status-warning' if link.is_shortener else 'status-good' }}">
              {{ 'Yes' if link.is_shortener else 'No' }}
            </span>
          </td>
          <td>
            <span class="status {{ 'status-bad' if link.anchor_href_mismatch else 'status-good' }}">
              {{ 'Yes' if link.anchor_href_mismatch else 'No' }}
            </span>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    </div>

    <p class="explain">
      IP address link: uses a numeric IP instead of a normal website domain.
      Shortened link: hides the original destination.
      Misleading link: the displayed link text differs from its actual destination.
      A warning is an indicator, not proof of phishing.
    </p>
  </section>
  {% endif %}

  {% if result.domain_matches %}
  <section class="card">
    <h2 class="card-title">Lookalike website detection</h2>
    <p class="card-description">
      Checks whether a website domain resembles a known brand.
    </p>
    <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Detected domain</th>
          <th>Similar brand</th>
          <th>Match type</th>
          <th>Character difference</th>
        </tr>
      </thead>
      <tbody>
        {% for match in result.domain_matches %}
        <tr>
          <td><code>{{ match.domain }}</code></td>
          <td>{{ match.matched_brand }}</td>
          <td>{{ match.match_type }}</td>
          <td>{{ match.edit_distance }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    </div>
    <p class="explain">
      Character difference indicates how many character edits separate
      the detected domain from the compared brand domain. Smaller values
      can indicate a closer resemblance.
    </p>
  </section>
  {% endif %}

  {% if result.ti_results %}
  <section class="card">
    <h2 class="card-title">External threat database results</h2>
    <p class="card-description">
      Results from available external threat intelligence services.
    </p>
    <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Domain</th>
          <th>Database</th>
          <th>Result</th>
          <th>Saved result</th>
        </tr>
      </thead>
      <tbody>
        {% for item in result.ti_results %}
        <tr>
          <td><code>{{ item.domain }}</code></td>
          <td>{{ item.source }}</td>
          <td>{{ item.verdict }}</td>
          <td>{{ 'Yes' if item.from_cache else 'No' }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    </div>
  </section>
  {% endif %}

  <div class="explain">
    Note: This tool provides automated indicators to assist investigation.
    A low risk score does not guarantee that an email is safe.
    Always verify suspicious emails independently.
  </div>
</main>

<footer class="footer">ShieldScan · Email Security & Digital Forensics</footer>
</body>
</html>
"""
)


def _ti_clients_available() -> bool:
    return bool(os.environ.get("VIRUSTOTAL_API_KEY") or os.environ.get("URLHAUS_AUTH_KEY"))


def _friendly_reason(reason: str) -> str:
    translations = {
        "From / Reply-To domain mismatch": "The sender address and reply address use different domains.",
        "From/Reply-To domain mismatch": "The sender address and reply address use different domains.",
    }
    return translations.get(reason, reason)


def _check_status(value: str) -> tuple[str, str]:
    value = str(value or "unknown").lower()

    if value == "pass":
        return "Passed", "status-good"
    if value == "fail":
        return "Failed", "status-bad"
    if value in ("softfail", "temperror", "permerror"):
        return (
            value.replace("softfail", "Soft fail")
            .replace("temperror", "Temporary error")
            .replace("permerror", "Permanent error"),
            "status-warning",
        )
    if value == "none":
        return "Not available", "status-neutral"
    return "Unknown", "status-neutral"


def create_app() -> Flask:
    load_dotenv()
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

    @app.get("/")
    def index():
        return render_template_string(
            _INDEX_TEMPLATE,
            error=None,
            ti_available=_ti_clients_available(),
            ti_default=True,
        )

    @app.post("/analyze")
    def analyze():
        uploaded = request.files.get("eml_file")

        if not uploaded or not uploaded.filename:
            return render_template_string(
                _INDEX_TEMPLATE,
                error="Please choose an email file before analyzing.",
                ti_available=_ti_clients_available(),
                ti_default=True,
            )

        if not uploaded.filename.lower().endswith(".eml"):
            return render_template_string(
                _INDEX_TEMPLATE,
                error="Please upload a valid .eml file.",
                ti_available=_ti_clients_available(),
                ti_default=True,
            )

        raw = uploaded.read()

        try:
            email = parse_eml_bytes(raw)
        except (ValueError, TypeError):
            return render_template_string(
                _INDEX_TEMPLATE,
                error="The uploaded email could not be read. Please check the file.",
                ti_available=_ti_clients_available(),
                ti_default=True,
            )

        result: RiskScoreResult = score_email(email)

        if request.form.get("ti") and _ti_clients_available():
            db_path = os.environ.get("TI_CACHE_DB", "ti_cache.sqlite3")
            cache_conn = init_cache_db(db_path)
            vt_client = VirusTotalClient(os.environ.get("VIRUSTOTAL_API_KEY") or None)
            urlhaus_client = URLHausClient(os.environ.get("URLHAUS_AUTH_KEY") or None)
            vt_limiter = VirusTotalRateLimiter(cache_conn)

            result = run_threat_intel(
                email,
                result,
                cache_conn,
                vt_client,
                urlhaus_client,
                vt_limiter,
            )

        header = result.header_result

        checks = []
        if header:
            checks = [
                (
                    "SPF verification",
                    _check_status(header.spf),
                    "Checks whether the sending server is authorized to send emails for this domain.",
                ),
                (
                    "DKIM verification",
                    _check_status(header.dkim),
                    "Checks the digital signature used to verify email authenticity.",
                ),
                (
                    "DMARC protection",
                    _check_status(header.dmarc),
                    "Checks the domain's policy for handling unauthenticated emails.",
                ),
            ]

        color = _LEVEL_COLORS.get(result.level, "#718096")
        risk_bg = {
            "low": "#e5f7ef",
            "medium": "#fff4df",
            "high": "#ffeaec",
        }.get(result.level, "#edf1f7")

        return render_template_string(
            _RESULT_TEMPLATE,
            filename=uploaded.filename,
            result=result,
            color=color,
            risk_bg=risk_bg,
            checks=checks,
            reasons=[_friendly_reason(r) for r in result.reasons],
        )

    return app


def main() -> None:
    app = create_app()
    port = int(os.environ.get("PORT", "5000"))
    print(f"ShieldScan running at http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=False)


if __name__ == "__main__":
    main()
