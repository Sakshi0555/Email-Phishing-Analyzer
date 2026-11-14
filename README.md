# Phishing Email Analyzer

A standalone Python tool that parses raw `.eml` files and scores them for phishing indicators. Runs entirely offline by default — no mail server or lab infrastructure required — with optional VirusTotal / URLhaus threat intel enrichment and a lightweight web UI on top of the same analysis engine.

## Features

- **Email parsing** — reads raw `.eml` files (headers + body) using Python's standard library `email` module, handling multipart/HTML/plaintext bodies and attachments.
- **Authentication checks** — parses `Authentication-Results` for SPF / DKIM / DMARC pass/fail.
- **Header anomaly detection** — sender/reply-to mismatches, display-name brand spoofing (e.g. "PayPal Security" from a non-PayPal domain), and suspicious `Received` chains.
- **Link analysis** — extracts every URL from the HTML and plaintext body, flagging URL shorteners, IP-literal links, and anchor text that doesn't match its actual href.
- **Lookalike domain detection** — typosquat / combosquat detection against a brand list (stdlib-only Levenshtein distance) plus homograph/punycode detection.
- **Composite risk scoring** — a configurable weighted score (0–100, low/medium/high) combining every signal above, tunable via `data/scoring_weights.json`.
- **Threat intel enrichment (optional)** — VirusTotal + URLhaus domain reputation lookups, SQLite-cached with automatic rate-limit handling for VirusTotal's free tier. A confirmed-malicious verdict overrides the local score.
- **CLI and web UI** — analyze a single file or a whole folder from the command line (with JSON output), or use the Flask dashboard for a browser-based report.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
# Single file, human-readable report
phishing-analyzer path/to/email.eml

# Batch a folder, JSON output
phishing-analyzer path/to/folder --json

# With VirusTotal / URLhaus threat intel enrichment
phishing-analyzer path/to/email.eml --ti
```

## Threat intel setup

1. Copy `.env.example` to `.env` and fill in `VIRUSTOTAL_API_KEY` and/or `URLHAUS_AUTH_KEY`. Either alone is enough; both is better.
2. Run with `--ti`. A confirmed-malicious verdict from either source overrides the local heuristic score and forces the result to HIGH.
3. Lookups are cached in SQLite (`ti_cache.sqlite3` by default, configurable via `TI_CACHE_DB`) for 24 hours, so re-running against the same domains doesn't burn API quota. VirusTotal's free tier (4 req/min, 500 req/day) is enforced automatically — once the daily budget derived from the cache is exhausted, VirusTotal lookups are skipped for the rest of the run and scoring falls back to the local heuristics.

## Web UI

```bash
phishing-analyzer-web
```

Opens a dashboard at `http://127.0.0.1:5000`. Upload a `.eml`, get the same score/reasons/links/domain-matches report the CLI prints, rendered as HTML. If `VIRUSTOTAL_API_KEY` or `URLHAUS_AUTH_KEY` is set (via `.env`), a checkbox appears to enrich with threat intel on that upload. Set `PORT` to run on something other than 5000.

## Run tests

```bash
pytest        # 48 tests covering parsing, scoring, TI clients, and the web UI
ruff check .
black --check .
```

## Project layout

```
phishing_analyzer/
  parser.py    # .eml parsing into a normalized ParsedEmail
  headers.py   # SPF/DKIM/DMARC + header anomaly detection
  links.py     # URL/link extraction and flagging
  domains.py   # lookalike / homograph domain detection
  scoring.py   # composite weighted risk score
  cli.py       # command-line interface
  ti.py        # SQLite cache + VirusTotal/URLhaus clients + verdict merge
  web.py       # Flask dashboard over the same pipeline
data/
  brands.txt            # brand domains checked for lookalikes
  shorteners.txt         # known URL shortener domains
  scoring_weights.json   # configurable signal weights
tests/
  fixtures/*.eml   # sample legit + phishing emails used by the test suite
```

## Design notes

This tool intentionally never executes, renders, or fetches anything referenced inside an analyzed email — it only ever reads `.eml` files and passes extracted domains to threat intel APIs. SPF/DKIM/DMARC results come from the `Authentication-Results` header added by the receiving mail server rather than independent re-verification, since the tool is designed to work fully offline on an already-delivered `.eml`.

## License

MIT — see [LICENSE](LICENSE).
