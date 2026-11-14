"""M5 - Command-line interface. M6/M7 - optional --ti threat intel enrichment.

phishing-analyzer path/to/email.eml
phishing-analyzer path/to/folder --json
phishing-analyzer path/to/email.eml --weights custom_weights.json
phishing-analyzer path/to/email.eml --ti          # VirusTotal + URLhaus lookups
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

from phishing_analyzer.parser import parse_eml_file
from phishing_analyzer.scoring import RiskScoreResult, score_email
from phishing_analyzer.ti import (
    URLHausClient,
    VirusTotalClient,
    VirusTotalRateLimiter,
    init_cache_db,
    run_threat_intel,
)


def _find_eml_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    if path.is_dir():
        return sorted(path.glob("*.eml"))
    return []


def _result_to_dict(path: Path, result: RiskScoreResult) -> dict:
    return {
        "file": str(path),
        "score": result.score,
        "level": result.level,
        "reasons": result.reasons,
        "auth": (
            {
                "spf": result.header_result.spf,
                "dkim": result.header_result.dkim,
                "dmarc": result.header_result.dmarc,
            }
            if result.header_result
            else {}
        ),
        "links": [
            {
                "href": link.href,
                "source": link.source,
                "domain": link.domain,
                "is_ip_literal": link.is_ip_literal,
                "is_shortener": link.is_shortener,
                "anchor_href_mismatch": link.anchor_href_mismatch,
            }
            for link in result.link_results
        ],
        "domain_matches": [
            {
                "domain": m.domain,
                "matched_brand": m.matched_brand,
                "match_type": m.match_type,
                "edit_distance": m.edit_distance,
            }
            for m in result.domain_matches
        ],
        "threat_intel": [
            {
                "domain": r.domain,
                "source": r.source,
                "verdict": r.verdict,
                "from_cache": r.from_cache,
            }
            for r in result.ti_results
        ],
    }


def _print_text_report(path: Path, result: RiskScoreResult) -> None:
    print(f"\n{path}")
    print(f"  Risk score: {result.score}/100 ({result.level.upper()})")
    if result.header_result:
        h = result.header_result
        print(f"  SPF={h.spf}  DKIM={h.dkim}  DMARC={h.dmarc}")
    if result.ti_results:
        print("  Threat intel:")
        for r in result.ti_results:
            cache_tag = " (cached)" if r.from_cache else ""
            print(f"    - {r.domain}: {r.verdict} [{r.source}]{cache_tag}")
    if result.reasons:
        print("  Reasons:")
        for reason in result.reasons:
            print(f"    - {reason}")
    else:
        print("  No anomalies detected.")


def _load_weights(weights_path: str | None) -> dict | None:
    if not weights_path:
        return None
    with open(weights_path, "r", encoding="utf-8") as fp:
        return json.load(fp)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishing-analyzer",
        description="Parse .eml files and score them for phishing indicators.",
    )
    parser.add_argument("path", help="Path to a .eml file, or a folder of .eml files")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    parser.add_argument(
        "--weights", metavar="FILE", help="Path to a custom scoring_weights.json to use"
    )
    parser.add_argument(
        "--ti",
        action="store_true",
        help=(
            "Enrich with VirusTotal + URLhaus domain reputation lookups. "
            "Requires VIRUSTOTAL_API_KEY and/or URLHAUS_AUTH_KEY in the environment or .env file."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    load_dotenv()
    args = build_arg_parser().parse_args(argv)

    path = Path(args.path)
    files = _find_eml_files(path)
    if not files:
        print(f"No .eml files found at: {path}", file=sys.stderr)
        return 1

    weights = _load_weights(args.weights)

    vt_client = urlhaus_client = vt_limiter = cache_conn = None
    if args.ti:
        vt_key = os.environ.get("VIRUSTOTAL_API_KEY") or None
        urlhaus_key = os.environ.get("URLHAUS_AUTH_KEY") or None
        if not vt_key and not urlhaus_key:
            print(
                "--ti was passed but neither VIRUSTOTAL_API_KEY nor URLHAUS_AUTH_KEY is set; "
                "continuing without threat intel.",
                file=sys.stderr,
            )
        else:
            db_path = os.environ.get("TI_CACHE_DB", "ti_cache.sqlite3")
            cache_conn = init_cache_db(db_path)
            vt_client = VirusTotalClient(vt_key)
            urlhaus_client = URLHausClient(urlhaus_key)
            vt_limiter = VirusTotalRateLimiter(cache_conn)

    json_results = []
    for file_path in files:
        try:
            email = parse_eml_file(file_path)
            result = score_email(email, weights=weights)
            if cache_conn is not None:
                result = run_threat_intel(
                    email, result, cache_conn, vt_client, urlhaus_client, vt_limiter
                )
        except Exception as exc:  # noqa: BLE001 - CLI boundary, report and continue
            print(f"Failed to analyze {file_path}: {exc}", file=sys.stderr)
            continue

        if args.json:
            json_results.append(_result_to_dict(file_path, result))
        else:
            _print_text_report(file_path, result)

    if args.json:
        print(json.dumps(json_results, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
