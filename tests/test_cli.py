import json
import os

from phishing_analyzer.cli import main

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def test_cli_single_file_text_output(capsys):
    path = os.path.join(FIXTURES, "phishing_paypal.eml")
    exit_code = main([path])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Risk score" in captured.out
    assert "HIGH" in captured.out


def test_cli_json_output_for_folder(capsys):
    exit_code = main([FIXTURES, "--json"])
    captured = capsys.readouterr()

    assert exit_code == 0
    data = json.loads(captured.out)
    assert len(data) == 3  # legit_email, phishing_paypal, minimal_no_received

    by_file = {os.path.basename(entry["file"]): entry for entry in data}
    assert by_file["legit_email.eml"]["level"] == "low"
    assert by_file["phishing_paypal.eml"]["level"] == "high"


def test_cli_missing_path_returns_nonzero(capsys):
    exit_code = main([os.path.join(FIXTURES, "does_not_exist.eml")])
    assert exit_code == 1
