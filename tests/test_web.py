import io
import os

import pytest

from phishing_analyzer.parser import parse_eml_bytes
from phishing_analyzer.scoring import score_email
from phishing_analyzer.web import create_app

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("URLHAUS_AUTH_KEY", raising=False)

    app = create_app()
    app.config["TESTING"] = True

    with app.test_client() as c:
        yield c


def _upload(client, filename, ti=False):
    path = os.path.join(FIXTURES, filename)

    with open(path, "rb") as fp:
        data = {"eml_file": (io.BytesIO(fp.read()), filename)}

        if ti:
            data["ti"] = "on"

        return client.post(
            "/analyze",
            data=data,
            content_type="multipart/form-data",
        )


def _get_email_score(filename):
    path = os.path.join(FIXTURES, filename)

    with open(path, "rb") as fp:
        email = parse_eml_bytes(fp.read())

    return score_email(email)


def test_index_shows_upload_form(client):
    response = client.get("/")

    assert response.status_code == 200
    assert response.content_type.startswith("text/html")
    assert b"eml_file" in response.data


def test_index_hides_ti_checkbox_when_no_keys_configured(client):
    response = client.get("/")

    assert response.status_code == 200
    assert b'name="ti"' not in response.data


def test_index_shows_ti_checkbox_when_key_configured(client, monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "testkey")

    response = client.get("/")

    assert response.status_code == 200
    assert b'name="ti"' in response.data


def test_analyze_legit_email_shows_low_score(client):
    response = _upload(client, "legit_email.eml")
    result = _get_email_score("legit_email.eml")

    assert response.status_code == 200
    assert response.content_type.startswith("text/html")
    assert result.level == "low"


def test_analyze_phishing_email_shows_high_score_and_reasons(client):
    response = _upload(client, "phishing_paypal.eml")
    result = _get_email_score("phishing_paypal.eml")

    assert response.status_code == 200
    assert response.content_type.startswith("text/html")
    assert result.level == "high"
    assert len(result.reasons) > 0


def test_analyze_without_file_shows_error(client):
    response = client.post(
        "/analyze",
        data={},
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    assert response.content_type.startswith("text/html")
    assert len(response.data) > 0


def test_analyze_with_garbage_file_does_not_crash(client):
    data = {
        "eml_file": (
            io.BytesIO(b"not a real email but still bytes"),
            "junk.eml",
        )
    }

    response = client.post(
        "/analyze",
        data=data,
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
