import importlib
import json
import os
import re
import sys


def _csrf(client, path):
    response = client.get(path)
    match = re.search(rb'name="csrf_token" value="([^"]+)"', response.data)
    assert match, f"CSRF token missing from {path}"
    return match.group(1).decode()


def test_registration_login_vote_and_admin(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FLASK_SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("BALLOT_SECRET", "test-ballot-secret")
    monkeypatch.setenv("ALLOW_DEV_OTP", "true")
    monkeypatch.setenv("OTP_RESEND_COOLDOWN_SECONDS", "0")
    monkeypatch.setenv("ADMIN_USERNAME", "testadmin")
    monkeypatch.setenv("ADMIN_PASSWORD", "test-password-123")
    sys.modules.pop("app", None)
    sys.modules.pop("blockchain", None)
    securevote = importlib.import_module("app")
    securevote.app.config.update(TESTING=True)
    monkeypatch.setattr(securevote, "generate_otp", lambda: "123456")

    client = securevote.app.test_client()
    response = client.get("/health")
    assert response.status_code == 200

    response = client.post(
        "/register",
        data={"csrf_token": _csrf(client, "/register"), "full_name": "Test Voter", "email": "voter@example.com"},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"LOCAL DEVELOPMENT OTP: 123456" in response.data

    response = client.post(
        "/verify-registration-otp",
        data={"csrf_token": _csrf(client, "/verify-registration-otp"), "otp": "123456"},
        follow_redirects=True,
    )
    assert b"Registration complete" in response.data
    with securevote.app.app_context():
        row = securevote.get_db().execute("SELECT * FROM voters WHERE email = ?", ("voter@example.com",)).fetchone()
        voter_id = row["voter_id"]
        assert row["otp_code"] is None
        assert row["otp_hash"] is None

    response = client.post(
        "/login",
        data={"csrf_token": _csrf(client, "/login"), "voter_id": voter_id, "email": "voter@example.com"},
        follow_redirects=True,
    )
    assert b"LOCAL DEVELOPMENT OTP: 123456" in response.data
    response = client.post(
        "/login-otp",
        data={"csrf_token": _csrf(client, "/login-otp"), "otp": "123456"},
        follow_redirects=True,
    )
    assert b"Cast your vote" in response.data

    response = client.post(
        "/vote",
        data={"csrf_token": _csrf(client, "/vote"), "candidate_id": "C1"},
        follow_redirects=True,
    )
    assert b"Vote submitted successfully" in response.data
    assert len(securevote.blockchain.all_vote_blocks()) == 1

    response = client.post(
        "/vote",
        data={"csrf_token": _csrf(client, "/vote"), "candidate_id": "C2"},
        follow_redirects=True,
    )
    assert b"already voted" in response.data
    assert len(securevote.blockchain.all_vote_blocks()) == 1

    client.post("/logout", data={"csrf_token": _csrf(client, "/")})
    response = client.post(
        "/admin/login",
        data={"csrf_token": _csrf(client, "/admin/login"), "username": "testadmin", "password": "test-password-123"},
        follow_redirects=True,
    )
    assert b"Administrative Dashboard" in response.data
    assert b"Chain is valid" not in response.data or response.status_code == 200


def test_csrf_is_enforced(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FLASK_SECRET_KEY", "another-test-secret")
    monkeypatch.setenv("BALLOT_SECRET", "another-ballot-secret")
    monkeypatch.setenv("ALLOW_DEV_OTP", "true")
    sys.modules.pop("app", None)
    sys.modules.pop("blockchain", None)
    securevote = importlib.import_module("app")
    securevote.app.config.update(TESTING=True)
    client = securevote.app.test_client()
    response = client.post("/register", data={"full_name": "No Token", "email": "x@example.com"})
    assert response.status_code == 400


def test_railway_uses_attached_volume_and_production_mode(tmp_path, monkeypatch):
    monkeypatch.delenv("DATA_DIR", raising=False)
    monkeypatch.setenv("RAILWAY_PROJECT_ID", "test-project")
    monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", "production")
    monkeypatch.setenv("RAILWAY_VOLUME_MOUNT_PATH", str(tmp_path))
    monkeypatch.setenv("FLASK_SECRET_KEY", "railway-test-secret")
    monkeypatch.setenv("BALLOT_SECRET", "railway-test-ballot-secret")
    monkeypatch.setenv("ADMIN_USERNAME", "railway-admin")
    monkeypatch.setenv("ADMIN_PASSWORD", "railway-test-password")
    monkeypatch.setenv("EMAIL_PROVIDER", "brevo")
    monkeypatch.setenv("BREVO_API_KEY", "test-brevo-api-key")
    monkeypatch.setenv("SMTP_USER", "sender@example.com")
    sys.modules.pop("app", None)
    sys.modules.pop("blockchain", None)

    securevote = importlib.import_module("app")
    securevote.app.config.update(TESTING=True)

    assert securevote.IS_RAILWAY is True
    assert securevote.IS_PRODUCTION is True
    assert securevote.DATA_DIR == tmp_path.resolve()
    response = securevote.app.test_client().get("/health")
    assert response.status_code == 200
    assert response.get_json()["persistent_storage"] is True


def test_brevo_email_uses_https_api(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FLASK_SECRET_KEY", "brevo-test-secret")
    monkeypatch.setenv("BALLOT_SECRET", "brevo-test-ballot-secret")
    monkeypatch.setenv("ALLOW_DEV_OTP", "false")
    monkeypatch.setenv("EMAIL_PROVIDER", "brevo")
    monkeypatch.setenv("BREVO_API_KEY", "test-brevo-api-key")
    monkeypatch.setenv("SMTP_USER", "verified-sender@example.com")
    sys.modules.pop("app", None)
    sys.modules.pop("blockchain", None)
    securevote = importlib.import_module("app")

    captured = {}

    class FakeResponse:
        status = 201

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(securevote.urllib.request, "urlopen", fake_urlopen)
    delivered, dev_otp = securevote.send_otp_email("voter@example.com", "123456", "register")

    assert delivered is True
    assert dev_otp is None
    assert captured["timeout"] == 15
    assert captured["request"].full_url == "https://api.brevo.com/v3/smtp/email"
    assert captured["request"].get_method() == "POST"
    payload = json.loads(captured["request"].data)
    assert payload["sender"]["email"] == "verified-sender@example.com"
    assert payload["to"] == [{"email": "voter@example.com"}]
    assert "123456" in payload["textContent"]
