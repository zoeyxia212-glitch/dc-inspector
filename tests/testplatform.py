"""API platform: personal tokens, request IDs, logging, health probes, headers, rate limits, OpenAPI."""

import json
import logging
import re
from datetime import timedelta

import pytest
import yaml
from conftest import PASSWORD

from inspector import auth
from inspector.app import OPENAPI_PATH, create_app
from inspector.db import utcnow
from inspector.logs import JsonFormatter, request_id_var


def make_token(client, **body):
    res = client.post("/api/v1/tokens", json={"name": "script", **body})
    assert res.status_code == 201, res.get_json()
    return res.get_json()


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------- personal API tokens
def test_token_works_for_scripts_and_secret_is_never_listed(app, login, conn):
    otto = login("otto")
    created = make_token(otto)
    assert created["token"].startswith("dci_") and created["role"] == "operator"
    script = app.test_client()  # no session cookie
    assert script.get("/api/v1/me", headers=bearer(created["token"])).get_json()["username"] == "otto"
    listed = otto.get("/api/v1/tokens").get_json()["tokens"][0]
    assert created["token"] not in json.dumps(listed) and listed["prefix"] == created["token"][:10]
    stored = conn.execute("SELECT token_hash FROM api_tokens").fetchone()[0]
    assert created["token"] not in stored


def test_token_role_is_capped_and_can_be_lower(app, login):
    otto = login("otto")
    assert otto.post("/api/v1/tokens", json={"name": "x", "role": "admin"}).status_code == 400
    readonly = make_token(otto, role="viewer")["token"]
    res = app.test_client().post(
        "/api/v1/silences", headers=bearer(readonly), json={"host_pattern": "*", "duration_minutes": 10, "reason": "x"}
    )
    assert res.status_code == 403  # owner may, the read-only token may not


def test_owner_downgrade_lowers_token_rights(app, login, conn):
    token = make_token(login("otto"))["token"]
    auth.update_user(conn, "otto", role="viewer")
    assert app.test_client().get("/api/v1/me", headers=bearer(token)).get_json()["role"] == "viewer"
    auth.update_user(conn, "otto", active=False)
    assert app.test_client().get("/api/v1/me", headers=bearer(token)).status_code == 401


def test_expired_and_revoked_tokens_rejected(app, login, conn):
    otto = login("otto")
    created = make_token(otto)
    conn.execute("UPDATE api_tokens SET expires_at = '2020-01-01T00:00:00Z'")
    assert app.test_client().get("/api/v1/me", headers=bearer(created["token"])).status_code == 401
    other = make_token(otto)
    res = otto.delete(f"/api/v1/tokens/{other['id']}", json={})
    assert res.status_code == 200
    assert app.test_client().get("/api/v1/me", headers=bearer(other["token"])).status_code == 401


def test_token_cannot_create_tokens(app, login):
    token = make_token(login("ada"))["token"]
    res = app.test_client().post("/api/v1/tokens", headers=bearer(token), json={"name": "chain"})
    assert res.status_code == 403


@pytest.mark.parametrize(
    "body", [{"name": ""}, {"name": "x", "expires_days": 0}, {"name": "x", "expires_days": 400}, {"name": "x" * 61}]
)
def test_token_validation(login, body):
    assert login("otto").post("/api/v1/tokens", json=body).status_code == 400


def test_only_owner_or_admin_can_revoke(login):
    token_id = make_token(login("otto"))["id"]
    res = login("vera").delete(f"/api/v1/tokens/{token_id}", json={})
    assert res.status_code == 404
    res = login("ada").delete(f"/api/v1/tokens/{token_id}", json={})
    assert res.status_code == 200


def test_token_actions_are_audited_with_token_name(app, login, conn):
    token = make_token(login("otto"), name="ci-bot")["token"]
    app.test_client().post(
        "/api/v1/silences",
        headers=bearer(token),
        json={"host_pattern": "sh03-*", "duration_minutes": 30, "reason": "CHG-9"},
    )
    detail = conn.execute("SELECT detail FROM audit_log WHERE action = 'silence_create'").fetchone()[0]
    assert detail.startswith("[token ci-bot]")


def test_last_used_is_recorded(app, login, conn):
    token = make_token(login("otto"))["token"]
    app.test_client().get("/api/v1/hosts", headers=bearer(token))
    assert conn.execute("SELECT last_used_at FROM api_tokens").fetchone()[0] is not None


def test_invalid_bearer_is_just_unauthenticated(app):
    assert app.test_client().get("/api/v1/me", headers=bearer("dci_nope")).status_code == 401


# ---------------------------------------------------------- request ID, headers, errors
def test_request_id_generated_or_propagated(app):
    c = app.test_client()
    generated = c.get("/health/live").headers["X-Request-ID"]
    assert re.fullmatch(r"[0-9a-f]{32}", generated)
    assert c.get("/health/live", headers={"X-Request-ID": "lb-abc.123"}).headers["X-Request-ID"] == "lb-abc.123"
    for bad in ("<script>alert(1)</script>", "has spaces", "x" * 65):  # log/header injection, size
        replaced = c.get("/health/live", headers={"X-Request-ID": bad}).headers["X-Request-ID"]
        assert replaced != bad and re.fullmatch(r"[0-9a-f]{32}", replaced)


def test_security_headers(app, login):
    res = login("vera").get("/api/v1/hosts")
    assert res.headers["X-Content-Type-Options"] == "nosniff"
    assert res.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in res.headers["Content-Security-Policy"]
    assert res.headers["Cache-Control"] == "no-store"
    assert "Strict-Transport-Security" not in res.headers  # only behind TLS


def test_hsts_when_secure_cookies(conn, settings, tmp_path, monkeypatch):
    monkeypatch.setenv("INSPECTOR_SECURE_COOKIES", "1")
    app = create_app(conn=conn, settings=settings, report_dir=tmp_path, secret_key="t")
    assert "max-age" in app.test_client().get("/health/live").headers["Strict-Transport-Security"]


def test_unhandled_error_hides_details_but_gives_request_id(app, caplog):
    app.config["PROPAGATE_EXCEPTIONS"] = False

    @app.get("/boom")
    def boom():
        raise RuntimeError("database password is hunter2")

    res = app.test_client().get("/boom", headers={"X-Request-ID": "req-500"})
    assert res.status_code == 500
    assert res.get_json() == {"error": "Internal server error", "request_id": "req-500"}
    assert "hunter2" not in res.get_data(as_text=True)


def test_bad_request_includes_request_id(login):
    res = login("otto").post(
        "/api/v1/alerts/1/ack", data="[]", content_type="application/json", headers={"X-Request-ID": "req-400"}
    )
    assert res.status_code == 400 and res.get_json()["request_id"] == "req-400"


# ---------------------------------------------------------- health probes
def test_liveness_and_readiness(app, conn):
    c = app.test_client()
    assert c.get("/health/live").status_code == 200
    ready = c.get("/health/ready").get_json()
    assert ready["checks"] == {"database": "ok", "schema": "ok"}
    conn.execute("PRAGMA user_version = 1")  # e.g. new code, migration not run
    res = c.get("/health/ready")
    assert res.status_code == 503 and "expected" in res.get_json()["checks"]["schema"]
    assert c.get("/health/live").status_code == 200  # liveness does not depend on the DB


# ---------------------------------------------------------- login rate limit
def test_login_rate_limited_per_address(conn, settings, tmp_path, users, monkeypatch):
    monkeypatch.setenv("INSPECTOR_LOGIN_LIMIT", "3")
    app = create_app(conn=conn, settings=settings, report_dir=tmp_path, secret_key="t")
    c = app.test_client()
    codes = [c.post("/login", data={"username": f"user{i}", "password": "x"}).status_code for i in range(4)]
    assert codes == [401, 401, 401, 429]
    assert c.post("/login", data={"username": "otto", "password": PASSWORD}).status_code == 429
    other = app.test_client().post(
        "/login", data={"username": "otto", "password": PASSWORD}, environ_base={"REMOTE_ADDR": "10.9.9.9"}
    )
    assert other.status_code == 302  # a different address is unaffected
    actions = [r[0] for r in conn.execute("SELECT action FROM audit_log")]
    assert "login_rate_limited" in actions


def test_rate_limiter_window():
    rl = auth.RateLimiter(2, 60)
    assert rl.allow("a", 0) and rl.allow("a", 1) and not rl.allow("a", 2)
    assert rl.allow("b", 2)
    assert rl.allow("a", 61)  # oldest hit left the window


# ---------------------------------------------------------- structured logging
def test_json_log_line_carries_request_id_and_fields():
    record = logging.LogRecord("inspector.access", logging.INFO, __file__, 1, "GET %s %s", ("/x", 200), None)
    record.status, record.duration_ms = 200, 3.2
    record.request_id = "rid-1"
    line = json.loads(JsonFormatter().format(record))
    assert line["message"] == "GET /x 200" and line["request_id"] == "rid-1"
    assert line["status"] == 200 and line["duration_ms"] == 3.2 and line["level"] == "INFO"


def test_access_log_written_per_request(app, login, caplog):
    with caplog.at_level(logging.INFO, logger="inspector.access"):
        login("vera").get("/api/v1/hosts", headers={"X-Request-ID": "trace-me"})
    records = [r for r in caplog.records if r.name == "inspector.access" and r.path == "/api/v1/hosts"]
    assert records and records[-1].status == 200 and records[-1].user == "vera"
    assert request_id_var.get() is None  # reset after the request


# ---------------------------------------------------------- OpenAPI contract
def _spec():
    return yaml.safe_load(OPENAPI_PATH.read_text())


def _app_routes(app):
    routes = set()
    for rule in app.url_map.iter_rules():
        path = re.sub(r"<(?:[a-z]+:)?([a-z_]+)>", r"{\1}", rule.rule)
        if path.startswith(("/api/v1/", "/health", "/metrics")):
            for method in rule.methods - {"HEAD", "OPTIONS"}:
                routes.add((path, method.lower()))
    return routes


def test_every_api_route_is_documented_and_vice_versa(app):
    documented = {(p, m) for p, ops in _spec()["paths"].items() for m in ops}
    routes = _app_routes(app)
    assert routes - documented == set(), "routes missing from openapi.yaml"
    assert documented - routes == set(), "openapi.yaml documents routes that do not exist"


def test_all_spec_references_resolve():
    spec = _spec()
    refs = re.findall(r"\$ref['\"]?:\s*['\"]?#/([^'\"}\s,]+)", OPENAPI_PATH.read_text())
    for ref in refs:
        node = spec
        for part in ref.split("/"):
            node = node[part]
    assert refs


def test_served_spec_has_current_version(app):
    from inspector import __version__

    spec = app.test_client().get("/api/v1/openapi.json").get_json()
    assert spec["info"]["version"] == __version__ and spec["openapi"].startswith("3.")


def test_docs_page_allows_its_cdn_only_there(app, login):
    docs = app.test_client().get("/api/docs")
    assert docs.status_code == 200 and "unpkg.com" in docs.headers["Content-Security-Policy"]
    assert "unpkg.com" not in login("vera").get("/").headers["Content-Security-Policy"]


def test_token_expiry_bound():
    assert auth.MAX_TOKEN_DAYS == 365 and timedelta(days=auth.MAX_TOKEN_DAYS) < timedelta(days=366)
    assert utcnow()
