from datetime import timedelta

import pytest

from inspector.db import to_text, utcnow

from conftest import HOST, PASSWORD, alerts_by, healthy

TOKEN = {"Authorization": "Bearer north-token-0123456789abcdef"}


def sample(host=HOST, seconds_ago=0, **overrides):
    return {"host": host, "datacenter": "SH01", "up": 1,
            "collected_at": to_text(utcnow() - timedelta(seconds=seconds_ago)), "values": healthy(**overrides)}


# ---------------------------------------------------------- login / roles
def test_pages_require_login(app):
    c = app.test_client()
    assert c.get("/").status_code == 302
    assert c.get("/api/v1/hosts").status_code == 401
    assert c.get("/health").status_code == 200


def test_bad_login(app):
    res = app.test_client().post("/login", data={"username": "otto", "password": "nope-nope-nope"})
    assert res.status_code == 401 and b"Invalid username or password" in res.data


def test_logout(login):
    c = login("vera")
    assert c.get("/api/v1/me").get_json()["role"] == "viewer"
    c.post("/logout")
    assert c.get("/api/v1/me").status_code == 401


@pytest.mark.parametrize("user, ack, silence, admin", [
    ("vera", 403, 403, 403), ("otto", 409, 201, 403), ("ada", 409, 201, 200)])
def test_role_permissions(login, user, ack, silence, admin):
    c = login(user)
    assert c.get("/api/v1/hosts").status_code == 200
    assert c.post("/api/v1/alerts/999/ack", json={"note": "x"}).status_code == ack
    assert c.post("/api/v1/silences", json={"host_pattern": "sh01-*", "duration_minutes": 60,
                                             "reason": "CHG-1"}).status_code == silence
    assert c.get("/api/v1/users").status_code == admin


def test_writes_must_be_json(login):
    """CSRF protection: a cross-site HTML form cannot send application/json."""
    res = login("ada").post("/api/v1/users", data={"username": "evil", "password": "x" * 12, "role": "admin"})
    assert res.status_code == 415


def test_index_hides_admin_tab_for_viewer(login):
    assert b'data-tab="admin"' in login("vera").get("/").data      # removed client-side by role
    assert b'const ROLE = "viewer"' in login("vera").get("/").data


# ---------------------------------------------------------- collector API
def test_ingest_requires_token(app):
    c = app.test_client()
    assert c.post("/api/v1/ingest", json={"samples": [sample()]}).status_code == 401
    assert c.post("/api/v1/ingest", json={"samples": [sample()]},
                  headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert c.get("/api/v1/collector/config").status_code == 401


def test_collector_config(app):
    cfg = app.test_client().get("/api/v1/collector/config", headers=TOKEN).get_json()
    assert cfg["interval_seconds"] == 30 and {c["name"] for c in cfg["checks"]} >= {"zombies", "uptime_s"}


def test_ingest_is_idempotent(app, conn):
    c = app.test_client()
    batch = {"samples": [sample(seconds_ago=30), sample()], "version": "2.0.0", "host_count": 5, "spooled": 0}
    assert c.post("/api/v1/ingest", json=batch, headers=TOKEN).get_json()["accepted"] == 2
    again = c.post("/api/v1/ingest", json=batch, headers=TOKEN).get_json()
    assert again == {"accepted": 0, "duplicates": 2, "alert_events": 0}
    row = conn.execute("SELECT last_seen_at, host_count, version FROM collectors WHERE name='sh-north'").fetchone()
    assert row["host_count"] == 5 and row["version"] == "2.0.0" and row["last_seen_at"]


@pytest.mark.parametrize("bad", [
    {"samples": []}, {"samples": "x"}, {"samples": [{"host": "a b"}]},
    {"samples": [{"host": "h", "collected_at": "yesterday"}]},
    {"samples": [{"host": "h", "collected_at": to_text(utcnow() + timedelta(hours=1))}]},
    {"samples": [{"host": "h", "collected_at": to_text(utcnow()), "values": {"cpu.percent": [1]}}]},
])
def test_ingest_validation(app, bad):
    assert app.test_client().post("/api/v1/ingest", json=bad, headers=TOKEN).status_code == 400


def test_ingest_raises_alert_visible_in_api(app, login):
    c = app.test_client()
    c.post("/api/v1/ingest", json={"samples": [sample(**{"service.nginx.up": 0.0})]}, headers=TOKEN)
    alerts = login("vera").get("/api/v1/alerts").get_json()["alerts"]
    assert [(a["rule"], a["target"], a["location"]) for a in alerts] == [("service_down", "nginx", "SH01-A01 U2")]
    host = login("vera").get("/api/v1/hosts").get_json()["hosts"][0]
    assert host["services_down"] == ["nginx"] and host["collector"] == "sh-north" and host["open_alerts"] == 1
    assert host["disks"] == {"/": 50.0}


# ---------------------------------------------------------- operator actions
def test_acknowledge_flow_and_audit(app, login, conn):
    app.test_client().post("/api/v1/ingest", json={"samples": [sample(**{"service.nginx.up": 0.0})]}, headers=TOKEN)
    alert_id = alerts_by(conn)[(HOST, "service_down", "nginx")]["id"]
    otto = login("otto")
    assert otto.post(f"/api/v1/alerts/{alert_id}/ack", json={"note": "INC-42 restarting"}).status_code == 200
    assert otto.post(f"/api/v1/alerts/{alert_id}/ack", json={"note": "again"}).status_code == 409
    a = alerts_by(conn)[(HOST, "service_down", "nginx")]
    assert a["acked_by"] == "otto" and a["ack_note"] == "INC-42 restarting"
    audit = login("ada").get("/api/v1/audit").get_json()["entries"]
    assert any(e["action"] == "alert_ack" and e["username"] == "otto" for e in audit)


def test_silence_lifecycle(login):
    otto = login("otto")
    res = otto.post("/api/v1/silences", json={"host_pattern": "sh03-*", "duration_minutes": 60, "reason": "CHG-77"})
    sid = res.get_json()["id"]
    listed = otto.get("/api/v1/silences").get_json()["silences"]
    assert listed[0]["active"] and listed[0]["created_by"] == "otto"
    assert otto.delete(f"/api/v1/silences/{sid}", json={}).status_code == 200
    assert otto.get("/api/v1/silences").get_json()["silences"] == []
    assert otto.post("/api/v1/silences", json={"host_pattern": "*", "duration_minutes": 60}).status_code == 400


# ---------------------------------------------------------- admin
def test_user_management(login):
    ada = login("ada")
    assert ada.post("/api/v1/users", json={"username": "newbie", "password": PASSWORD, "role": "viewer"}).status_code == 201
    assert ada.post("/api/v1/users", json={"username": "newbie", "password": PASSWORD}).status_code == 400
    assert ada.patch("/api/v1/users/newbie", json={"role": "operator"}).status_code == 200
    assert ada.patch("/api/v1/users/ada", json={"role": "viewer"}).status_code == 400    # last admin
    users = {u["username"]: u for u in ada.get("/api/v1/users").get_json()["users"]}
    assert users["newbie"]["role"] == "operator"
    assert "password_hash" not in users["newbie"]
    audit = ada.get("/api/v1/audit").get_json()["entries"]
    assert any(e["action"] == "user_update" and "role=operator" in e["detail"] for e in audit)


def test_password_never_written_to_audit(login, conn):
    login("ada").patch("/api/v1/users/vera", json={"password": "another-long-password"})
    details = " ".join(r[0] for r in conn.execute("SELECT detail FROM audit_log"))
    assert "another-long-password" not in details and "password=***" in details


def test_login_events_audited(app, conn):
    app.test_client().post("/login", data={"username": "otto", "password": "wrong-wrong-wrong"})
    app.test_client().post("/login", data={"username": "otto", "password": PASSWORD})
    actions = [r[0] for r in conn.execute("SELECT action FROM audit_log WHERE username='otto' ORDER BY id")]
    assert actions == ["login_failed", "login"]


# ---------------------------------------------------------- lookup / reports
def test_device_lookup(login):
    c = login("vera")
    assert c.get("/api/v1/devices?q=10.3.1.11").get_json()["devices"][0]["hostname"] == "sh03-a01-srv01"
    assert c.get("/api/v1/devices?q=hello").status_code == 400
    assert c.get("/api/v1/devices/AST-999999").status_code == 404


def test_reports(login, tmp_path):
    (tmp_path / "inspection report 20261118.html").write_text("<html>ok</html>")
    c = login("vera")
    assert c.get("/api/v1/reports").get_json()["reports"] == ["inspection report 20261118.html"]
    assert c.get("/reports/inspection report 20261118.html").status_code == 200
    assert c.get("/reports/../config/server.yaml").status_code == 404
    assert c.get("/reports/..%2Fconfig%2Fserver.yaml").status_code == 404
