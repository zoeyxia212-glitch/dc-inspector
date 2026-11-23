from datetime import timedelta

import pytest
from conftest import HOST, PASSWORD, alerts_by, healthy

from inspector.db import to_text, utcnow

TOKEN = {"Authorization": "Bearer dcc_north0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZab"}


def sample(host=HOST, seconds_ago=0, **overrides):
    return {
        "host": host,
        "datacenter": "SH01",
        "up": 1,
        "collected_at": to_text(utcnow() - timedelta(seconds=seconds_ago)),
        "values": healthy(**overrides),
    }


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


@pytest.mark.parametrize(
    "user, ack, silence, admin", [("vera", 403, 403, 403), ("otto", 409, 201, 403), ("ada", 409, 201, 200)]
)
def test_role_permissions(login, user, ack, silence, admin):
    c = login(user)
    assert c.get("/api/v1/hosts").status_code == 200
    assert c.post("/api/v1/alerts/999/ack", json={"note": "x"}).status_code == ack
    assert (
        c.post(
            "/api/v1/silences", json={"host_pattern": "sh01-*", "duration_minutes": 60, "reason": "CHG-1"}
        ).status_code
        == silence
    )
    assert c.get("/api/v1/users").status_code == admin


def test_writes_must_be_json(login):
    """CSRF protection: a cross-site HTML form cannot send application/json."""
    res = login("ada").post("/api/v1/users", data={"username": "evil", "password": "x" * 12, "role": "admin"})
    assert res.status_code == 415


def test_index_hides_admin_tab_for_viewer(login):
    assert b'data-tab="admin"' in login("vera").get("/").data  # removed client-side by role
    assert b'const ROLE = "viewer"' in login("vera").get("/").data


# ---------------------------------------------------------- collector API
def test_ingest_requires_token(app):
    c = app.test_client()
    assert c.post("/api/v1/ingest", json={"samples": [sample()]}).status_code == 401
    assert (
        c.post("/api/v1/ingest", json={"samples": [sample()]}, headers={"Authorization": "Bearer wrong"}).status_code
        == 401
    )
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


@pytest.mark.parametrize(
    "bad",
    [
        {"samples": []},
        {"samples": "x"},
        {"samples": [{"host": "a b"}]},
        {"samples": [{"host": "h", "collected_at": "yesterday"}]},
        {"samples": [{"host": "h", "collected_at": to_text(utcnow() + timedelta(hours=1))}]},
        {"samples": [{"host": "h", "collected_at": to_text(utcnow()), "values": {"cpu.percent": [1]}}]},
    ],
)
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
    res = otto.delete(f"/api/v1/silences/{sid}", json={})
    assert res.status_code == 200
    assert otto.get("/api/v1/silences").get_json()["silences"] == []
    assert otto.post("/api/v1/silences", json={"host_pattern": "*", "duration_minutes": 60}).status_code == 400


# ---------------------------------------------------------- admin
def test_user_management(login):
    ada = login("ada")
    assert (
        ada.post("/api/v1/users", json={"username": "newbie", "password": PASSWORD, "role": "viewer"}).status_code
        == 201
    )
    assert ada.post("/api/v1/users", json={"username": "newbie", "password": PASSWORD}).status_code == 400
    assert ada.patch("/api/v1/users/newbie", json={"role": "operator"}).status_code == 200
    assert ada.patch("/api/v1/users/ada", json={"role": "viewer"}).status_code == 400  # last admin
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


# ---------------------------------------------------------- device insights
def test_device_detail_includes_monitoring(app, login):
    app.test_client().post("/api/v1/ingest", json={"samples": [sample(**{"service.nginx.up": 0.0})]}, headers=TOKEN)
    d = login("vera").get("/api/v1/devices/AST-000002").get_json()
    assert d["monitoring"]["latest"]["services_down"] == ["nginx"]
    assert [(a["rule"], a["status"]) for a in d["monitoring"]["alerts"]] == [("service_down", "open")]
    switch = login("vera").get("/api/v1/devices/AST-000001").get_json()
    assert switch["monitoring"]["latest"] is None


def test_history_endpoint(app, login):
    c = app.test_client()
    c.post(
        "/api/v1/ingest",
        json={"samples": [sample(seconds_ago=60, **{"cpu.percent": 20.0}), sample(**{"cpu.percent": 40.0})]},
        headers=TOKEN,
    )
    data = login("vera").get(f"/api/v1/hosts/{HOST}/history?keys=cpu.percent&hours=1").get_json()
    assert [p[1] for p in data["series"]["cpu.percent"]] == [20.0, 40.0]
    assert login("vera").get(f"/api/v1/hosts/{HOST}/history?hours=0").status_code == 400


def test_rack_endpoint(login):
    c = login("vera")
    assert c.get("/api/v1/racks/SH02-A01").get_json()["used_u"] == 9
    assert c.get("/api/v1/racks/NOPE").status_code == 404


def test_inventory_export_and_import_permissions(login, conn):
    vera, ada = login("vera"), login("ada")
    res = vera.get("/api/v1/inventory/export.csv")
    assert res.status_code == 200 and res.mimetype == "text/csv"
    new = (
        "\n".join(
            [res.data.decode().splitlines()[0], "AST-900001,new-srv01,10.99.0.1,server,Dell,R760,SH01-A01,30,online"]
        )
        + "\n"
    )
    assert vera.post("/api/v1/inventory/import", json={"csv": new, "dry_run": False}).status_code == 403
    dry = ada.post("/api/v1/inventory/import", json={"csv": new}).get_json()  # dry run by default
    assert dry["ok"] and dry["dry_run"] and dry["created"] == 1
    assert conn.execute("SELECT COUNT(*) FROM devices WHERE asset_id='AST-900001'").fetchone()[0] == 0
    real = ada.post("/api/v1/inventory/import", json={"csv": new, "dry_run": False}).get_json()
    assert real["created"] == 1
    bad = ada.post("/api/v1/inventory/import", json={"csv": new.replace("SH01-A01", "SH99-A01"), "dry_run": False})
    assert bad.status_code == 422 and "unknown rack" in bad.get_json()["errors"][0]
    actions = [r[0] for r in conn.execute("SELECT action FROM audit_log")]
    assert actions.count("inventory_import") == 1 and "inventory_export" in actions


@pytest.mark.parametrize(
    "path, body, expected",
    [
        (
            "/api/v1/silences",
            {"host_pattern": "*", "duration_minutes": "abc", "reason": "x"},
            "duration_minutes must be",
        ),
        (
            "/api/v1/silences",
            {"host_pattern": "*", "duration_minutes": 60, "reason": "x", "starts_at": "soon"},
            "starts_at must look like",
        ),
        ("/api/v1/tokens", {"name": "x", "expires_days": "lots"}, "expires_days must be"),
    ],
)
def test_bad_input_gets_a_safe_message(login, path, body, expected):
    """Only messages written for the client are returned, never raw exception text (CodeQL)."""
    res = login("otto").post(path, json=body)
    assert res.status_code == 400 and expected in res.get_json()["error"]
    assert "invalid literal" not in res.get_json()["error"]


def test_bad_history_hours_message(login):
    res = login("vera").get("/api/v1/hosts/x/history?hours=abc")
    assert res.status_code == 400 and res.get_json()["error"] == "hours must be a whole number"
