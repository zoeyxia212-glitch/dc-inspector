"""Operational features: rack correlation, schema migrations, self-monitoring, backups."""
import sqlite3
from datetime import timedelta

import pytest

from inspector import ops
from inspector.alerts import due_reminders
from inspector.db import SCHEMA, SCHEMA_VERSION, connect, init_schema, schema_version, transaction
from inspector.main import main

from conftest import T0, alerts_by, at, outbox

RACK = [f"sh01-a01-srv0{i}" for i in range(1, 9)]          # 8 servers in rack SH01-A01


def down(push, step, hosts):
    """One collection round: the collector sends every host of the round in one batch."""
    push.batch(step, {h: False for h in hosts})


# ---------------------------------------------------------- rack correlation
def test_rack_outage_groups_hosts(conn, push):
    for step in (0, 1):
        down(push, step, RACK[:5])                       # 5 hosts in one rack go down together
    open_ = alerts_by(conn)
    rack = open_[("rack/SH01-A01", "rack_outage", "")]
    assert "5 hosts in rack SH01-A01" in rack["summary"] and "sh01-a01-tor" in rack["summary"]
    children = [a for k, a in open_.items() if k[1] == "host_down"]
    assert len(children) == 5 and all(a["parent_id"] == rack["id"] for a in children)
    # one notification per channel for the rack, none for the five hosts
    assert {(o["subject"].split()[1], o["event"]) for o in outbox(conn)} == {("rack/SH01-A01", "opened")}


def test_hosts_below_threshold_alert_individually(conn, push):
    for step in (0, 1):
        down(push, step, RACK[:2])
    assert ("rack/SH01-A01", "rack_outage", "") not in alerts_by(conn)
    assert sum(1 for o in outbox(conn) if "host_down" in o["subject"]) == 4      # 2 hosts x 2 channels


def test_later_host_joins_existing_rack_outage(conn, push):
    for step in (0, 1):
        down(push, step, RACK[:3])
    before = len(outbox(conn))
    for step in (2, 3):
        down(push, step, RACK[:4])
    assert len(outbox(conn)) == before                      # 4th host attached silently
    rack = alerts_by(conn)[("rack/SH01-A01", "rack_outage", "")]
    assert rack["summary"].startswith("4 hosts")


def test_rack_recovery_notifies_once(conn, push):
    for step in (0, 1):
        down(push, step, RACK[:3])
    before = len(outbox(conn))
    push.batch(2, {h: True for h in RACK[:3]})
    assert alerts_by(conn) == {}
    new = outbox(conn)[before:]
    assert {(o["subject"].split()[1], o["event"]) for o in new} == {("rack/SH01-A01", "resolved")}


def test_grouped_hosts_get_no_reminders(conn, push):
    for step in (0, 1):
        down(push, step, RACK[:3])
    with transaction(conn):
        reminders = due_reminders(conn, 30, T0 + timedelta(hours=1))
    assert [r["host"] for r in reminders] == ["rack/SH01-A01"]


def test_different_racks_are_independent(conn, push):
    for step in (0, 1):
        down(push, step, ["sh01-a01-srv01", "sh02-a01-srv01", "sh03-a01-srv01"])
    assert not any(k[1] == "rack_outage" for k in alerts_by(conn))


# ---------------------------------------------------------- migrations
def test_fresh_database_is_at_latest_version():
    c = connect(":memory:")
    assert init_schema(c) == [2] and schema_version(c) == SCHEMA_VERSION
    assert init_schema(c) == []                                     # idempotent


def test_existing_v1_database_is_upgraded_in_place(tmp_path):
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.executescript(SCHEMA)                                       # what v2.0 created: no parent_id, user_version 0
    old.execute("""INSERT INTO alerts (host, rule, severity, summary, status, opened_at, last_seen_at)
                   VALUES ('h', 'cpu_high', 'critical', 's', 'open', '2026-11-18T00:00:00Z', '2026-11-18T00:00:00Z')""")
    old.commit(); old.close()
    c = connect(path)
    assert init_schema(c) == [2]
    row = c.execute("SELECT host, parent_id FROM alerts").fetchone()
    assert row["host"] == "h" and row["parent_id"] is None          # data kept, column added


# ---------------------------------------------------------- self-monitoring
def test_prometheus_metrics(conn, push):
    push(0, **{"service.nginx.up": 0.0})
    text = ops.prometheus_metrics(conn, 120, now=at(2))
    assert 'dcinspector_collector_up{collector="sh-north"} 1' in text
    assert 'dcinspector_collector_last_seen_age_seconds{collector="sh-north"} 60.0' in text
    assert 'dcinspector_alerts_open{severity="critical"} 1' in text
    assert 'dcinspector_alerts_critical_unacknowledged 1' in text
    assert 'dcinspector_notifications{status="pending"} 2' in text
    assert 'dcinspector_hosts{state="up"} 1' in text
    assert "# TYPE dcinspector_hosts gauge" in text


def test_metrics_endpoint_auth(app, login, monkeypatch):
    assert app.test_client().get("/metrics").status_code == 401
    assert login("vera").get("/metrics").status_code == 200
    monkeypatch.setenv("INSPECTOR_METRICS_TOKEN", "scrape-token-123")
    c = app.test_client()
    assert c.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
    res = c.get("/metrics", headers={"Authorization": "Bearer scrape-token-123"})
    assert res.status_code == 200 and b"dcinspector_collector_up" in res.data


# ---------------------------------------------------------- backups
def test_backup_verify_and_retention(conn, push, tmp_path):
    push(0)
    for i in range(4):
        ops.backup(conn, tmp_path, keep=2, now=T0 + timedelta(minutes=i))
    files = sorted(p.name for p in tmp_path.glob("*.db"))
    assert files == ["inspector backup 20261118 000200.db", "inspector backup 20261118 000300.db"]
    info = ops.restore_check(tmp_path / files[-1])
    assert info == {"integrity": "ok", "schema_version": SCHEMA_VERSION, "devices": 360, "samples": 1, "alerts": 0}
    assert not list(tmp_path.glob("*.tmp"))


def test_backup_cli(tmp_path):
    db = tmp_path / "live.db"
    main(["seed", "--db", str(db)])
    main(["backup", str(tmp_path / "b"), "--db", str(db)])
    backup_file = next((tmp_path / "b").glob("*.db"))
    with pytest.raises(SystemExit) as exit_:
        main(["verify-backup", str(backup_file)])
    assert exit_.value.code == 0


def test_backup_rejects_bad_keep(conn, tmp_path):
    with pytest.raises(ValueError):
        ops.backup(conn, tmp_path, keep=0)
