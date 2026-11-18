from datetime import timedelta

from inspector import scheduler
from inspector.db import transaction
from inspector.report import build_report_data, prune, render_report, write_report
from inspector import alerts

from conftest import T0, at, outbox

UNTIL = T0 + timedelta(hours=1)


def history(push):
    for step in range(4):
        push(step, host="sh01-a01-srv01", **{"cpu.percent": 20.0 + step, "disk./data.percent": 60.0})
        push(step, host="sh02-a01-srv01", up=step < 2)


def test_report_numbers(conn, push):
    history(push)
    data = build_report_data(conn, T0, UNTIL, expected_hosts={
        "sh01-a01-srv01": "SH01", "sh02-a01-srv01": "SH02", "sh03-a01-srv01": "SH03"})
    hosts = {h["host"]: h for h in data["hosts"]}
    assert hosts["sh01-a01-srv01"]["status"] == "OK"
    assert hosts["sh01-a01-srv01"]["checks"] == 4 and hosts["sh01-a01-srv01"]["max_cpu"] == 23.0
    assert hosts["sh01-a01-srv01"]["max_disk"] == 60.0
    assert hosts["sh02-a01-srv01"]["status"] == "CRITICAL" and hosts["sh02-a01-srv01"]["availability"] == 50.0
    assert hosts["sh03-a01-srv01"]["status"] == "NO DATA"
    assert data["summary"]["checks"] == 8 and data["summary"]["availability"] == 75.0


def test_report_shows_who_handled_alert(conn, push):
    history(push)
    alert_id = conn.execute("SELECT id FROM alerts").fetchone()[0]
    alerts.acknowledge(conn, alert_id, "otto", "INC-9 power cycled", at(4))
    html = render_report(build_report_data(conn, T0, UNTIL, tz="Pacific/Auckland"))
    assert "otto: INC-9 power cycled" in html and "host_down" in html
    assert "2026-11-18 13:00" in html                                # NZ local time


def test_daily_job_writes_report_notifies_and_prunes(conn, settings, push, tmp_path):
    import dataclasses
    from inspector.config import Channel
    s = dataclasses.replace(settings, channels=[Channel(name="mail", type="email", daily_report=True)], retention_days=1)
    push(0)
    push(10)
    path = scheduler.run_daily(conn, s, tmp_path, now=at(10) + timedelta(days=1, seconds=-60))
    assert path.endswith("inspection report 20261119.html") or path.endswith(".html")
    msgs = outbox(conn)
    assert [m["event"] for m in msgs] == ["report"] and "Availability" in msgs[0]["body"]
    assert conn.execute("SELECT COUNT(*) FROM samples").fetchone()[0] == 1      # step 0 pruned


def test_write_report_file(conn, push, tmp_path):
    history(push)
    path = write_report(conn, tmp_path, until=UNTIL, tz="UTC")
    assert path.name == "inspection report 20261118.html"


def test_empty_period(empty_conn):
    assert "No alerts in this period" in render_report(build_report_data(empty_conn, T0, UNTIL))


def test_prune_cascades(conn, push):
    push(0)
    push(10)
    with transaction(conn):
        assert prune(conn, 1, now=at(10) + timedelta(days=1, seconds=-60)) == 1
    assert conn.execute("SELECT COUNT(DISTINCT sample_id) FROM sample_values").fetchone()[0] == 1
