from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from conftest import T0, outbox

from inspector import scheduler


def test_watchdog_raises_collector_down_and_notifies(conn, settings, push):
    push(0)
    assert scheduler.run_watchdog(conn, settings, T0 + timedelta(minutes=5)) == 1
    msgs = outbox(conn)
    assert {m["channel"] for m in msgs} == {"all", "critical-only"}
    assert "collector/sh-north" in msgs[0]["subject"]


def test_watchdog_sends_reminders(conn, settings, push):
    push(0, **{"service.nginx.up": 0.0})
    push(1, **{"service.nginx.up": 0.0})
    before = len(outbox(conn))
    # the collector is also silent by then, so collector_down opens too
    scheduler.run_watchdog(conn, settings, T0 + timedelta(minutes=31))
    events = [m["event"] for m in outbox(conn)[before:]]
    assert events.count("reminder") == 2  # both channels for the service_down alert


def test_delivery_through_scheduler(conn, settings, push):
    push(0, **{"service.nginx.up": 0.0})
    sent = []
    stats = scheduler.run_delivery(
        conn, settings, T0, {"slack": lambda c, s, b: sent.append(c.name), "wecom": lambda c, s, b: sent.append(c.name)}
    )
    assert stats["sent"] == 2 and sorted(sent) == ["all", "critical-only"]


def test_next_report_time():
    nz = ZoneInfo("Pacific/Auckland")
    assert scheduler.next_report_time(datetime(2026, 11, 18, 7, 0, tzinfo=nz), 8).day == 18
    assert scheduler.next_report_time(datetime(2026, 11, 18, 9, 0, tzinfo=nz), 8).day == 19
