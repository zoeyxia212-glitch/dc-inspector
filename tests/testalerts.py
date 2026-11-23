"""Alert lifecycle through the real ingest path and the real rules.yaml."""

from datetime import timedelta

import pytest
from conftest import HOST, T0, alerts_by, at, healthy, outbox

from inspector import alerts
from inspector.db import to_text, transaction
from inspector.rules import Rule, evaluate_rule, load_rules


def test_rules_file_loads(settings):
    names = {r.name for r in settings.rules}
    assert {"host_down", "cpu_high", "disk_critical", "service_down", "rebooted"} <= names


def test_cpu_needs_two_checks_in_a_row(conn, push):
    push(0, **{"cpu.percent": 97})
    assert alerts_by(conn) == {}
    push(1, **{"cpu.percent": 98})
    alert = alerts_by(conn)[(HOST, "cpu_high", "")]
    assert alert["severity"] == "critical" and alert["summary"] == "CPU 98% for over a minute"


def test_short_spikes_ignored(conn, push):
    for step, cpu in enumerate([97, 20, 99, 10, 95]):
        push(step, **{"cpu.percent": cpu})
    assert alerts_by(conn) == {}


def test_one_alert_while_problem_continues_then_resolves(conn, push):
    for step in range(6):
        push(step, **{"cpu.percent": 99})
    assert len(alerts_by(conn)) == 1
    push(6, **{"cpu.percent": 5})
    assert alerts_by(conn) == {}
    assert list(alerts_by(conn, "resolved")) == [(HOST, "cpu_high", "")]
    events = [(o["event"], o["channel"]) for o in outbox(conn)]
    assert events.count(("opened", "all")) == 1 and events.count(("resolved", "all")) == 1


def test_disk_warning_vs_critical_per_mount(conn, push):
    push(0, **{"disk./data.percent": 90.0, "disk./var.percent": 97.0})
    keys = set(alerts_by(conn))
    assert (HOST, "disk_warning", "/data") in keys
    assert (HOST, "disk_critical", "/var") in keys
    assert (HOST, "disk_warning", "/var") not in keys  # 97 is critical only, not both
    push(1, **{"disk./data.percent": 97.0, "disk./var.percent": 97.0})
    keys = set(alerts_by(conn))
    assert (HOST, "disk_critical", "/data") in keys and (HOST, "disk_warning", "/data") not in keys


def test_service_down_and_back(conn, push):
    push(0, **{"service.nginx.up": 0.0})
    assert (HOST, "service_down", "nginx") in alerts_by(conn)
    push(1)
    assert alerts_by(conn) == {}


def test_host_down_keeps_other_alerts_open(conn, push):
    push(0, **{"cpu.percent": 99})
    push(1, **{"cpu.percent": 99})
    push(2, up=False)
    assert set(alerts_by(conn)) == {(HOST, "cpu_high", "")}  # 1 failure: not yet
    push(3, up=False)
    assert set(alerts_by(conn)) == {(HOST, "cpu_high", ""), (HOST, "host_down", "")}
    push(4)
    assert alerts_by(conn) == {}


def test_target_vanished_resolves(conn, push):
    push(0, **{"disk./old.percent": 99.0})
    assert (HOST, "disk_critical", "/old") in alerts_by(conn)
    push(1)  # mount no longer reported by a reachable host
    assert alerts_by(conn) == {}


def test_custom_checks_in_rules(conn, push):
    push(0, **{"check.uptime_s": 120.0})
    alert = alerts_by(conn)[(HOST, "rebooted", "")]
    assert alert["summary"] == "Host rebooted 120 s ago"
    push(1, **{"check.ro_mounts": 1.0, "check.uptime_s": 150.0})
    assert (HOST, "filesystem_readonly", "") in alerts_by(conn)


def test_hosts_are_independent(conn, push):
    for step in range(2):
        push(step, host="sh01-a01-srv01", **{"cpu.percent": 99})
        push(step, host="sh02-a01-srv01")
    assert set(alerts_by(conn)) == {("sh01-a01-srv01", "cpu_high", "")}


def test_severity_routing(conn, push):
    push(0, **{"disk./data.percent": 90.0})  # warning
    assert {o["channel"] for o in outbox(conn)} == {"all"}
    push(1, **{"disk./data.percent": 90.0, "service.nginx.up": 0.0})  # critical
    assert {(o["channel"], o["event"]) for o in outbox(conn)} >= {("critical-only", "opened")}


def test_notification_includes_rack_location(conn, push):
    push(0, **{"service.nginx.up": 0.0})
    body = outbox(conn)[0]["body"]
    assert "Location: SH01-A01 U2" in body and "https://dc.example.com/#monitor" in body


# ---------------------------------------------------------- silences / ack / reminders
def test_silence_records_but_does_not_notify(conn, push):
    with transaction(conn):
        alerts.add_silence(
            conn, "sh01-*", "*", T0 - timedelta(minutes=1), T0 + timedelta(hours=1), "CHG-1234 nginx upgrade", "otto"
        )
    push(0, **{"service.nginx.up": 0.0})
    alert = alerts_by(conn)[(HOST, "service_down", "nginx")]
    assert alert["silenced"] == 1
    assert outbox(conn) == []


def test_silence_rule_pattern(conn, push):
    with transaction(conn):
        alerts.add_silence(conn, "*", "disk_*", T0 - timedelta(minutes=1), T0 + timedelta(hours=1), "cleanup", "otto")
    push(0, **{"disk./data.percent": 99.0, "service.nginx.up": 0.0})
    a = alerts_by(conn)
    assert a[(HOST, "disk_critical", "/data")]["silenced"] == 1
    assert a[(HOST, "service_down", "nginx")]["silenced"] == 0


@pytest.mark.parametrize("hours, reason", [(0, "x"), (24 * 31, "x"), (1, "  ")])
def test_invalid_silences(conn, hours, reason):
    with pytest.raises(ValueError):
        alerts.add_silence(conn, "*", "*", T0, T0 + timedelta(hours=hours), reason, "otto")


def test_ack_stops_reminders(conn, push):
    push(0, **{"service.nginx.up": 0.0})
    alert_id = alerts_by(conn)[(HOST, "service_down", "nginx")]["id"]
    later = T0 + timedelta(minutes=31)
    with transaction(conn):
        assert len(alerts.due_reminders(conn, 30, later)) == 1
    with transaction(conn):
        assert alerts.acknowledge(conn, alert_id, "otto", "on it, INC-42", later)
        assert not alerts.acknowledge(conn, alert_id, "ada", "", later)  # only once
        assert alerts.due_reminders(conn, 30, later + timedelta(hours=1)) == []


def test_warnings_get_no_reminders(conn, push):
    push(0, **{"disk./data.percent": 90.0})
    assert alerts.due_reminders(conn, 30, T0 + timedelta(hours=2)) == []


# ---------------------------------------------------------- collector watchdog
def test_collector_down_and_recovered(conn, push):
    push(0)  # sh-north seen at T0
    with transaction(conn):
        assert alerts.check_collectors(conn, 120, T0 + timedelta(seconds=60)) == []
        events = alerts.check_collectors(conn, 120, T0 + timedelta(seconds=180))
    assert [(e["event"], e["host"], e["severity"]) for e in events] == [("opened", "collector/sh-north", "critical")]
    with transaction(conn):
        assert alerts.check_collectors(conn, 120, T0 + timedelta(seconds=200)) == []  # no duplicate
    push(7)  # data arrives again
    with transaction(conn):
        events = alerts.check_collectors(conn, 120, at(7))
    assert [e["event"] for e in events] == ["resolved"]


def test_never_seen_collector_is_not_alerted(conn):
    with transaction(conn):
        assert alerts.check_collectors(conn, 120, T0 + timedelta(days=1)) == []


# ---------------------------------------------------------- rule definitions
def test_for_alias_and_validation(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text("rules:\n  - {name: a, expr: 'up == 0', for: 3, severity: critical}\n")
    assert load_rules(path)[0].for_checks == 3


@pytest.mark.parametrize(
    "kwargs",
    [
        {"name": "a", "expr": "cpu.percent >"},
        {"name": "a", "expr": "up == 0", "severity": "panic"},
        {"name": "a", "expr": "up == 0", "for_checks": 0},
    ],
)
def test_bad_rules(kwargs):
    with pytest.raises(ValueError):
        Rule(**kwargs)


def test_default_summary_shows_value_and_condition():
    rule = Rule(name="x", expr="disk.*.percent > 80", for_checks=2)
    result = evaluate_rule(rule, [{"disk./a.percent": 91.0}, {"disk./a.percent": 90.0}])
    assert result["/a"] == (True, True, "disk./a.percent = 91 (disk./a.percent > 80) for 2 checks")


# ---------------------------------------------------------- backfill after an outage
def batch(*rounds, host=HOST):
    """rounds: (step, up, overrides) -> one ingest payload, like a collector flushing its spool."""
    return {
        "samples": [
            {
                "host": host,
                "datacenter": "SH01",
                "collected_at": to_text(at(step)),
                "up": int(up),
                "values": healthy(**over) if up else {"ssh.error": "timeout", "ping.up": 0.0},
            }
            for step, up, over in rounds
        ]
    }


def test_spooled_rounds_are_evaluated_in_order_with_their_own_times(conn, settings):
    from inspector.ingest import ingest

    # central was down for steps 0-5; the collector sends all six rounds at step 6
    payload = batch(
        (0, True, {}),
        (1, True, {"cpu.percent": 99}),
        (2, True, {"cpu.percent": 99}),
        (3, True, {"cpu.percent": 99}),
        (4, True, {}),
        (5, True, {}),
    )
    ingest(conn, settings, "sh-north", payload, now=at(6))
    alert = alerts_by(conn, "resolved")[(HOST, "cpu_high", "")]
    assert alert["opened_at"] == to_text(at(2)) and alert["resolved_at"] == to_text(at(4))
    # opened+resolved inside one batch -> one 'resolved' notification per channel, no stale 'opened'
    assert sorted((o["event"], o["channel"]) for o in outbox(conn)) == [
        ("resolved", "all"),
        ("resolved", "critical-only"),
    ]


def test_problem_still_open_after_backfill_notifies_opened_with_real_time(conn, settings):
    from inspector.ingest import ingest

    ingest(conn, settings, "sh-north", batch((0, True, {}), (1, False, {}), (2, False, {}), (3, False, {})), now=at(4))
    alert = alerts_by(conn)[(HOST, "host_down", "")]
    assert alert["opened_at"] == to_text(at(2))
    assert {o["event"] for o in outbox(conn)} == {"opened"}


# ---------------------------------------------------------- central vs collector blame
def test_all_collectors_silent_blames_central_not_sites(conn, push):
    from inspector import auth

    auth.register_collector(conn, "sh-south", "dcc_south0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZab")
    conn.execute("UPDATE collectors SET last_seen_at = ?", (to_text(T0),))
    with transaction(conn):
        events = alerts.check_collectors(conn, 120, T0 + timedelta(minutes=5))
    assert [(e["host"], e["rule"]) for e in events] == [("central", "ingest_stalled")]
    # one site comes back: central is fine, the other site is the problem
    conn.execute(
        "UPDATE collectors SET last_seen_at = ? WHERE name = 'sh-north'", (to_text(T0 + timedelta(minutes=5)),)
    )
    with transaction(conn):
        events = alerts.check_collectors(conn, 120, T0 + timedelta(minutes=5, seconds=30))
    assert sorted((e["event"], e["host"]) for e in events) == [
        ("opened", "collector/sh-south"),
        ("resolved", "central"),
    ]
