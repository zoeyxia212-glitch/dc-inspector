"""Alert engine: open / update / resolve alerts from rule results.

Lifecycle of one alert (one per host + rule + target):
  opened    condition held for `for_checks` samples in a row -> notify
  updated   still true: last_seen/summary refreshed, no new notification
  acked     an operator acknowledged it: stops reminder notifications
  resolved  condition is now explicitly false -> notify
Missing data (host unreachable, metric absent) never resolves an alert;
only an explicit "false" does. If a target disappears from a reachable host
(e.g. a mount was removed), its alert is resolved.
Alerts that match an active silence (maintenance window) are recorded with
silenced=1 and do not notify.
"""
import fnmatch
import sqlite3
from datetime import datetime, timedelta

from inspector.db import to_text, utcnow
from inspector.rules import Rule, evaluate_rule

COLLECTOR_RULE = "collector_down"


def recent_samples(conn: sqlite3.Connection, host: str, limit: int) -> list[dict]:
    """Newest first: [{'up': 1.0, 'cpu.percent': 12.0, ...}, ...] plus '_datacenter'."""
    rows = conn.execute(
        """SELECT id, up, datacenter FROM samples WHERE host = ?
           ORDER BY collected_at DESC LIMIT ?""", (host, limit)).fetchall()
    samples = []
    for row in rows:
        values = {"up": float(row["up"])}
        for v in conn.execute("SELECT key, num, text FROM sample_values WHERE sample_id = ?",
                              (row["id"],)):
            values[v["key"]] = v["num"] if v["num"] is not None else v["text"]
        values["_datacenter"] = row["datacenter"]
        samples.append(values)
    return samples


def active_silence(conn: sqlite3.Connection, host: str, rule: str, now_text: str) -> dict | None:
    for s in conn.execute("SELECT * FROM silences WHERE starts_at <= ? AND ends_at > ?",
                          (now_text, now_text)):
        if fnmatch.fnmatchcase(host, s["host_pattern"]) and fnmatch.fnmatchcase(rule, s["rule_pattern"]):
            return dict(s)
    return None


def evaluate_host(conn: sqlite3.Connection, host: str, rules: list[Rule],
                  now: datetime | None = None) -> list[dict]:
    """Must run inside a transaction. Returns events for notification."""
    now_text = to_text(now or utcnow())
    depth = max((r.for_checks for r in rules), default=1)
    samples = recent_samples(conn, host, depth)
    if not samples:
        return []
    datacenter = samples[0].pop("_datacenter")
    for s in samples[1:]:
        s.pop("_datacenter", None)
    host_up = samples[0].get("up") == 1.0

    open_alerts = {(a["rule"], a["target"]): dict(a) for a in conn.execute(
        "SELECT * FROM alerts WHERE host = ? AND status = 'open' AND rule != ?",
        (host, COLLECTOR_RULE))}
    events, seen = [], set()

    for rule in rules:
        for target, (latest, firing, summary) in evaluate_rule(rule, samples).items():
            key = (rule.name, target)
            seen.add(key)
            existing = open_alerts.get(key)
            if firing and existing:
                conn.execute("UPDATE alerts SET last_seen_at = ?, summary = ? WHERE id = ?",
                             (now_text, summary, existing["id"]))
            elif firing:
                silenced = active_silence(conn, host, rule.name, now_text) is not None
                alert_id = conn.execute(
                    """INSERT INTO alerts (host, datacenter, rule, target, severity, summary, status,
                                           silenced, opened_at, last_seen_at)
                       VALUES (?, ?, ?, ?, ?, ?, 'open', ?, ?, ?)""",
                    (host, datacenter, rule.name, target, rule.severity, summary, int(silenced),
                     now_text, now_text)).lastrowid
                events.append(_event(conn, alert_id, "opened"))
            elif existing and latest is False:
                events.append(_resolve(conn, existing["id"], now_text))

    if host_up:
        # Target vanished (mount removed, service no longer configured) or rule deleted.
        for key, alert in open_alerts.items():
            if key not in seen:
                events.append(_resolve(conn, alert["id"], now_text))
    return events


INGEST_RULE = "ingest_stalled"
CENTRAL_HOST = "central"


def check_collectors(conn: sqlite3.Connection, stale_seconds: int,
                     now: datetime | None = None) -> list[dict]:
    """Raise/resolve collector_down. A silent collector means a whole site is unmonitored.

    If every collector goes silent at once (2+ collectors), the likely cause is the central
    side (API down, central network, disk full), so one `ingest_stalled` alert is raised on
    the central server instead of blaming every site.
    """
    now = now or utcnow()
    now_text, cutoff = to_text(now), to_text(now - timedelta(seconds=stale_seconds))
    collectors = [dict(c) for c in conn.execute(
        "SELECT name, last_seen_at FROM collectors WHERE last_seen_at IS NOT NULL")]
    stale = {c["name"]: c["last_seen_at"] < cutoff for c in collectors}
    all_stale = len(collectors) >= 2 and all(stale.values())
    events = []

    def open_alert(host, rule):
        return conn.execute("SELECT id FROM alerts WHERE host = ? AND rule = ? AND status = 'open'",
                            (host, rule)).fetchone()

    def raise_alert(host, rule, summary):
        silenced = active_silence(conn, host, rule, now_text) is not None
        alert_id = conn.execute(
            """INSERT INTO alerts (host, rule, target, severity, summary, status, silenced,
                                   opened_at, last_seen_at)
               VALUES (?, ?, '', 'critical', ?, 'open', ?, ?, ?)""",
            (host, rule, summary, int(silenced), now_text, now_text)).lastrowid
        events.append(_event(conn, alert_id, "opened"))

    central_alert = open_alert(CENTRAL_HOST, INGEST_RULE)
    if all_stale and not central_alert:
        newest = max(c["last_seen_at"] for c in collectors)
        raise_alert(CENTRAL_HOST, INGEST_RULE,
                    f"No data from any collector since {newest}: check the central API, its network and disk")
    elif not all_stale and central_alert:
        events.append(_resolve(conn, central_alert["id"], now_text))

    for c in collectors:
        host = f"collector/{c['name']}"
        alert = open_alert(host, COLLECTOR_RULE)
        if stale[c["name"]] and not all_stale and not alert:
            raise_alert(host, COLLECTOR_RULE,
                        f"No data from collector {c['name']} since {c['last_seen_at']} - site is unmonitored")
        elif not stale[c["name"]] and alert:
            events.append(_resolve(conn, alert["id"], now_text))
    return events


def due_reminders(conn: sqlite3.Connection, after_minutes: int,
                  now: datetime | None = None) -> list[dict]:
    """Critical alerts still open, not acknowledged, not silenced, not notified recently."""
    if after_minutes <= 0:
        return []
    cutoff = to_text((now or utcnow()) - timedelta(minutes=after_minutes))
    rows = conn.execute(
        """SELECT id FROM alerts
           WHERE status = 'open' AND severity = 'critical' AND acked_at IS NULL AND silenced = 0
             AND COALESCE(last_notified_at, opened_at) < ?""", (cutoff,)).fetchall()
    return [_event(conn, r["id"], "reminder") for r in rows]


def acknowledge(conn: sqlite3.Connection, alert_id: int, username: str, note: str = "",
                now: datetime | None = None) -> bool:
    cur = conn.execute(
        """UPDATE alerts SET acked_by = ?, acked_at = ?, ack_note = ?
           WHERE id = ? AND status = 'open' AND acked_at IS NULL""",
        (username, to_text(now or utcnow()), note[:500], alert_id))
    return cur.rowcount == 1


def add_silence(conn: sqlite3.Connection, host_pattern: str, rule_pattern: str,
                starts_at: datetime, ends_at: datetime, reason: str, created_by: str) -> int:
    if ends_at <= starts_at:
        raise ValueError("Silence must end after it starts")
    if ends_at - starts_at > timedelta(days=30):
        raise ValueError("Silences longer than 30 days are not allowed")
    if not reason.strip():
        raise ValueError("A reason is required (e.g. change ticket number)")
    sid = conn.execute(
        """INSERT INTO silences (host_pattern, rule_pattern, starts_at, ends_at, reason,
                                 created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (host_pattern.strip() or "*", rule_pattern.strip() or "*", to_text(starts_at),
         to_text(ends_at), reason.strip()[:500], created_by, to_text(utcnow()))).lastrowid
    # Already-open alerts that now fall in the window stop notifying too.
    now_text = to_text(utcnow())
    if to_text(starts_at) <= now_text:
        for a in conn.execute("SELECT id, host, rule FROM alerts WHERE status = 'open' AND silenced = 0").fetchall():
            if fnmatch.fnmatchcase(a["host"], host_pattern) and fnmatch.fnmatchcase(a["rule"], rule_pattern or "*"):
                conn.execute("UPDATE alerts SET silenced = 1 WHERE id = ?", (a["id"],))
    return sid


def _resolve(conn, alert_id: int, now_text: str) -> dict:
    conn.execute("UPDATE alerts SET status = 'resolved', resolved_at = ? WHERE id = ?",
                 (now_text, alert_id))
    return _event(conn, alert_id, "resolved")


def _event(conn, alert_id: int, kind: str) -> dict:
    row = dict(conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone())
    return {"event": kind, **row}
