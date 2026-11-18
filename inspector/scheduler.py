"""Central background jobs (run as its own process: `python -m inspector.main scheduler`).

  every 5 s    deliver pending notifications (with retries)
  every 30 s   (watchdog_seconds) collector watchdog (collector_down), reminders for unacknowledged critical alerts
  daily        inspection report (+ notify channels with daily_report: true), data retention
"""
import logging
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from inspector import alerts, lookup, notify, report
from inspector.config import REPORT_DIR, ServerSettings
from inspector.db import to_text, transaction, utcnow

log = logging.getLogger(__name__)


def next_report_time(now_local: datetime, hour: int) -> datetime:
    target = now_local.replace(hour=hour, minute=0, second=0, microsecond=0)
    return target if target > now_local else target + timedelta(days=1)


def location_lookup(conn):
    return lambda host: lookup.get_location(conn, host)


def run_watchdog(conn: sqlite3.Connection, settings: ServerSettings, now: datetime | None = None) -> int:
    now = now or utcnow()
    with transaction(conn):
        events = alerts.check_collectors(conn, settings.collector_stale_seconds, now)
        events += alerts.due_reminders(conn, settings.renotify_after_minutes, now)
        notify.enqueue(conn, events, settings.channels, location_lookup(conn), now, settings.public_url)
    return len(events)


def run_delivery(conn: sqlite3.Connection, settings: ServerSettings, now: datetime | None = None,
                 senders: dict | None = None) -> dict:
    # Sending happens outside a long write lock; each row update is its own small write.
    return notify.deliver_pending(conn, settings.channels, now, senders)


def run_daily(conn: sqlite3.Connection, settings: ServerSettings, report_dir=REPORT_DIR,
              now: datetime | None = None, expected_hosts: dict | None = None) -> str:
    now = now or utcnow()
    path = report.write_report(conn, report_dir, until=now, expected_hosts=expected_hosts,
                               tz=settings.timezone)
    data = report.build_report_data(conn, now - timedelta(hours=24), now, expected_hosts, settings.timezone)
    summary = data["summary"]
    availability = f"{summary['availability']:.2f}%" if summary["availability"] is not None else "n/a"
    body = "\n".join([
        f"Daily inspection report {data['since']} -> {data['until']} ({settings.timezone})",
        f"Hosts: {summary['hosts']}   Checks: {summary['checks']}   Availability: {availability}",
        f"Alerts: {summary['alerts']} ({summary['critical']} critical)   Hosts needing attention: {summary['problem_hosts']}",
        f"{settings.public_url.rstrip('/')}/reports/{path.name}",
    ])
    with transaction(conn):
        for channel in settings.channels:
            if channel.daily_report:
                notify.enqueue_message(conn, channel, "report", f"Daily inspection report {data['until'][:10]}", body, now)
        deleted = report.prune(conn, settings.retention_days, now)
        conn.execute("DELETE FROM audit_log WHERE at < ?",
                     (to_text(now - timedelta(days=settings.audit_retention_days)),))
    log.info("Daily report %s written; pruned %d old samples", path.name, deleted)
    return str(path)


def run_forever(conn: sqlite3.Connection, settings: ServerSettings, stop: threading.Event,
                report_dir=REPORT_DIR) -> None:
    zone = ZoneInfo(settings.timezone)
    next_report = next_report_time(datetime.now(zone), settings.report_hour)
    next_watchdog = 0.0
    log.info("Scheduler started; next daily report %s", next_report.strftime("%Y-%m-%d %H:%M %Z"))
    while not stop.is_set():
        try:
            stats = run_delivery(conn, settings)
            if any(stats.values()):
                log.info("Notifications: %s", stats)
            if time.monotonic() >= next_watchdog:
                n = run_watchdog(conn, settings)
                if n:
                    log.info("Watchdog: %d alert events", n)
                next_watchdog = time.monotonic() + settings.watchdog_seconds
            if datetime.now(zone) >= next_report:
                run_daily(conn, settings, report_dir)
                next_report = next_report_time(datetime.now(zone), settings.report_hour)
        except Exception:
            log.exception("Scheduler cycle failed; continuing")
        stop.wait(5)
    log.info("Scheduler stopped")
