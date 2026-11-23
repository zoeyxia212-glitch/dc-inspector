"""Daily inspection report (HTML)."""

import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

from jinja2 import Environment, FileSystemLoader, select_autoescape

from inspector.db import from_text, to_text, utcnow

TEMPLATES = Path(__file__).resolve().parent / "templates"
_env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html"]))


def build_report_data(
    conn: sqlite3.Connection,
    since: datetime,
    until: datetime,
    expected_hosts: dict[str, str] | None = None,
    tz: str = "UTC",
) -> dict:
    """expected_hosts: {host: datacenter} from config, so silent hosts still show up."""
    zone = ZoneInfo(tz)
    window = (to_text(since), to_text(until))

    hosts: dict[str, dict] = {}
    for row in conn.execute(
        """SELECT s.host, MAX(s.datacenter) AS datacenter, COUNT(*) AS checks,
                      SUM(1 - s.up) AS unreachable,
                      AVG(CASE WHEN v.key = 'cpu.percent' THEN v.num END) AS avg_cpu,
                      MAX(CASE WHEN v.key = 'cpu.percent' THEN v.num END) AS max_cpu,
                      MAX(CASE WHEN v.key = 'mem.percent' THEN v.num END) AS max_mem
               FROM samples s
               LEFT JOIN sample_values v ON v.sample_id = s.id AND v.key IN ('cpu.percent', 'mem.percent')
               WHERE s.collected_at >= ? AND s.collected_at < ?
               GROUP BY s.host""",
        window,
    ):
        hosts[row["host"]] = {**dict(row), "max_disk": None, "service_failures": 0, "alerts": 0, "status": "OK"}
    # checks/unreachable above are inflated by the 2-key join; count them separately
    for row in conn.execute(
        """SELECT host, COUNT(*) AS checks, SUM(1 - up) AS unreachable FROM samples
               WHERE collected_at >= ? AND collected_at < ? GROUP BY host""",
        window,
    ):
        hosts[row["host"]].update(checks=row["checks"], unreachable=row["unreachable"])

    for host, dc in (expected_hosts or {}).items():
        hosts.setdefault(
            host,
            {
                "host": host,
                "datacenter": dc,
                "checks": 0,
                "unreachable": 0,
                "avg_cpu": None,
                "max_cpu": None,
                "max_mem": None,
                "max_disk": None,
                "service_failures": 0,
                "alerts": 0,
                "status": "NO DATA",
            },
        )

    for row in conn.execute(
        """SELECT s.host, MAX(v.num) AS max_disk
               FROM sample_values v JOIN samples s ON s.id = v.sample_id
               WHERE v.key LIKE 'disk.%.percent' AND v.key NOT LIKE '%inode%'
                 AND s.collected_at >= ? AND s.collected_at < ? GROUP BY s.host""",
        window,
    ):
        if row["host"] in hosts:
            hosts[row["host"]]["max_disk"] = row["max_disk"]

    for row in conn.execute(
        """SELECT s.host, COUNT(*) AS failures
               FROM sample_values v JOIN samples s ON s.id = v.sample_id
               WHERE v.key LIKE 'service.%.up' AND v.num = 0
                 AND s.collected_at >= ? AND s.collected_at < ? GROUP BY s.host""",
        window,
    ):
        if row["host"] in hosts:
            hosts[row["host"]]["service_failures"] = row["failures"]

    # Alerts that were active at any point during the window.
    alerts = [
        dict(a)
        for a in conn.execute(
            """SELECT * FROM alerts
           WHERE opened_at < ? AND (resolved_at IS NULL OR resolved_at >= ?)
           ORDER BY CASE severity WHEN 'critical' THEN 0 ELSE 1 END, opened_at""",
            (window[1], window[0]),
        )
    ]
    for alert in alerts:
        alert["opened_local"] = _local(alert["opened_at"], zone)
        alert["resolved_local"] = _local(alert["resolved_at"], zone) if alert["resolved_at"] else "still open"
        h = hosts.get(alert["host"])
        if h is None:
            continue
        h["alerts"] += 1
        if alert["severity"] == "critical":
            h["status"] = "CRITICAL"
        elif h["status"] == "OK":
            h["status"] = "WARNING"

    for h in hosts.values():
        h["availability"] = (100.0 * (h["checks"] - h["unreachable"]) / h["checks"]) if h["checks"] else None

    by_dc = defaultdict(list)
    for h in hosts.values():
        by_dc[h["datacenter"] or "-"].append(h)
    datacenters = []
    for dc, members in sorted(by_dc.items()):
        avail = [h["availability"] for h in members if h["availability"] is not None]
        datacenters.append(
            {
                "code": dc,
                "hosts": len(members),
                "availability": sum(avail) / len(avail) if avail else None,
                "alerts": sum(h["alerts"] for h in members),
                "problem_hosts": sum(h["status"] != "OK" for h in members),
            }
        )

    host_list = sorted(hosts.values(), key=lambda h: h["host"])
    problems = sorted(
        (h for h in host_list if h["status"] != "OK"), key=lambda h: (-h["alerts"], -(h["unreachable"] or 0), h["host"])
    )
    total_checks = sum(h["checks"] for h in host_list)
    total_up = sum(h["checks"] - h["unreachable"] for h in host_list)

    return {
        "since": _local(window[0], zone),
        "until": _local(window[1], zone),
        "timezone": tz,
        "summary": {
            "hosts": len(host_list),
            "checks": total_checks,
            "availability": 100.0 * total_up / total_checks if total_checks else None,
            "alerts": len(alerts),
            "critical": sum(a["severity"] == "critical" for a in alerts),
            "problem_hosts": len(problems),
        },
        "datacenters": datacenters,
        "hosts": host_list,
        "problems": problems[:10],
        "alerts": alerts,
    }


def render_report(data: dict) -> str:
    return _env.get_template("report.html").render(**data)


def write_report(
    conn: sqlite3.Connection,
    output_dir,
    until: datetime | None = None,
    hours: int = 24,
    expected_hosts: dict[str, str] | None = None,
    tz: str = "UTC",
) -> Path:
    until = until or utcnow()
    data = build_report_data(conn, until - timedelta(hours=hours), until, expected_hosts, tz)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"inspection report {until.astimezone(ZoneInfo(tz)):%Y%m%d}.html"
    path.write_text(render_report(data), encoding="utf-8")
    return path


def prune(conn: sqlite3.Connection, retention_days: int, now: datetime | None = None) -> int:
    """Delete samples, resolved alerts and old outbox rows past the retention period."""
    cutoff = to_text((now or utcnow()) - timedelta(days=retention_days))
    deleted = conn.execute("DELETE FROM samples WHERE collected_at < ?", (cutoff,)).rowcount
    conn.execute("DELETE FROM alerts WHERE status = 'resolved' AND resolved_at < ?", (cutoff,))
    conn.execute("DELETE FROM outbox WHERE status != 'pending' AND created_at < ?", (cutoff,))
    return deleted


def _local(text: str, zone: ZoneInfo) -> str:
    return from_text(text).astimezone(zone).strftime("%Y-%m-%d %H:%M")
