"""Operating the central server itself: self-monitoring metrics and backups."""
import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

from inspector.db import from_text, to_text, utcnow

BACKUP_PREFIX = "inspector backup "


def _esc(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def prometheus_metrics(conn: sqlite3.Connection, stale_seconds: int, db_path=None,
                       now: datetime | None = None) -> str:
    """Prometheus text exposition format: lets an external system monitor the monitor."""
    now = now or utcnow()
    lines = []

    def metric(name, help_text, kind, samples):
        lines.append(f"# HELP dcinspector_{name} {help_text}")
        lines.append(f"# TYPE dcinspector_{name} {kind}")
        for labels, value in samples:
            label = ",".join(f'{k}="{_esc(v)}"' for k, v in labels.items())
            lines.append(f"dcinspector_{name}{{{label}}} {value}" if label else f"dcinspector_{name} {value}")

    collectors = conn.execute("SELECT name, last_seen_at, spooled FROM collectors ORDER BY name").fetchall()
    ages = [(c["name"], (now - from_text(c["last_seen_at"])).total_seconds() if c["last_seen_at"] else None)
            for c in collectors]
    metric("collector_last_seen_age_seconds", "Seconds since a collector last delivered data.", "gauge",
           [({"collector": n}, round(a, 1)) for n, a in ages if a is not None])
    metric("collector_up", "1 if the collector delivered data within the stale threshold.", "gauge",
           [({"collector": n}, int(a is not None and a <= stale_seconds)) for n, a in ages])
    metric("collector_spooled_batches", "Batches waiting in the collector's local spool.", "gauge",
           [({"collector": c["name"]}, c["spooled"] or 0) for c in collectors])

    counts = {(r["severity"]): r["n"] for r in conn.execute(
        "SELECT severity, COUNT(*) AS n FROM alerts WHERE status = 'open' AND parent_id IS NULL GROUP BY severity")}
    metric("alerts_open", "Open alerts (rack-grouped host alerts counted once).", "gauge",
           [({"severity": s}, counts.get(s, 0)) for s in ("warning", "critical")])
    unacked = conn.execute("""SELECT COUNT(*) FROM alerts WHERE status = 'open' AND severity = 'critical'
                              AND acked_at IS NULL AND silenced = 0 AND parent_id IS NULL""").fetchone()[0]
    metric("alerts_critical_unacknowledged", "Critical alerts nobody has acknowledged.", "gauge", [({}, unacked)])

    outbox = {r["status"]: r["n"] for r in conn.execute("SELECT status, COUNT(*) AS n FROM outbox GROUP BY status")}
    metric("notifications", "Notifications in the outbox by status.", "gauge",
           [({"status": s}, outbox.get(s, 0)) for s in ("pending", "sent", "failed")])
    oldest = conn.execute("SELECT MIN(created_at) FROM outbox WHERE status = 'pending'").fetchone()[0]
    metric("notifications_oldest_pending_seconds", "Age of the oldest undelivered notification.", "gauge",
           [({}, round((now - from_text(oldest)).total_seconds(), 1) if oldest else 0)])

    latest = conn.execute(
        """SELECT s.up FROM samples s JOIN (SELECT host, MAX(collected_at) AS t FROM samples GROUP BY host) l
           ON l.host = s.host AND l.t = s.collected_at""").fetchall()
    metric("hosts", "Monitored hosts by latest reachability.", "gauge",
           [({"state": "up"}, sum(r["up"] for r in latest)), ({"state": "down"}, sum(1 - r["up"] for r in latest))])
    recent = conn.execute("SELECT COUNT(*) FROM samples WHERE collected_at >= ?",
                          (to_text(now - timedelta(hours=1)),)).fetchone()[0]
    metric("samples_last_hour", "Samples stored in the last hour.", "gauge", [({}, recent)])
    if db_path and str(db_path) != ":memory:" and Path(db_path).exists():
        size = sum(Path(f"{db_path}{suffix}").stat().st_size for suffix in ("", "-wal")
                   if Path(f"{db_path}{suffix}").exists())
        metric("database_size_bytes", "Size of the SQLite database including WAL.", "gauge", [({}, size)])
    return "\n".join(lines) + "\n"


def backup(conn: sqlite3.Connection, dest_dir, keep: int = 7, now: datetime | None = None) -> Path:
    """Online backup (safe while the server is running), verified, with retention."""
    if keep < 1:
        raise ValueError("keep must be at least 1")
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    path = dest_dir / f"{BACKUP_PREFIX}{(now or utcnow()):%Y%m%d %H%M%S}.db"
    tmp = path.with_suffix(".tmp")
    target = sqlite3.connect(tmp)
    try:
        conn.backup(target)
        check = target.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        target.close()
    if check != "ok":
        tmp.unlink(missing_ok=True)
        raise RuntimeError(f"Backup failed integrity check: {check}")
    os.replace(tmp, path)                 # atomic: a half-written file is never left as a backup
    for old in sorted(dest_dir.glob(f"{BACKUP_PREFIX}*.db"))[:-keep]:
        old.unlink()
    return path


def restore_check(path) -> dict:
    """Open a backup read-only and report what it contains (for restore drills)."""
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return {"integrity": conn.execute("PRAGMA integrity_check").fetchone()[0],
                "schema_version": conn.execute("PRAGMA user_version").fetchone()[0],
                "devices": conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
                "samples": conn.execute("SELECT COUNT(*) FROM samples").fetchone()[0],
                "alerts": conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]}
    finally:
        conn.close()
