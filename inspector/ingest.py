"""Store samples sent by collectors and evaluate alerts (central server side)."""
import sqlite3
from datetime import datetime, timedelta

from inspector import alerts, lookup, notify
from inspector.config import ServerSettings
from inspector.db import TIME_FORMAT, from_text, to_text, transaction, utcnow
from inspector.parsers import SAFE_NAME

MAX_SAMPLES = 2000
MAX_VALUES = 500
MAX_CLOCK_SKEW = timedelta(minutes=10)


class IngestError(ValueError):
    pass


def validate_sample(s: dict, now: datetime) -> dict:
    if not isinstance(s, dict):
        raise IngestError("sample must be an object")
    host = s.get("host")
    if not isinstance(host, str) or not SAFE_NAME.match(host):
        raise IngestError(f"bad host name: {host!r}")
    try:
        collected = from_text(s.get("collected_at", ""))
    except (TypeError, ValueError):
        raise IngestError(f"{host}: collected_at must be {TIME_FORMAT}")
    if collected > now + MAX_CLOCK_SKEW:
        raise IngestError(f"{host}: collected_at is in the future (check NTP on the collector)")
    values = s.get("values") or {}
    if not isinstance(values, dict) or len(values) > MAX_VALUES:
        raise IngestError(f"{host}: values must be an object with at most {MAX_VALUES} keys")
    clean = {}
    for key, value in values.items():
        if not isinstance(key, str) or len(key) > 200:
            raise IngestError(f"{host}: bad metric key")
        if isinstance(value, bool) or not isinstance(value, (int, float, str)):
            raise IngestError(f"{host}: {key} must be a number or string")
        clean[key] = value if not isinstance(value, str) else value[:500]
    return {"host": host, "datacenter": str(s.get("datacenter") or "")[:20] or None,
            "collected_at": to_text(collected), "up": 1 if s.get("up") else 0,
            "duration_s": s.get("duration_s") if isinstance(s.get("duration_s"), (int, float)) else None,
            "error": (str(s["error"])[:500] if s.get("error") else None), "values": clean}


def ingest(conn: sqlite3.Connection, settings: ServerSettings, collector: str, payload: dict,
           location_of=None, now: datetime | None = None) -> dict:
    now = now or utcnow()
    location_of = location_of or (lambda host: lookup.get_location(conn, host))
    samples = payload.get("samples")
    if not isinstance(samples, list) or not samples:
        raise IngestError("samples must be a non-empty list")
    if len(samples) > MAX_SAMPLES:
        raise IngestError(f"at most {MAX_SAMPLES} samples per request")
    clean = sorted((validate_sample(s, now) for s in samples), key=lambda s: s["collected_at"])

    accepted = duplicates = 0
    events = []
    with transaction(conn):
        # Replay in collection order and evaluate after every sample, at the time it was
        # collected: after an outage, spooled rounds arrive together, and a problem that
        # started and ended inside that gap must still be recorded with the right times.
        for s in clean:
            cur = conn.execute(
                """INSERT OR IGNORE INTO samples (host, datacenter, collector, collected_at, received_at,
                                                  up, duration_s, error)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (s["host"], s["datacenter"], collector, s["collected_at"], to_text(now),
                 s["up"], s["duration_s"], s["error"]))
            if cur.rowcount == 0:
                duplicates += 1          # re-sent after an outage: already stored
                continue
            accepted += 1
            conn.executemany(
                "INSERT INTO sample_values (sample_id, key, num, text) VALUES (?, ?, ?, ?)",
                [(cur.lastrowid, k, v if not isinstance(v, str) else None, v if isinstance(v, str) else None)
                 for k, v in s["values"].items()])
            events += alerts.evaluate_host(conn, s["host"], settings.rules, from_text(s["collected_at"]))

        # An alert that opened and resolved inside this batch is reported once, as resolved
        # (the message carries both times), instead of two stale notifications.
        resolved_ids = {e["id"] for e in events if e["event"] == "resolved"}
        events = [e for e in events if not (e["event"] == "opened" and e["id"] in resolved_ids)]
        notify.enqueue(conn, events, settings.channels, location_of, now, settings.public_url)

        conn.execute(
            """UPDATE collectors SET last_seen_at = ?, version = ?, host_count = ?, spooled = ?
               WHERE name = ?""",
            (to_text(now), str(payload.get("version", ""))[:20],
             payload.get("host_count") if isinstance(payload.get("host_count"), int) else None,
             payload.get("spooled") if isinstance(payload.get("spooled"), int) else None, collector))
    return {"accepted": accepted, "duplicates": duplicates, "alert_events": len(events)}
