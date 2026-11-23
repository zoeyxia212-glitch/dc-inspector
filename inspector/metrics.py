"""Read side of monitoring data: latest host snapshots and metric history."""

import re
import sqlite3
from datetime import datetime, timedelta

from inspector.db import to_text, utcnow

KEY_RE = re.compile(r"^[A-Za-z0-9_./@:-]{1,120}$")
MAX_KEYS = 10
MAX_POINTS = 300


def snapshot(row: sqlite3.Row, values: dict, stale_before: str, asset: dict | None, open_alerts: int) -> dict:
    """Display-ready summary of one sample row."""
    return {
        "host": row["host"],
        "asset_id": asset["asset_id"] if asset else None,
        "datacenter": row["datacenter"],
        "collector": row["collector"],
        "collected_at": row["collected_at"],
        "up": bool(row["up"]),
        "error": row["error"],
        "ssh_error": values.get("ssh.error"),
        "ping": values.get("ping.up"),
        "stale": row["collected_at"] < stale_before,
        "cpu": values.get("cpu.percent"),
        "mem": values.get("mem.percent"),
        "load_per_core": values.get("load.per_core"),
        "disks": {
            k[5:-8]: v
            for k, v in values.items()
            if k.startswith("disk.") and k.endswith(".percent") and not k.endswith(".inode_percent")
        },
        "services_down": sorted(
            k[8:-3] for k, v in values.items() if k.startswith("service.") and k.endswith(".up") and v == 0
        ),
        "checks": {k[6:]: v for k, v in values.items() if k.startswith("check.")},
        "open_alerts": open_alerts,
        "location": f"{asset['rack']} U{asset['u_position']}" if asset else None,
    }


def latest(
    conn: sqlite3.Connection, stale_seconds: int, host: str | None = None, now: datetime | None = None
) -> list[dict]:
    stale_before = to_text((now or utcnow()) - timedelta(seconds=stale_seconds))
    where, params = ("WHERE host = ?", (host,)) if host else ("", ())
    rows = conn.execute(
        f"""SELECT s.* FROM samples s
            JOIN (SELECT host, MAX(collected_at) AS t FROM samples {where} GROUP BY host) latest
              ON latest.host = s.host AND latest.t = s.collected_at
            ORDER BY s.host""",
        params,
    ).fetchall()
    if not rows:
        return []
    # A constant number of queries however many hosts there are (no per-host N+1 lookups).
    ids = [r["id"] for r in rows]
    marks = ",".join("?" * len(ids))
    values: dict[int, dict] = {i: {} for i in ids}
    for v in conn.execute(f"SELECT sample_id, key, num, text FROM sample_values WHERE sample_id IN ({marks})", ids):
        values[v["sample_id"]][v["key"]] = v["num"] if v["num"] is not None else v["text"]
    assets = {
        a["hostname"]: dict(a)
        for a in conn.execute(
            """SELECT d.hostname, d.asset_id, d.u_position, r.code AS rack
           FROM devices d JOIN racks r ON r.id = d.rack_id"""
        )
    }
    open_counts = {
        a["host"]: a["n"]
        for a in conn.execute("SELECT host, COUNT(*) AS n FROM alerts WHERE status = 'open' GROUP BY host")
    }
    return [
        snapshot(r, values[r["id"]], stale_before, assets.get(r["host"]), open_counts.get(r["host"], 0)) for r in rows
    ]


def history(
    conn: sqlite3.Connection,
    host: str,
    keys: list[str],
    hours: int = 24,
    now: datetime | None = None,
    max_points: int = MAX_POINTS,
) -> dict:
    """{key: [[time, value], ...]} for numeric metrics, plus 'up'. Downsampled by averaging."""
    if not keys or len(keys) > MAX_KEYS or not all(KEY_RE.match(k) for k in keys):
        raise ValueError(f"Give 1-{MAX_KEYS} metric keys like cpu.percent")
    if not 1 <= hours <= 24 * 31:
        raise ValueError("hours must be between 1 and 744")
    since = to_text((now or utcnow()) - timedelta(hours=hours))
    series: dict[str, list] = {k: [] for k in keys}
    series["up"] = [
        [r["collected_at"], float(r["up"])]
        for r in conn.execute(
            "SELECT collected_at, up FROM samples WHERE host = ? AND collected_at >= ? ORDER BY collected_at",
            (host, since),
        )
    ]
    marks = ",".join("?" * len(keys))
    for r in conn.execute(
        f"""SELECT s.collected_at, v.key, v.num FROM samples s
                JOIN sample_values v ON v.sample_id = s.id
                WHERE s.host = ? AND s.collected_at >= ? AND v.key IN ({marks}) AND v.num IS NOT NULL
                ORDER BY s.collected_at""",
        (host, since, *keys),
    ):
        series[r["key"]].append([r["collected_at"], r["num"]])
    return {k: _downsample(v, max_points) for k, v in series.items()}


def _downsample(points: list, max_points: int) -> list:
    if len(points) <= max_points:
        return points
    size = -(-len(points) // max_points)  # ceil
    out = []
    for i in range(0, len(points), size):
        chunk = points[i : i + size]
        out.append([chunk[-1][0], round(sum(p[1] for p in chunk) / len(chunk), 2)])
    return out
