"""Inventory (CMDB) maintenance: rack elevation and CSV import/export.

CSV columns: asset_id,hostname,ip,device_type,vendor,model,rack,u_position,status
Import is an upsert keyed by asset_id. The whole file is validated first and
applied in one transaction: either every row is applied or none is.
"""
import csv
import io
import re
import ipaddress
import sqlite3
from dataclasses import dataclass, field

from inspector.db import transaction
from inspector.parsers import SAFE_NAME

COLUMNS = ["asset_id", "hostname", "ip", "device_type", "vendor", "model", "rack", "u_position", "status"]
DEVICE_TYPES = ("server", "switch")
STATUSES = ("online", "offline", "maintenance")
MAX_ROWS = 20000
TEXT_RE = re.compile(r"^[A-Za-z0-9 ._()/+-]{1,80}$")
# Cells starting with these are run as formulas by Excel/Sheets (CSV injection, OWASP).
FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def _safe_cell(value) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(FORMULA_START) else text



# ---------------------------------------------------------------- rack elevation
def rack_elevation(conn: sqlite3.Connection, rack_code: str) -> dict | None:
    rack = conn.execute(
        """SELECT r.id, r.code, r.total_u, dc.code AS datacenter, dc.name AS datacenter_name
           FROM racks r JOIN datacenters dc ON dc.id = r.datacenter_id WHERE r.code = ?""",
        (rack_code.upper(),)).fetchone()
    if rack is None:
        return None
    devices = {}
    for d in conn.execute(
            """SELECT asset_id, hostname, ip, device_type, vendor, model, u_position, status
               FROM devices WHERE rack_id = ?""", (rack["id"],)):
        dev = dict(d)
        alerts = conn.execute(
            """SELECT MAX(CASE severity WHEN 'critical' THEN 2 ELSE 1 END) AS sev, COUNT(*) AS n
               FROM alerts WHERE host = ? AND status = 'open'""", (d["hostname"],)).fetchone()
        dev["open_alerts"] = alerts["n"]
        dev["alert_level"] = {2: "critical", 1: "warning"}.get(alerts["sev"])
        monitored = conn.execute("SELECT up FROM samples WHERE host = ? ORDER BY collected_at DESC LIMIT 1",
                                 (d["hostname"],)).fetchone()
        dev["monitored"] = monitored is not None
        dev["up"] = bool(monitored["up"]) if monitored else None
        devices[d["u_position"]] = dev
    units = [{"u": u, "device": devices.get(u)} for u in range(rack["total_u"], 0, -1)]
    used = len(devices)
    return {"rack": rack["code"], "datacenter": rack["datacenter"], "datacenter_name": rack["datacenter_name"],
            "total_u": rack["total_u"], "used_u": used, "free_u": rack["total_u"] - used, "units": units}


# ---------------------------------------------------------------- export
def export_csv(conn: sqlite3.Connection) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(COLUMNS)
    for r in conn.execute(
            """SELECT d.asset_id, d.hostname, d.ip, d.device_type, d.vendor, d.model, r.code AS rack,
                      d.u_position, d.status
               FROM devices d JOIN racks r ON r.id = d.rack_id ORDER BY d.asset_id"""):
        writer.writerow([_safe_cell(r[c]) for c in COLUMNS])
    return out.getvalue()


# ---------------------------------------------------------------- import
@dataclass
class ImportResult:
    created: int = 0
    updated: int = 0
    unchanged: int = 0
    errors: list[str] = field(default_factory=list)
    dry_run: bool = False

    @property
    def ok(self) -> bool:
        return not self.errors

    def to_dict(self) -> dict:
        return {"ok": self.ok, "dry_run": self.dry_run, "created": self.created,
                "updated": self.updated, "unchanged": self.unchanged, "errors": self.errors[:50],
                "error_count": len(self.errors)}


def _parse(text: str, racks: dict) -> tuple[list[dict], list[str]]:
    reader = csv.DictReader(io.StringIO(text.lstrip("﻿")))       # tolerate Excel's BOM
    missing = [c for c in COLUMNS if c not in (reader.fieldnames or [])]
    if missing:
        return [], [f"Missing columns: {', '.join(missing)}"]
    rows, errors = [], []
    for line, raw in enumerate(reader, start=2):
        if line - 1 > MAX_ROWS:
            errors.append(f"More than {MAX_ROWS} rows")
            break
        r = {k: (raw.get(k) or "").strip() for k in COLUMNS}
        problems = []
        if not r["asset_id"] or len(r["asset_id"]) > 40:
            problems.append("asset_id required")
        if not SAFE_NAME.match(r["hostname"]):
            problems.append(f"bad hostname {r['hostname']!r}")
        try:
            ipaddress.ip_address(r["ip"])
        except ValueError:
            problems.append(f"bad ip {r['ip']!r}")
        if r["device_type"] not in DEVICE_TYPES:
            problems.append(f"device_type must be one of {DEVICE_TYPES}")
        if r["status"] not in STATUSES:
            problems.append(f"status must be one of {STATUSES}")
        rack = racks.get(r["rack"].upper())
        if rack is None:
            problems.append(f"unknown rack {r['rack']!r}")
        try:
            r["u_position"] = int(r["u_position"])
            if rack and not 1 <= r["u_position"] <= rack["total_u"]:
                problems.append(f"u_position must be 1-{rack['total_u']}")
        except ValueError:
            problems.append("u_position must be a number")
        for col in ("vendor", "model"):
            if not TEXT_RE.match(r[col]) or r[col].startswith(FORMULA_START):
                problems.append(f"{col} must be 1-80 letters, digits, spaces or . _ ( ) / + - (not starting with + or -)")
        if problems:
            errors.append(f"line {line}: " + "; ".join(problems))
        else:
            r["rack_id"] = rack["id"]
            r["asset_id"] = r["asset_id"].upper()
            rows.append(r | {"line": line})
    return rows, errors


def import_csv(conn: sqlite3.Connection, text: str, dry_run: bool = False) -> ImportResult:
    result = ImportResult(dry_run=dry_run)
    racks = {r["code"]: dict(r) for r in conn.execute("SELECT id, code, total_u FROM racks")}
    rows, result.errors = _parse(text, racks)
    if result.errors:
        return result
    if not rows:
        result.errors.append("No data rows")
        return result

    # duplicates inside the file
    for key in ("asset_id", "hostname", "ip"):
        seen = {}
        for r in rows:
            if r[key] in seen:
                result.errors.append(f"line {r['line']}: duplicate {key} {r[key]} (also line {seen[r[key]]})")
            seen[r[key]] = r["line"]
    if result.errors:
        return result

    try:
        with transaction(conn):
            for r in rows:
                existing = conn.execute("SELECT * FROM devices WHERE asset_id = ?", (r["asset_id"],)).fetchone()
                values = (r["hostname"], r["ip"], r["device_type"], r["vendor"], r["model"],
                          r["rack_id"], r["u_position"], r["status"])
                if existing is None:
                    conn.execute(
                        """INSERT INTO devices (hostname, ip, device_type, vendor, model, rack_id, u_position,
                                                status, asset_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (*values, r["asset_id"]))
                    result.created += 1
                elif tuple(existing[c] for c in ("hostname", "ip", "device_type", "vendor", "model",
                                                  "rack_id", "u_position", "status")) == values:
                    result.unchanged += 1
                else:
                    conn.execute(
                        """UPDATE devices SET hostname=?, ip=?, device_type=?, vendor=?, model=?, rack_id=?,
                                              u_position=?, status=? WHERE asset_id = ?""", (*values, r["asset_id"]))
                    result.updated += 1
            # Checked against the final state, so swaps/moves inside one file are fine.
            for clash in conn.execute(
                    """SELECT r.code, d.u_position, GROUP_CONCAT(d.asset_id, ', ') AS assets
                       FROM devices d JOIN racks r ON r.id = d.rack_id
                       GROUP BY d.rack_id, d.u_position HAVING COUNT(*) > 1"""):
                result.errors.append(f"rack {clash['code']} U{clash['u_position']} used by {clash['assets']}")
            if result.errors or dry_run:
                raise _Rollback()
    except _Rollback:
        if result.errors:
            result.created = result.updated = result.unchanged = 0
    except sqlite3.IntegrityError as exc:
        result.created = result.updated = result.unchanged = 0
        result.errors.append(f"Conflicts with an existing device (hostname or ip already used): {exc}")
    return result


class _Rollback(Exception):
    pass
