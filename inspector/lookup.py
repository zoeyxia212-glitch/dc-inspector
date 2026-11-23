"""Device lookup: search by IP, rack location or asset ID, and show port connections."""

import ipaddress
import re
import sqlite3

ASSET_RE = re.compile(r"^AST-\d{1,6}$", re.IGNORECASE)
RACK_RE = re.compile(r"^SH\d{2}(-[A-Z]\d{2})?$", re.IGNORECASE)  # SH01 or SH01-A03
IP_PREFIX_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){0,3}\.?$")  # 10.1. or 10.1.2

DEVICE_COLUMNS = """
    d.asset_id, d.hostname, d.ip, d.device_type, d.vendor, d.model,
    d.u_position, d.status, r.code AS rack, dc.code AS datacenter, dc.name AS datacenter_name
"""
DEVICE_JOIN = """
    FROM devices d
    JOIN racks r ON r.id = d.rack_id
    JOIN datacenters dc ON dc.id = r.datacenter_id
"""
MAX_RESULTS = 200


class InvalidQuery(ValueError):
    """Raised when a search term is not a valid IP, rack code or asset ID."""


def detect_query_type(query: str) -> str:
    """Guess what the user typed, so one search box works for everything."""
    q = query.strip()
    if ASSET_RE.match(q):
        return "asset_id"
    if RACK_RE.match(q):
        return "rack"
    if IP_PREFIX_RE.match(q):
        return "ip"
    raise InvalidQuery(f"'{query}' is not an IP address, rack code (SH01-A03) or asset ID (AST-000123)")


def search(conn: sqlite3.Connection, query: str) -> list[dict]:
    kind = detect_query_type(query)
    q = query.strip()
    if kind == "asset_id":
        number = int(q.split("-")[1])
        return _fetch(conn, "WHERE d.asset_id = ?", (f"AST-{number:06d}",))
    if kind == "rack":
        # Whole DC ("SH01") or one rack ("SH01-A03")
        return _fetch(conn, "WHERE r.code = ? OR dc.code = ?", (q.upper(), q.upper()))
    return search_by_ip(conn, q)


def search_by_ip(conn: sqlite3.Connection, ip: str) -> list[dict]:
    """Exact match for a full IP, prefix match for a partial one (e.g. '10.3.2.')."""
    ip = ip.strip()
    if ip.count(".") == 3 and not ip.endswith("."):
        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise InvalidQuery(f"'{ip}' is not a valid IP address") from exc
        return _fetch(conn, "WHERE d.ip = ?", (ip,))
    prefix = ip if ip.endswith(".") else ip + "."
    return _fetch(conn, "WHERE d.ip LIKE ?", (prefix + "%",))


def get_device_detail(conn: sqlite3.Connection, asset_id: str) -> dict | None:
    """Device info plus every port and what it is cabled to."""
    rows = _fetch(conn, "WHERE d.asset_id = ?", (asset_id.upper(),))
    if not rows:
        return None
    device = rows[0]
    ports = conn.execute(
        """
        SELECT p.name, p.speed, p.status,
               peer_dev.hostname AS peer_hostname,
               peer_dev.asset_id AS peer_asset_id,
               peer_port.name    AS peer_port
        FROM ports p
        JOIN devices d ON d.id = p.device_id
        LEFT JOIN connections c ON p.id IN (c.port_a_id, c.port_b_id)
        LEFT JOIN ports peer_port
               ON peer_port.id = CASE WHEN c.port_a_id = p.id THEN c.port_b_id ELSE c.port_a_id END
        LEFT JOIN devices peer_dev ON peer_dev.id = peer_port.device_id
        WHERE d.asset_id = ?
        ORDER BY p.id
        """,
        (device["asset_id"],),
    ).fetchall()
    device["ports"] = [dict(p) for p in ports]
    return device


def get_location(conn: sqlite3.Connection, hostname: str) -> str | None:
    """'SH01-A01 U2' style location for alert messages, or None if not in inventory."""
    row = conn.execute(
        f"SELECT r.code AS rack, d.u_position {DEVICE_JOIN} WHERE d.hostname = ?", (hostname,)
    ).fetchone()
    return f"{row['rack']} U{row['u_position']}" if row else None


def _fetch(conn: sqlite3.Connection, where: str, params: tuple) -> list[dict]:
    sql = f"SELECT {DEVICE_COLUMNS} {DEVICE_JOIN} {where} ORDER BY d.ip LIMIT {MAX_RESULTS}"
    return [dict(row) for row in conn.execute(sql, params).fetchall()]
