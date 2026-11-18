from datetime import timedelta

import pytest

from inspector import inventory, metrics
from inspector.main import main

from conftest import HOST, T0, at

HEADER = ",".join(inventory.COLUMNS)


def row(asset="AST-900001", host="new-srv01", ip="10.99.0.1", dtype="server", rack="SH01-A01", u=30,
        status="online", vendor="Dell", model="R760"):
    return f"{asset},{host},{ip},{dtype},{vendor},{model},{rack},{u},{status}"


def csv_text(*rows):
    return "\n".join([HEADER, *rows]) + "\n"


def count(conn):
    return conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]


# ---------------------------------------------------------- rack elevation
def test_rack_elevation(conn, push):
    push(0, **{"service.nginx.up": 0.0})
    rack = inventory.rack_elevation(conn, "sh01-a01")
    assert rack["total_u"] == 42 and rack["used_u"] == 9 and rack["free_u"] == 33
    assert [u["u"] for u in rack["units"][:2]] == [42, 41]              # top of the rack first
    top = rack["units"][0]["device"]
    assert top["device_type"] == "switch" and top["monitored"] is False
    srv = next(u["device"] for u in rack["units"] if u["u"] == 2)
    assert srv["hostname"] == HOST and srv["up"] is True
    assert srv["open_alerts"] == 1 and srv["alert_level"] == "critical"


def test_unknown_rack(conn):
    assert inventory.rack_elevation(conn, "SH99-Z99") is None


# ---------------------------------------------------------- export / import
def test_export_then_import_is_unchanged(conn):
    text = inventory.export_csv(conn)
    assert text.splitlines()[0] == HEADER and len(text.splitlines()) == 361
    result = inventory.import_csv(conn, text)
    assert result.ok and (result.created, result.updated, result.unchanged) == (0, 0, 360)


def test_create_and_update(conn):
    result = inventory.import_csv(conn, csv_text(row(), row(asset="AST-000002", host="sh01-a01-srv01",
                                                           ip="10.1.1.11", u=2, status="maintenance",
                                                           vendor="Dell", model="PowerEdge R750")))
    assert result.ok and result.created == 1 and result.updated == 1
    assert conn.execute("SELECT status FROM devices WHERE asset_id='AST-000002'").fetchone()[0] == "maintenance"
    assert count(conn) == 361


def test_dry_run_changes_nothing(conn):
    result = inventory.import_csv(conn, csv_text(row()), dry_run=True)
    assert result.ok and result.created == 1 and count(conn) == 360


@pytest.mark.parametrize("bad, message", [
    (row(ip="10.99.0.999"), "bad ip"),
    (row(rack="SH99-A01"), "unknown rack"),
    (row(u=50), "u_position must be 1-42"),
    (row(dtype="router"), "device_type"),
    (row(status="broken"), "status"),
    (row(host="bad host"), "bad hostname"),
    (row(u=2), "SH01-A01 U2 used by"),                      # occupied by an existing server
    (row(ip="10.1.1.11"), "already used"),                  # ip of an existing device
])
def test_invalid_rows_reject_whole_file(conn, bad, message):
    result = inventory.import_csv(conn, csv_text(row(asset="AST-900002", host="ok-srv", ip="10.99.0.2", u=31), bad))
    assert not result.ok and message in " ".join(result.errors)
    assert count(conn) == 360                               # nothing applied, not even the good row


def test_duplicates_within_file(conn):
    result = inventory.import_csv(conn, csv_text(row(), row(asset="AST-900002", u=31)))
    assert not result.ok and "duplicate hostname" in result.errors[0]


def test_move_inside_one_file_is_allowed(conn):
    # swap two servers' U positions in a single import
    text = inventory.export_csv(conn)
    text = text.replace(",SH01-A01,2,", ",SH01-A01,TMP,").replace(",SH01-A01,4,", ",SH01-A01,2,").replace(",SH01-A01,TMP,", ",SH01-A01,4,")
    result = inventory.import_csv(conn, text)
    assert result.ok and result.updated == 2


def test_missing_columns_and_excel_bom(conn):
    assert "Missing columns" in inventory.import_csv(conn, "asset_id,hostname\nA,b\n").errors[0]
    assert inventory.import_csv(conn, "﻿" + csv_text(row())).ok


def test_cli_import_export(conn, tmp_path, monkeypatch):
    db = tmp_path / "x.db"
    out = tmp_path / "inv.csv"
    main(["seed", "--db", str(db)])
    main(["export-devices", str(out), "--db", str(db)])
    out.write_text(out.read_text() + row() + "\n")
    with pytest.raises(SystemExit) as exit_:
        main(["import-devices", str(out), "--db", str(db), "--dry-run"])
    assert exit_.value.code == 0


# ---------------------------------------------------------- metrics
def test_history_series(conn, push):
    for step in range(5):
        push(step, **{"cpu.percent": 10.0 + step})
    push(5, up=False)
    data = metrics.history(conn, HOST, ["cpu.percent", "disk./.percent"], hours=1, now=at(6))
    assert [p[1] for p in data["cpu.percent"]] == [10.0, 11.0, 12.0, 13.0, 14.0]
    assert [p[1] for p in data["up"]] == [1.0] * 5 + [0.0]
    assert len(data["disk./.percent"]) == 5


def test_history_window_and_downsampling(conn, push):
    for step in range(20):
        push(step, **{"cpu.percent": float(step)})
    data = metrics.history(conn, HOST, ["cpu.percent"], hours=1, now=at(20), max_points=5)
    assert len(data["cpu.percent"]) == 5 and data["cpu.percent"][0][1] == 1.5      # mean of 0..3
    recent = metrics.history(conn, HOST, ["cpu.percent"], hours=1, now=at(20) + timedelta(minutes=55))
    assert len(recent["cpu.percent"]) < 20


@pytest.mark.parametrize("keys, hours", [([], 24), (["x"] * 11, 24), (["cpu.percent; drop"], 24), (["cpu.percent"], 0)])
def test_history_validation(conn, keys, hours):
    with pytest.raises(ValueError):
        metrics.history(conn, HOST, keys, hours)


def test_latest_snapshot_links_asset(conn, push):
    push(0)
    snap = metrics.latest(conn, 90, now=at(0))[0]
    assert snap["asset_id"] == "AST-000002" and snap["location"] == "SH01-A01 U2" and not snap["stale"]
