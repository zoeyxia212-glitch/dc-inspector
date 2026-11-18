from inspector.db import connect
from inspector.seed import seed


def count(conn, sql):
    return conn.execute(sql).fetchone()[0]


def test_default_inventory_size(conn):
    assert count(conn, "SELECT COUNT(*) FROM datacenters") == 10
    assert count(conn, "SELECT COUNT(*) FROM racks") == 40
    assert count(conn, "SELECT COUNT(*) FROM devices WHERE device_type='switch'") == 40
    assert count(conn, "SELECT COUNT(*) FROM devices WHERE device_type='server'") == 320


def test_every_server_nic_is_cabled_to_a_switch(conn):
    uncabled = count(conn, """
        SELECT COUNT(*) FROM ports p JOIN devices d ON d.id = p.device_id
        WHERE d.device_type = 'server'
          AND p.id NOT IN (SELECT port_a_id FROM connections)""")
    assert uncabled == 0


def test_seed_is_repeatable():
    a, b = connect(":memory:"), connect(":memory:")
    seed(a, random_seed=7)
    seed(b, random_seed=7)
    q = "SELECT asset_id, vendor, status FROM devices ORDER BY id"
    assert a.execute(q).fetchall() == b.execute(q).fetchall()


def test_reseeding_does_not_duplicate(conn):
    seed(conn)
    assert count(conn, "SELECT COUNT(*) FROM devices") == 360
