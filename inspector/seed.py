"""Generate a realistic, repeatable mock inventory.

Layout (defaults): 10 data centres x 4 racks.
Each rack has 1 top-of-rack (ToR) switch + 8 servers.
Every server has 2 NICs (eth0, eth1) cabled to ports on its rack's switch.

Run:  python -m inspector.seed
"""

import random
import sqlite3

from inspector.db import connect, init_schema, inserted_id

CITIES = [
    "Shanghai",
    "Shanghai",
    "Shanghai",
    "Shanghai",
    "Suzhou",
    "Hangzhou",
    "Kunshan",
    "Shanghai",
    "Nantong",
    "Jiaxing",
]
SERVER_MODELS = [
    ("Dell", "PowerEdge R750"),
    ("HPE", "ProLiant DL380"),
    ("Inspur", "NF5280M6"),
    ("Lenovo", "ThinkSystem SR650"),
]
SWITCH_MODELS = [("Huawei", "CE6881-48S6CQ"), ("H3C", "S6850-56HF")]
SWITCH_PORTS = 48


def seed(
    conn: sqlite3.Connection, num_dcs: int = 10, racks_per_dc: int = 4, servers_per_rack: int = 8, random_seed: int = 42
) -> None:
    """Wipe and refill the inventory tables. Same random_seed => same data."""
    if servers_per_rack * 2 > SWITCH_PORTS:
        raise ValueError("Not enough switch ports for that many servers")

    rng = random.Random(random_seed)  # noqa: S311 - reproducible mock data, not security
    init_schema(conn)
    conn.execute("BEGIN IMMEDIATE")
    for table in ("connections", "ports", "devices", "racks", "datacenters"):
        conn.execute(f"DELETE FROM {table}")

    asset_counter = 0

    def next_asset_id() -> str:
        nonlocal asset_counter
        asset_counter += 1
        return f"AST-{asset_counter:06d}"

    def add_port(device_id: int, name: str, speed: str, status: str = "up") -> int:
        cur = conn.execute(
            "INSERT INTO ports (device_id, name, speed, status) VALUES (?, ?, ?, ?)", (device_id, name, speed, status)
        )
        return inserted_id(cur)

    for dc_no in range(1, num_dcs + 1):
        dc_code = f"SH{dc_no:02d}"
        city = CITIES[(dc_no - 1) % len(CITIES)]
        dc_id = inserted_id(
            conn.execute(
                "INSERT INTO datacenters (code, name, city) VALUES (?, ?, ?)",
                (dc_code, f"{city} Data Centre {dc_no:02d}", city),
            )
        )

        for rack_no in range(1, racks_per_dc + 1):
            row_name = "AB"[(rack_no - 1) // 2 % 2]
            rack_code = f"{dc_code}-{row_name}{rack_no:02d}"
            rack_id = inserted_id(
                conn.execute(
                    "INSERT INTO racks (datacenter_id, code, row_name) VALUES (?, ?, ?)", (dc_id, rack_code, row_name)
                )
            )

            # IP plan: 10.<dc>.<rack>.<host>  — switch is .1, servers .11+
            subnet = f"10.{dc_no}.{rack_no}"

            vendor, model = rng.choice(SWITCH_MODELS)
            switch_id = inserted_id(
                conn.execute(
                    """INSERT INTO devices (asset_id, hostname, ip, device_type, vendor,
                                        model, rack_id, u_position, status)
                   VALUES (?, ?, ?, 'switch', ?, ?, ?, 42, 'online')""",
                    (next_asset_id(), f"{rack_code.lower()}-tor", f"{subnet}.1", vendor, model, rack_id),
                )
            )
            switch_ports = [add_port(switch_id, f"GE1/0/{p}", "25G", "down") for p in range(1, SWITCH_PORTS + 1)]

            for srv_no in range(1, servers_per_rack + 1):
                vendor, model = rng.choice(SERVER_MODELS)
                status = rng.choices(["online", "offline", "maintenance"], weights=[90, 5, 5])[0]
                if rack_no == 1 and srv_no == 1:
                    status = "online"  # srvNN in rack A01 are the monitored lab hosts
                server_id = inserted_id(
                    conn.execute(
                        """INSERT INTO devices (asset_id, hostname, ip, device_type, vendor,
                                            model, rack_id, u_position, status)
                       VALUES (?, ?, ?, 'server', ?, ?, ?, ?, ?)""",
                        (
                            next_asset_id(),
                            f"{rack_code.lower()}-srv{srv_no:02d}",
                            f"{subnet}.{10 + srv_no}",
                            vendor,
                            model,
                            rack_id,
                            srv_no * 2,
                            status,
                        ),
                    )
                )

                link_status = "up" if status == "online" else "down"
                for nic_no in range(2):  # eth0 -> switch port 2n-1, eth1 -> 2n
                    nic_id = add_port(server_id, f"eth{nic_no}", "25G", link_status)
                    sw_port_id = switch_ports[(srv_no - 1) * 2 + nic_no]
                    conn.execute("UPDATE ports SET status = ? WHERE id = ?", (link_status, sw_port_id))
                    conn.execute("INSERT INTO connections (port_a_id, port_b_id) VALUES (?, ?)", (nic_id, sw_port_id))

    conn.execute("COMMIT")


if __name__ == "__main__":
    connection = connect()
    seed(connection)
    total = connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    print(f"Seeded {total} devices into the inventory database.")
