"""Load test for the central server: how many hosts can one SQLite-backed instance handle?

    python scripts/benchmark.py --hosts 2000 --rounds 10

Simulates collectors sending realistic samples (about 15 metrics per host) in batches of
`--batch` hosts, with a few hosts failing each round so alert evaluation and rack correlation
do real work. Measures ingest (storage + rule evaluation + notifications) and the read paths
the UI uses. Runs on a temporary file database with WAL, like production.
"""

import argparse
import random
import statistics
import sys
import tempfile
import time
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from inspector import auth, inventory, metrics
from inspector.config import load_server_config
from inspector.db import connect, to_text, utcnow
from inspector.ingest import ingest
from inspector.seed import seed


def sample(host: str, when: str, rng: random.Random, failing: bool) -> dict:
    if failing:
        return {
            "host": host,
            "datacenter": "SH01",
            "collected_at": when,
            "up": 0,
            "error": "Connection timed out",
            "values": {"ssh.error": "timeout", "ping.up": 0.0},
        }
    return {
        "host": host,
        "datacenter": "SH01",
        "collected_at": when,
        "up": 1,
        "values": {
            "cpu.percent": round(rng.uniform(2, 70), 1),
            "mem.percent": round(rng.uniform(20, 80), 1),
            "swap.percent": 0.0,
            "load.1": 0.4,
            "load.5": 0.3,
            "load.15": 0.2,
            "cpu.cores": 16.0,
            "load.per_core": 0.03,
            "disk./.percent": 55.0,
            "disk./.inode_percent": 4.0,
            "disk./data.percent": round(rng.uniform(30, 80), 1),
            "disk./data.inode_percent": 2.0,
            "service.nginx.up": 1.0,
            "service.crond.up": 1.0,
            "check.zombies": 0.0,
            "check.uptime_s": 900000.0,
            "check.ro_mounts": 0.0,
        },
    }


def pct(values, p):
    values = sorted(values)
    return values[min(len(values) - 1, round(p / 100 * (len(values) - 1)))]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hosts", type=int, default=2000)
    ap.add_argument("--rounds", type=int, default=10)
    ap.add_argument("--batch", type=int, default=500, help="hosts per ingest request (one collector round)")
    ap.add_argument("--fail-rate", type=float, default=0.01)
    args = ap.parse_args()

    rng = random.Random(7)
    settings = load_server_config()
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "bench.db"
        conn = connect(db_path)
        seed(conn)
        auth.register_collector(conn, "bench", "bench-token-0123456789abcdefgh")
        # first 360 hosts are real inventory devices (rack correlation applies), the rest are extra
        inventory_hosts = [r[0] for r in conn.execute("SELECT hostname FROM devices WHERE device_type='server'")]
        hosts = (inventory_hosts + [f"extra-{i:05d}" for i in range(args.hosts)])[: args.hosts]

        start = utcnow() - timedelta(seconds=30 * args.rounds)
        per_batch, per_round = [], []
        failing = set(rng.sample(hosts, max(1, int(len(hosts) * args.fail_rate))))
        for rnd in range(args.rounds):
            when = to_text(start + timedelta(seconds=30 * rnd))
            if rnd == args.rounds // 2:  # half-way: different hosts fail, earlier ones recover
                failing = set(rng.sample(hosts, max(1, int(len(hosts) * args.fail_rate))))
            round_start = time.perf_counter()
            for i in range(0, len(hosts), args.batch):
                batch = [sample(h, when, rng, h in failing) for h in hosts[i : i + args.batch]]
                t = time.perf_counter()
                ingest(conn, settings, "bench", {"samples": batch}, now=start + timedelta(seconds=30 * rnd))
                per_batch.append(time.perf_counter() - t)
            per_round.append(time.perf_counter() - round_start)

        def timed(fn, n=5):
            runs = []
            for _ in range(n):
                t = time.perf_counter()
                fn()
                runs.append(time.perf_counter() - t)
            return statistics.median(runs)

        latest_s = timed(lambda: metrics.latest(conn, 90))
        history_s = timed(lambda: metrics.history(conn, hosts[0], ["cpu.percent", "mem.percent"], 24))
        rack_s = timed(lambda: inventory.rack_elevation(conn, "SH01-A01"))
        alerts_open = conn.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0]
        samples = conn.execute("SELECT COUNT(*) FROM samples").fetchone()[0]
        values = conn.execute("SELECT COUNT(*) FROM sample_values").fetchone()[0]
        size_mb = sum(p.stat().st_size for p in Path(tmp).glob("bench.db*")) / 1e6

    interval = 30
    print(f"\nHosts {args.hosts} · rounds {args.rounds} · batch {args.batch} · fail rate {args.fail_rate:.0%}")
    print(f"Stored: {samples:,} samples, {values:,} metric values, {alerts_open} open alerts, DB {size_mb:.1f} MB\n")
    print(
        f"{'Ingest per batch (store + rules + notify)':45} p50 {pct(per_batch, 50) * 1000:7.1f} ms   "
        f"p95 {pct(per_batch, 95) * 1000:7.1f} ms"
    )
    print(
        f"{'Ingest per full round (all hosts)':45} p50 {pct(per_round, 50):7.2f} s    "
        f"= {pct(per_round, 50) / interval:.0%} of a {interval} s interval"
    )
    print(f"{'Throughput':45} {args.hosts / pct(per_round, 50):,.0f} host-samples/s")
    print(f"{'GET /api/v1/hosts (latest for all hosts)':45} {latest_s * 1000:7.2f} ms")
    print(f"{'Host history 24 h (2 metrics)':45} {history_s * 1000:7.2f} ms")
    print(f"{'Rack elevation (42U)':45} {rack_s * 1000:7.2f} ms")
    capacity = int(args.hosts * interval / pct(per_round, 50) * 0.5)
    print(
        f"\nEstimated capacity at 50% utilisation and a {interval} s interval: ~{capacity:,} hosts per central server"
    )


if __name__ == "__main__":
    main()
