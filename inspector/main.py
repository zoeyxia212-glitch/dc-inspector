"""Command line entry point.

Central server
    python -m inspector.main init                      # create tables (+ mock inventory if empty)
    python -m inspector.main create-user alice --role admin
    python -m inspector.main add-collector sh-north    # prints the collector's API token once
    python -m inspector.main gen-token                 # random token to pre-share via a vault/secret
    python -m inspector.main server                    # dev web server (use gunicorn in production)
    python -m inspector.main scheduler                 # notifications, watchdog, daily report
    python -m inspector.main report                    # write a report now
    python -m inspector.main check-config              # validate server.yaml + rules.yaml
    python -m inspector.main export-devices inventory.csv
    python -m inspector.main import-devices inventory.csv [--dry-run]   # upsert from CMDB export
    python -m inspector.main backup /var/backups/dc-inspector [--keep 7]  # online, verified backup
    python -m inspector.main verify-backup "<file>"     # restore drill: open read-only and summarise

Regional collector
    python -m inspector.main agent --config collector.yaml
    python -m inspector.main collect-once --config collector.yaml   # debug: print one round as JSON
"""

import argparse
import getpass
import json
import logging
import os
import signal
import sys
import threading

from inspector import __version__, auth, report, scheduler
from inspector.config import DEFAULT_SERVER_CONFIG, REPORT_DIR, ConfigError, load_collector_config, load_server_config
from inspector.db import DEFAULT_DB_PATH, connect, init_schema
from inspector.logs import configure_logging
from inspector.seed import seed

log = logging.getLogger("inspector")


def _stop_event() -> threading.Event:
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    return stop


def _password(prompt_env: str) -> str:
    password = os.environ.get(prompt_env)
    if password:
        return password
    if not sys.stdin.isatty():
        sys.exit(f"Set {prompt_env} or run interactively")
    first = getpass.getpass("Password: ")
    if first != getpass.getpass("Repeat: "):
        sys.exit("Passwords do not match")
    return first


def main(argv=None) -> None:
    p = argparse.ArgumentParser(prog="inspector", description=f"DC Inspector {__version__}")
    p.add_argument(
        "command",
        choices=[
            "init",
            "seed",
            "create-user",
            "add-collector",
            "gen-token",
            "server",
            "scheduler",
            "report",
            "check-config",
            "agent",
            "collect-once",
            "import-devices",
            "export-devices",
            "backup",
            "verify-backup",
        ],
    )
    p.add_argument("name", nargs="?", help="username, collector name, or CSV file")
    p.add_argument("--role", default="viewer", choices=auth.ROLES)
    p.add_argument("--token", help="add-collector: pre-shared token from gen-token instead of a new one")
    p.add_argument("--server-config", default=DEFAULT_SERVER_CONFIG)
    p.add_argument("--config", help="collector config (agent, collect-once)")
    p.add_argument("--db", default=DEFAULT_DB_PATH)
    p.add_argument("--hours", type=int, default=24)
    p.add_argument("--dry-run", action="store_true", help="import-devices: validate only")
    p.add_argument("--keep", type=int, default=7, help="backup: number of backups to keep")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    args = p.parse_args(argv)
    configure_logging()

    try:
        if args.command in ("agent", "collect-once"):
            return _collector_command(args)
        return _server_command(args)
    except ConfigError as exc:
        sys.exit(f"Configuration error: {exc}")


def _collector_command(args) -> None:
    from inspector.agent import Agent, ssh_runner_factory  # collectors don't need Flask
    from inspector.collector import collect_all

    if not args.config:
        sys.exit("--config collector.yaml is required")
    settings = load_collector_config(args.config)
    if args.command == "collect-once":
        samples = collect_all(settings.hosts, ssh_runner_factory(settings))
        print(json.dumps(samples, indent=2))
        return
    if not settings.token:
        sys.exit(f"Collector token missing: set {settings.token_env}")
    Agent(settings).run_forever(_stop_event())


def _server_command(args) -> None:
    from inspector import ops

    if args.command == "verify-backup":
        if not args.name:
            sys.exit("Usage: verify-backup <backup file>")
        summary = ops.restore_check(args.name)
        print(json.dumps(summary))
        sys.exit(0 if summary["integrity"] == "ok" else 1)

    conn = connect(args.db)
    applied = init_schema(conn)
    if applied:
        log.info("Database migrated to schema version %s", applied[-1])

    if args.command == "backup":
        if not args.name:
            sys.exit("Usage: backup <directory> [--keep N]")
        path = ops.backup(conn, args.name, args.keep)
        log.info("Backup written and verified: %s", path)
        return

    if args.command == "check-config":
        s = load_server_config(args.server_config)
        print(f"OK: {len(s.rules)} rules, {len(s.checks)} custom checks, {len(s.channels)} channels")
        return
    if args.command in ("init", "seed"):
        empty = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0
        if args.command == "seed" or empty:
            seed(conn)
            log.info("Mock inventory loaded")
        log.info("Database ready at %s", args.db)
        return
    if args.command == "create-user":
        if not args.name:
            sys.exit("Usage: create-user <username> --role viewer|operator|admin")
        try:
            auth.create_user(conn, args.name, _password("INSPECTOR_NEW_PASSWORD"), args.role)
        except auth.AuthError as exc:
            sys.exit(str(exc))
        auth.audit(conn, "cli", "user_create", f"{args.name} as {args.role}")
        log.info("User %s created with role %s", args.name, args.role)
        return
    if args.command == "gen-token":
        print(auth.new_collector_token())
        return
    if args.command == "add-collector":
        if not args.name:
            sys.exit("Usage: add-collector <name> [--token TOKEN]")
        try:
            token = auth.register_collector(conn, args.name, args.token)
        except auth.AuthError as exc:
            sys.exit(str(exc))
        auth.audit(conn, "cli", "collector_register", args.name)
        if not args.token:
            print(f"Collector {args.name} registered. Token (shown once, store it in the collector's environment):")
            print(token)
        return

    if args.command in ("import-devices", "export-devices"):
        from inspector import inventory

        if not args.name:
            sys.exit(f"Usage: {args.command} <file.csv>")
        if args.command == "export-devices":
            with open(args.name, "w", encoding="utf-8", newline="") as f:
                f.write(inventory.export_csv(conn))
            log.info("Inventory exported to %s", args.name)
            return
        with open(args.name, encoding="utf-8-sig") as f:
            result = inventory.import_csv(conn, f.read(), dry_run=args.dry_run)
        for err in result.errors[:50]:
            print("ERROR", err)
        print(json.dumps({k: v for k, v in result.to_dict().items() if k != "errors"}))
        if result.ok and not args.dry_run:
            auth.audit(
                conn, "cli", "inventory_import", f"{args.name}: created {result.created}, updated {result.updated}"
            )
        sys.exit(0 if result.ok else 1)

    settings = load_server_config(args.server_config)
    if args.command == "report":
        path = report.write_report(conn, REPORT_DIR, hours=args.hours, tz=settings.timezone)
        log.info("Report written to %s", path)
    elif args.command == "scheduler":
        scheduler.run_forever(conn, settings, _stop_event())
    elif args.command == "server":
        from inspector.app import create_app

        create_app(args.db, settings=settings).run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
