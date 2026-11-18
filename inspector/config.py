"""Configuration for the central server (server.yaml) and regional collectors (collector.yaml).

Secrets never live in these files: they reference environment variables
(`*_env` keys), which come from the deployment (systemd EnvironmentFile,
Docker secrets/.env, Ansible Vault).
"""
import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from inspector.db import PROJECT_ROOT
from inspector.parsers import DEFAULT_SERVICE_CHECK, SAFE_NAME, CheckDef
from inspector.rules import Rule, load_rules

DEFAULT_SERVER_CONFIG = Path(os.environ.get("INSPECTOR_SERVER_CONFIG", PROJECT_ROOT / "config" / "server.yaml"))
REPORT_DIR = Path(os.environ.get("INSPECTOR_REPORTS", PROJECT_ROOT / "reports"))


class ConfigError(ValueError):
    pass


# ---------------------------------------------------------------- central server
@dataclass
class Channel:
    name: str
    type: str                                  # email | wecom | dingtalk | slack
    min_severity: str = "warning"
    datacenters: list[str] = field(default_factory=list)   # empty = all
    daily_report: bool = False
    settings: dict = field(default_factory=dict)

    TYPES = ("email", "wecom", "dingtalk", "slack")

    def __post_init__(self):
        if self.type not in self.TYPES:
            raise ConfigError(f"Channel {self.name}: type must be one of {self.TYPES}")
        if self.min_severity not in ("warning", "critical"):
            raise ConfigError(f"Channel {self.name}: min_severity must be warning or critical")

    def secret(self, key: str) -> str | None:
        """Value of setting `key`, or of the env var named by `key_env`."""
        if self.settings.get(f"{key}_env"):
            return os.environ.get(self.settings[f"{key}_env"])
        return self.settings.get(key)


@dataclass
class ServerSettings:
    rules: list[Rule]
    checks: list[CheckDef] = field(default_factory=list)
    channels: list[Channel] = field(default_factory=list)
    interval_seconds: int = 30
    service_check: str = DEFAULT_SERVICE_CHECK
    collector_stale_seconds: int = 120
    watchdog_seconds: int = 30
    renotify_after_minutes: int = 30
    report_hour: int = 8
    timezone: str = "Pacific/Auckland"
    retention_days: int = 30
    audit_retention_days: int = 365
    public_url: str = "http://localhost:8000"

    def collector_config(self) -> dict:
        """What collectors pull from GET /api/v1/collector/config."""
        return {"interval_seconds": self.interval_seconds, "service_check": self.service_check,
                "checks": [c.to_dict() for c in self.checks]}


def load_server_config(path=DEFAULT_SERVER_CONFIG) -> ServerSettings:
    path = Path(path)
    raw = _read(path)
    rules_path = path.parent / raw.get("rules_file", "rules.yaml")
    collection = raw.get("collection", {})
    alerting = raw.get("alerting", {})
    report = raw.get("report", {})
    try:
        checks = [CheckDef(**c) for c in collection.get("checks", [])]
        channels = []
        for c in raw.get("notifications", {}).get("channels", []):
            c = dict(c)
            fixed = {k: c.pop(k) for k in ("name", "type", "min_severity", "datacenters", "daily_report") if k in c}
            channels.append(Channel(**fixed, settings=c))
        rules = load_rules(rules_path)
    except (TypeError, ValueError) as exc:
        raise ConfigError(str(exc)) from exc
    _unique([c.name for c in checks], "check")
    _unique([c.name for c in channels], "channel")

    return ServerSettings(
        rules=rules, checks=checks, channels=channels,
        interval_seconds=int(collection.get("interval_seconds", 30)),
        service_check=collection.get("service_check", DEFAULT_SERVICE_CHECK),
        collector_stale_seconds=int(alerting.get("collector_stale_seconds", 120)),
        watchdog_seconds=int(alerting.get("watchdog_seconds", 30)),
        renotify_after_minutes=int(alerting.get("renotify_after_minutes", 30)),
        report_hour=int(report.get("hour", 8)),
        timezone=report.get("timezone", "Pacific/Auckland"),
        retention_days=int(raw.get("retention_days", 30)),
        audit_retention_days=int(raw.get("audit_retention_days", 365)),
        public_url=os.environ.get("INSPECTOR_PUBLIC_URL") or raw.get("public_url", "http://localhost:8000"),
    )


# ---------------------------------------------------------------- regional collector
@dataclass
class HostConfig:
    name: str
    address: str
    datacenter: str
    port: int = 22
    username: str = "inspector"
    password_env: str | None = None
    key_file: str | None = None
    mounts: list[str] = field(default_factory=lambda: ["/"])
    services: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not SAFE_NAME.match(self.name):
            raise ConfigError(f"Invalid host name {self.name!r}")

    @property
    def password(self) -> str | None:
        return os.environ.get(self.password_env) if self.password_env else None


@dataclass
class CollectorSettings:
    name: str
    central_url: str
    hosts: list[HostConfig]
    token_env: str = "INSPECTOR_COLLECTOR_TOKEN"
    ssh_client: str = "openssh"                # openssh (system ssh, keys) | paramiko
    ssh_timeout: int = 10
    known_hosts: str | None = None
    max_workers: int = 20
    spool_path: str = "spool.db"
    spool_max_batches: int = 20000             # ~1 week at 30 s; oldest dropped beyond this
    config_refresh_seconds: int = 300

    @property
    def token(self) -> str | None:
        return os.environ.get(self.token_env)


def load_collector_config(path) -> CollectorSettings:
    raw = _read(Path(path))
    defaults = raw.get("defaults", {})
    ssh = raw.get("ssh", {})
    try:
        hosts = [HostConfig(**{**defaults, **h}) for h in raw.get("hosts", [])]
    except TypeError as exc:
        raise ConfigError(f"Bad host entry: {exc}") from exc
    _unique([h.name for h in hosts], "host")
    if ssh.get("client", "openssh") not in ("openssh", "paramiko"):
        raise ConfigError("ssh.client must be openssh or paramiko")
    for key in ("name", "central_url"):
        if not raw.get(key):
            raise ConfigError(f"collector config needs '{key}'")
    return CollectorSettings(
        name=raw["name"], central_url=raw["central_url"].rstrip("/"), hosts=hosts,
        token_env=raw.get("token_env", "INSPECTOR_COLLECTOR_TOKEN"),
        ssh_client=ssh.get("client", "openssh"), ssh_timeout=int(ssh.get("timeout", 10)),
        known_hosts=ssh.get("known_hosts"), max_workers=int(raw.get("max_workers", 20)),
        spool_path=raw.get("spool_path", "spool.db"),
        spool_max_batches=int(raw.get("spool_max_batches", 20000)),
        config_refresh_seconds=int(raw.get("config_refresh_seconds", 300)),
    )


def _read(path: Path) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError as exc:
        raise ConfigError(f"Config file not found: {path}") from exc


def _unique(names, what):
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        raise ConfigError(f"Duplicate {what} names: {dupes}")
