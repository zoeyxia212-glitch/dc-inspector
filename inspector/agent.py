"""Regional collector agent: one per site, runs next to the hosts it inspects.

  - pulls interval + custom checks from the central server (cached locally)
  - collects all its hosts in parallel over SSH every interval
  - store-and-forward: every batch goes to a local spool first, then is sent
    oldest-first; if the central server or the WAN link is down, data is kept
    and delivered later (the server de-duplicates re-sent samples)
"""
import json
import os
import logging
import sqlite3
import threading
import time
import urllib.error
import urllib.request

from inspector import __version__
from inspector.collector import RunnerFactory, collect_all
from inspector.config import CollectorSettings
from inspector.parsers import DEFAULT_SERVICE_CHECK, CheckDef
from inspector.sshclient import OpenSSHRunner, SSHRunner

log = logging.getLogger(__name__)
DEFAULT_REMOTE_CONFIG = {"interval_seconds": 30, "service_check": DEFAULT_SERVICE_CHECK, "checks": []}


class CentralError(RuntimeError):
    pass


class CentralClient:
    def __init__(self, base_url: str, token: str | None, timeout: int = 15):
        self.base_url, self.token, self.timeout = base_url.rstrip("/"), token, timeout

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict:
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(self.base_url + path, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}", "Content-Type": "application/json",
            "User-Agent": f"dc-inspector-collector/{__version__}"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:200]
            raise CentralError(f"HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            raise CentralError(f"central unreachable: {exc}") from exc

    def get_config(self) -> dict:
        return self._request("GET", "/api/v1/collector/config")

    def send(self, payload: dict) -> dict:
        return self._request("POST", "/api/v1/ingest", payload)


class Spool:
    """Durable local queue (SQLite) of batches waiting to be sent."""

    def __init__(self, path: str, max_batches: int = 20000):
        self.conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.conn.execute("CREATE TABLE IF NOT EXISTS spool (id INTEGER PRIMARY KEY, payload TEXT NOT NULL)")
        self.conn.execute("CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self.max_batches = max_batches

    def add(self, samples: list[dict]) -> None:
        self.conn.execute("INSERT INTO spool (payload) VALUES (?)", (json.dumps(samples),))
        over = self.count() - self.max_batches
        if over > 0:
            self.conn.execute("DELETE FROM spool WHERE id IN (SELECT id FROM spool ORDER BY id LIMIT ?)", (over,))
            log.error("Spool full: dropped %d oldest batches", over)

    def oldest(self, limit: int) -> list[tuple[int, list]]:
        return [(r[0], json.loads(r[1])) for r in
                self.conn.execute("SELECT id, payload FROM spool ORDER BY id LIMIT ?", (limit,))]

    def delete(self, ids: list[int]) -> None:
        self.conn.executemany("DELETE FROM spool WHERE id = ?", [(i,) for i in ids])

    def count(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM spool").fetchone()[0]

    def get(self, key: str):
        row = self.conn.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, key: str, value) -> None:
        self.conn.execute("INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)", (key, json.dumps(value)))


def ssh_runner_factory(settings: CollectorSettings) -> RunnerFactory:
    def make(host):
        if settings.ssh_client == "openssh":
            return OpenSSHRunner(host.address, host.port, host.username, host.key_file,
                                 settings.ssh_timeout, settings.known_hosts, settings.ssh_control_dir)
        return SSHRunner(host.address, host.port, host.username, host.password, host.key_file,
                         settings.ssh_timeout, settings.known_hosts)
    return make


class Agent:
    def __init__(self, settings: CollectorSettings, client: CentralClient | None = None,
                 runner_factory: RunnerFactory | None = None, spool: Spool | None = None):
        self.settings = settings
        self.client = client or CentralClient(settings.central_url, settings.token)
        self.runner_factory = runner_factory or ssh_runner_factory(settings)
        self.spool = spool or Spool(settings.spool_path, settings.spool_max_batches)
        if settings.ssh_control_dir:
            os.makedirs(settings.ssh_control_dir, mode=0o700, exist_ok=True)
        self.remote = self.spool.get("remote_config") or dict(DEFAULT_REMOTE_CONFIG)
        self._config_fetched_at = None

    def refresh_config(self, force: bool = False) -> None:
        due = self._config_fetched_at is None or \
            time.monotonic() - self._config_fetched_at >= self.settings.config_refresh_seconds
        if not (force or due):
            return
        try:
            remote = self.client.get_config()
            [CheckDef(**c) for c in remote.get("checks", [])]       # validate before use
        except (CentralError, TypeError, ValueError) as exc:
            log.warning("Could not refresh config from central (%s); using cached config", exc)
            self._config_fetched_at = time.monotonic() - self.settings.config_refresh_seconds + 60
            return
        if remote != self.remote:
            log.info("Config from central: interval %ss, %d custom checks",
                     remote.get("interval_seconds"), len(remote.get("checks", [])))
        self.remote = remote
        self.spool.put("remote_config", remote)
        self._config_fetched_at = time.monotonic()

    @property
    def interval(self) -> int:
        return max(5, int(self.remote.get("interval_seconds", 30)))

    def collect(self) -> list[dict]:
        checks = [CheckDef(**c) for c in self.remote.get("checks", [])]
        return collect_all(self.settings.hosts, self.runner_factory, checks,
                           self.remote.get("service_check", DEFAULT_SERVICE_CHECK),
                           self.settings.max_workers)

    def flush(self, max_batches: int = 50) -> int:
        """Send spooled batches oldest-first. Stops at the first failure (order is preserved)."""
        sent = 0
        while True:
            batch = self.spool.oldest(10)[: max_batches - sent]
            if not batch:
                return sent
            samples = [s for _, b in batch for s in b]
            try:
                self.client.send({"collector": self.settings.name, "version": __version__,
                                  "host_count": len(self.settings.hosts),
                                  "spooled": self.spool.count() - len(batch), "samples": samples})
            except CentralError as exc:
                if "HTTP 4" in str(exc) and "HTTP 401" not in str(exc) and "HTTP 429" not in str(exc):
                    # The server rejected this data as invalid: drop it rather than block the queue forever.
                    log.error("Central rejected %d batches, dropping them: %s", len(batch), exc)
                    self.spool.delete([i for i, _ in batch])
                    continue
                log.warning("Send failed, %d batches kept in spool: %s", self.spool.count(), exc)
                return sent
            self.spool.delete([i for i, _ in batch])
            sent += len(batch)
            if sent >= max_batches:
                return sent

    def run_once(self) -> dict:
        self.refresh_config()
        samples = self.collect()
        self.spool.add(samples)
        sent = self.flush()
        down = sum(1 for s in samples if not s["up"])
        result = {"hosts": len(samples), "down": down, "sent_batches": sent, "spooled": self.spool.count()}
        log.info("Round: %(hosts)d hosts, %(down)d unreachable, sent %(sent_batches)d batches, "
                 "%(spooled)d waiting in spool", result)
        return result

    def run_forever(self, stop: threading.Event) -> None:
        log.info("Collector %s: %d hosts, central %s", self.settings.name,
                 len(self.settings.hosts), self.settings.central_url)
        self.refresh_config(force=True)
        while not stop.is_set():
            started = time.monotonic()
            try:
                self.run_once()
            except Exception:
                log.exception("Collection round failed; retrying next interval")
            stop.wait(max(0.0, self.interval - (time.monotonic() - started)))
        log.info("Collector stopped (%d batches in spool will be sent on next start)", self.spool.count())
