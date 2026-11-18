"""Collect one round of metrics from many hosts in parallel."""
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Protocol

from inspector.config import HostConfig
from inspector.db import to_text, utcnow
from inspector.parsers import DEFAULT_SERVICE_CHECK, CheckDef, ParseError, build_command, parse_output


class Runner(Protocol):
    def run(self, command: str) -> str: ...


RunnerFactory = Callable[[HostConfig], Runner]


def collect_host(host: HostConfig, runner_factory: RunnerFactory, checks: list[CheckDef] = (),
                 service_check: str = DEFAULT_SERVICE_CHECK) -> dict:
    sample = {"host": host.name, "datacenter": host.datacenter,
              "collected_at": to_text(utcnow()), "up": 0, "error": None,
              "duration_s": None, "values": {}}
    started = time.monotonic()
    try:
        command = build_command(host.mounts, host.services, checks, service_check)
        output = runner_factory(host).run(command)
    except Exception as exc:
        sample["error"] = str(exc)[:500]
        return sample
    finally:
        sample["duration_s"] = round(time.monotonic() - started, 2)

    sample["up"] = 1
    try:
        sample["values"] = parse_output(output, host.mounts, host.services, checks)
    except ParseError as exc:
        sample["error"] = f"Could not parse output: {exc}"
    return sample


def collect_all(hosts: list[HostConfig], runner_factory: RunnerFactory, checks: list[CheckDef] = (),
                service_check: str = DEFAULT_SERVICE_CHECK, max_workers: int = 20) -> list[dict]:
    """One slow or dead host never delays the others (bounded by the SSH timeout)."""
    if not hosts:
        return []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(hosts))) as pool:
        return list(pool.map(lambda h: collect_host(h, runner_factory, checks, service_check), hosts))
