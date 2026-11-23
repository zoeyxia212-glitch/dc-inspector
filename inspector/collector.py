"""Collect one round of metrics from many hosts in parallel."""

import shutil
import subprocess
import time
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from typing import Protocol

from inspector.config import HostConfig
from inspector.db import to_text, utcnow
from inspector.parsers import DEFAULT_SERVICE_CHECK, CheckDef, ParseError, build_command, parse_output


class Runner(Protocol):
    def run(self, command: str) -> str: ...


RunnerFactory = Callable[[HostConfig], Runner]
Pinger = Callable[[str], int]

# Why SSH failed decides who should act: network/hardware team, the host's admin, or security.
ERROR_CLASSES = [
    ("auth_failed", ("permission denied", "authentication failed", "auth fail")),
    ("host_key", ("host key verification failed", "remote host identification has changed")),
    ("refused", ("connection refused",)),
    (
        "dns",
        (
            "could not resolve",
            "name or service not known",
            "nodename nor servname",
            "temporary failure in name resolution",
        ),
    ),
    ("unreachable", ("no route to host", "network is unreachable", "host is unreachable")),
    ("timeout", ("timed out", "timeout")),
]


def classify_error(message: str) -> str:
    text = message.lower()
    for name, needles in ERROR_CLASSES:
        if any(n in text for n in needles):
            return name
    return "other"


def ping(address: str, timeout: int = 1) -> int:
    """1 = replies, 0 = no reply, -1 = could not ping (no binary, no permission, ICMP blocked locally)."""
    if not shutil.which("ping"):
        return -1
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), address], capture_output=True, timeout=timeout + 2
        )
    except (subprocess.TimeoutExpired, OSError):
        return -1
    return {0: 1, 1: 0}.get(result.returncode, -1)  # iputils: 0 reply, 1 no reply, 2 error


def collect_host(
    host: HostConfig,
    runner_factory: RunnerFactory,
    checks: Sequence[CheckDef] = (),
    service_check: str = DEFAULT_SERVICE_CHECK,
    pinger: Pinger = ping,
) -> dict:
    sample = {
        "host": host.name,
        "datacenter": host.datacenter,
        "collected_at": to_text(utcnow()),
        "up": 0,
        "error": None,
        "duration_s": None,
        "values": {},
    }
    started = time.monotonic()
    try:
        command = build_command(host.mounts, host.services, checks, service_check)
        output = runner_factory(host).run(command)
    except Exception as exc:
        error = str(exc)[:500]
        sample["error"] = error
        sample["duration_s"] = round(time.monotonic() - started, 2)
        # Second opinion: does the machine answer at all? Separates "host/network down"
        # from "host alive but SSH broken" (sshd crashed, key removed, host reinstalled).
        sample["values"] = {"ssh.error": classify_error(error), "ping.up": float(pinger(host.address))}
        return sample
    sample["duration_s"] = round(time.monotonic() - started, 2)

    sample["up"] = 1
    try:
        sample["values"] = parse_output(output, host.mounts, host.services, checks)
    except ParseError as exc:
        sample["error"] = f"Could not parse output: {exc}"
    return sample


def collect_all(
    hosts: list[HostConfig],
    runner_factory: RunnerFactory,
    checks: Sequence[CheckDef] = (),
    service_check: str = DEFAULT_SERVICE_CHECK,
    max_workers: int = 20,
    pinger: Pinger = ping,
) -> list[dict]:
    """One slow or dead host never delays the others (bounded by the SSH timeout)."""
    if not hosts:
        return []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(hosts))) as pool:
        return list(pool.map(lambda h: collect_host(h, runner_factory, checks, service_check, pinger), hosts))
