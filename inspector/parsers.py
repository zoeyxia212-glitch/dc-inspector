"""Build the remote inspection command and parse its output into flat metrics.

One SSH session per host per round runs a single command whose output is split
by '##' markers. Built-in sections use only /proc and POSIX tools, so they work
on any Linux, including minimal images without systemd:

    ##STAT1 / ##STAT2   /proc/stat 1 s apart     -> cpu.percent
    ##NPROC / ##LOAD    nproc, /proc/loadavg      -> load.1 load.5 load.15 load.per_core
    ##MEM               /proc/meminfo             -> mem.percent, swap.percent
    ##DISK / ##INODE    df -P / df -Pi <mounts>   -> disk.<mount>.percent, disk.<mount>.inode_percent
    ##SVC <name>        process / systemd check   -> service.<name>.up
    ##CHK <name>        custom check from central -> check.<name>
"""

import re
import shlex
from collections.abc import Sequence
from dataclasses import dataclass

DEFAULT_SERVICE_CHECK = "pgrep -x {name} >/dev/null && echo active || echo inactive"
SYSTEMD_SERVICE_CHECK = "systemctl is-active {name}"
SAFE_NAME = re.compile(r"^[A-Za-z0-9_.@-]+$")
SAFE_MOUNT = re.compile(r"^/[A-Za-z0-9_./-]*$")
NUMBER = re.compile(r"-?\d+(?:\.\d+)?")


class ParseError(ValueError):
    pass


@dataclass(frozen=True)
class CheckDef:
    """A custom check defined centrally (config/server.yaml), pushed to collectors.

    Commands are written by admins in the server config, never through the UI or API.
    """

    name: str
    command: str
    type: str = "number"  # number | text
    pattern: str | None = None  # regex; group 1 (or whole match) is the value
    timeout: int = 5

    def __post_init__(self):
        if not SAFE_NAME.match(self.name):
            raise ValueError(f"Invalid check name {self.name!r}")
        if self.type not in ("number", "text"):
            raise ValueError(f"Check {self.name}: type must be number or text")
        if self.pattern:
            re.compile(self.pattern)
        if not 1 <= int(self.timeout) <= 30:
            raise ValueError(f"Check {self.name}: timeout must be 1-30 s")

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "command": self.command,
            "type": self.type,
            "pattern": self.pattern,
            "timeout": self.timeout,
        }


def build_command(
    mounts: list[str], services: list[str], checks: Sequence[CheckDef] = (), service_check: str = DEFAULT_SERVICE_CHECK
) -> str:
    for mount in mounts:
        if not SAFE_MOUNT.match(mount):
            raise ValueError(f"Unsafe mount path: {mount!r}")
    for service in services:
        if not SAFE_NAME.match(service):
            raise ValueError(f"Unsafe service name: {service!r}")

    quoted_mounts = " ".join(shlex.quote(m) for m in mounts)
    parts = [
        "export LC_ALL=C",
        "echo '##STAT1'",
        "head -n1 /proc/stat",
        "sleep 1",
        "echo '##STAT2'",
        "head -n1 /proc/stat",
        "echo '##NPROC'",
        "nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo",
        "echo '##LOAD'",
        "cat /proc/loadavg",
        "echo '##MEM'",
        "cat /proc/meminfo",
        "echo '##DISK'",
        f"df -P {quoted_mounts} 2>/dev/null",
        "echo '##INODE'",
        f"df -Pi {quoted_mounts} 2>/dev/null",
    ]
    for service in services:
        parts += [f"echo '##SVC {service}'", service_check.format(name=shlex.quote(service))]
    for check in checks:
        parts += [
            f"echo '##CHK {check.name}'",
            f"timeout {int(check.timeout)} sh -c {shlex.quote(check.command)} 2>/dev/null",
        ]
    return "; ".join(parts)


def split_sections(output: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current = None
    for line in output.splitlines():
        if line.startswith("##"):
            current = line[2:].strip()
            sections[current] = []
        elif current is not None and line.strip():
            sections[current].append(line.strip())
    return sections


def parse_cpu(stat1: str, stat2: str) -> float:
    def totals(line):
        fields = line.split()
        if not fields or fields[0] != "cpu":
            raise ParseError(f"Not a /proc/stat cpu line: {line!r}")
        values = [int(v) for v in fields[1:9]]  # user nice system idle iowait irq softirq steal
        values += [0] * (8 - len(values))
        return values[3] + values[4], sum(values)

    idle1, total1 = totals(stat1)
    idle2, total2 = totals(stat2)
    if total2 - total1 <= 0:
        return 0.0
    return round(100.0 * (1 - (idle2 - idle1) / (total2 - total1)), 1)


def parse_meminfo(lines: list[str]) -> dict[str, float]:
    info = {}
    for line in lines:
        key, _, rest = line.partition(":")
        if rest.strip():
            info[key] = int(rest.split()[0])
    if not info.get("MemTotal"):
        raise ParseError("MemTotal missing from /proc/meminfo")
    available = info.get("MemAvailable", info.get("MemFree", 0) + info.get("Buffers", 0) + info.get("Cached", 0))
    result = {"mem.percent": round(100.0 * (1 - available / info["MemTotal"]), 1)}
    if info.get("SwapTotal"):
        result["swap.percent"] = round(100.0 * (1 - info.get("SwapFree", 0) / info["SwapTotal"]), 1)
    return result


def parse_df(lines: list[str], mounts: list[str]) -> dict[str, float]:
    """{mount: used %} from `df -P` or `df -Pi` output (both put Use% in column 5)."""
    usage = {}
    for line in lines:
        fields = line.split()
        if len(fields) < 6 or not fields[4].endswith("%"):
            continue  # header, or '-' for filesystems without inodes
        if fields[5] in mounts:
            usage[fields[5]] = float(fields[4].rstrip("%"))
    return usage


def parse_check(lines: list[str], check: CheckDef):
    text = "\n".join(lines).strip()
    if check.pattern:
        m = re.search(check.pattern, text, re.MULTILINE)
        if not m:
            return None
        text = (m.group(1) if m.groups() else m.group(0)).strip()
    if check.type == "text":
        return text or None
    m = NUMBER.search(text)
    return float(m.group(0)) if m else None


def parse_output(output: str, mounts: list[str], services: list[str], checks: Sequence[CheckDef] = ()) -> dict:
    """Flat {metric key: number or text}."""
    s = split_sections(output)
    try:
        values = {"cpu.percent": parse_cpu(s["STAT1"][0], s["STAT2"][0])}
        values.update(parse_meminfo(s["MEM"]))
    except (KeyError, IndexError) as exc:
        raise ParseError(f"Missing section in output: {exc}") from exc

    load = s.get("LOAD", [""])[0].split() if s.get("LOAD") else []
    nproc = int(s["NPROC"][0]) if s.get("NPROC") and s["NPROC"][0].isdigit() else None
    if len(load) >= 3:
        values["load.1"], values["load.5"], values["load.15"] = (float(x) for x in load[:3])
        if nproc:
            values["cpu.cores"] = float(nproc)
            values["load.per_core"] = round(values["load.1"] / nproc, 2)

    for mount, pct in parse_df(s.get("DISK", []), mounts).items():
        values[f"disk.{mount}.percent"] = pct
    for mount, pct in parse_df(s.get("INODE", []), mounts).items():
        values[f"disk.{mount}.inode_percent"] = pct
    for service in services:
        lines = s.get(f"SVC {service}", [])
        values[f"service.{service}.up"] = 1.0 if lines and lines[0] == "active" else 0.0
    for check in checks:
        value = parse_check(s.get(f"CHK {check.name}", []), check)
        if value is not None:
            values[f"check.{check.name}"] = value
    return values
