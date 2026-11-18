import pytest

from inspector import parsers
from inspector.parsers import CheckDef

CHECKS = [CheckDef("zombies", "x", "number"), CheckDef("uptime_s", "x", "number", pattern=r"^([\d.]+)"),
          CheckDef("kernel", "x", "text")]

SAMPLE_OUTPUT = """##STAT1
cpu  1000 0 500 8000 100 0 0 0 0 0
##STAT2
cpu  1180 0 560 8040 120 0 0 0 0 0
##NPROC
4
##LOAD
3.20 2.10 1.05 2/345 6789
##MEM
MemTotal:        8000000 kB
MemFree:         1000000 kB
MemAvailable:    2000000 kB
SwapTotal:       1000000 kB
SwapFree:         750000 kB
##DISK
Filesystem     1024-blocks    Used Available Capacity Mounted on
overlay           61255492 30627746  27497656      53% /
tmpfs                65536    58000      7536      89% /data
##INODE
Filesystem      Inodes   IUsed   IFree IUse% Mounted on
overlay        3907584  120000 3787584    4% /
tmpfs           500000  480000   20000   96% /data
##SVC nginx
active
##SVC crond
inactive
##CHK zombies
3
##CHK uptime_s
12345.67 23456.00
##CHK kernel
6.8.0-138-generic
"""
MOUNTS = ["/", "/data"]
SERVICES = ["nginx", "crond"]


def test_parse_full_output():
    v = parsers.parse_output(SAMPLE_OUTPUT, MOUNTS, SERVICES, CHECKS)
    assert v["cpu.percent"] == 80.0                 # (180+60) / (180+60+40+20)
    assert v["mem.percent"] == 75.0 and v["swap.percent"] == 25.0
    assert v["load.1"] == 3.2 and v["cpu.cores"] == 4 and v["load.per_core"] == 0.8
    assert v["disk./.percent"] == 53.0 and v["disk./data.percent"] == 89.0
    assert v["disk./data.inode_percent"] == 96.0
    assert v["service.nginx.up"] == 1.0 and v["service.crond.up"] == 0.0
    assert v["check.zombies"] == 3.0
    assert v["check.uptime_s"] == 12345.67          # pattern picks the first number
    assert v["check.kernel"] == "6.8.0-138-generic"


def test_check_with_no_output_is_absent():
    output = SAMPLE_OUTPUT.replace("##CHK zombies\n3\n", "##CHK zombies\n")
    assert "check.zombies" not in parsers.parse_output(output, MOUNTS, SERVICES, CHECKS)


def test_missing_service_section_means_down():
    output = SAMPLE_OUTPUT.split("##SVC nginx")[0]
    v = parsers.parse_output(output, MOUNTS, SERVICES)
    assert v["service.nginx.up"] == 0.0


def test_filesystem_without_inodes_is_skipped():
    lines = ["Filesystem Inodes IUsed IFree IUse% Mounted on", "vfat - - - - /"]
    assert parsers.parse_df(lines, ["/"]) == {}


def test_garbage_output_raises():
    with pytest.raises(parsers.ParseError):
        parsers.parse_output("Permission denied\n", MOUNTS, SERVICES)


def test_cpu_counter_reset():
    assert parsers.parse_cpu("cpu 5 5 5 5", "cpu 1 1 1 1") == 0.0


def test_build_command_sections_and_check_timeout():
    cmd = parsers.build_command(MOUNTS, SERVICES, [CheckDef("zombies", "ps | wc -l", timeout=3)])
    for marker in ("##STAT1", "##NPROC", "##LOAD", "##MEM", "##DISK", "##INODE", "##SVC nginx", "##CHK zombies"):
        assert marker in cmd
    assert "timeout 3 sh -c 'ps | wc -l'" in cmd
    assert cmd.startswith("export LC_ALL=C")       # stable number formats on any locale


@pytest.mark.parametrize("services, mounts", [
    (["nginx; rm -rf /"], ["/"]), (["nginx"], ["/; reboot"]), (["nginx"], ["relative"]),
    (["$(id)"], ["/"]), (["nginx"], ["/tmp/`id`"]),
])
def test_unsafe_names_rejected(services, mounts):
    with pytest.raises(ValueError):
        parsers.build_command(mounts, services)


@pytest.mark.parametrize("kwargs", [
    {"name": "bad name", "command": "x"}, {"name": "x", "command": "x", "type": "bool"},
    {"name": "x", "command": "x", "pattern": "("}, {"name": "x", "command": "x", "timeout": 120},
])
def test_invalid_check_definitions(kwargs):
    with pytest.raises((ValueError, Exception)):
        CheckDef(**kwargs)
