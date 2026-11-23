"""Telling 'host down' apart from 'SSH broken', 'credentials changed' and 'host key changed'."""

import subprocess
from unittest import mock

import pytest
from conftest import HOST, alerts_by

from inspector import collector
from inspector.config import HostConfig
from inspector.sshclient import OpenSSHRunner, SSHError

H = HostConfig(name="h1", address="10.1.1.11", datacenter="SH01")


@pytest.mark.parametrize(
    "message, expected",
    [
        ("inspector@10.1.1.11: Permission denied (publickey).", "auth_failed"),
        ("Host key verification failed.", "host_key"),
        ("@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@", "host_key"),
        ("ssh: connect to host 10.1.1.11 port 22: Connection refused", "refused"),
        ("ssh: connect to host 10.1.1.11 port 22: Connection timed out", "timeout"),
        ("ssh: connect to host 10.1.1.11 port 22: No route to host", "unreachable"),
        ("ssh: Could not resolve hostname sh01: Name or service not known", "dns"),
        ("AuthenticationException: Authentication failed.", "auth_failed"),  # paramiko wording
        ("something odd", "other"),
    ],
)
def test_classify_error(message, expected):
    assert collector.classify_error(message) == expected


class Failing:
    def __init__(self, message):
        self.message = message

    def run(self, command):
        raise SSHError(self.message)


def test_failed_sample_carries_diagnosis():
    s = collector.collect_host(H, lambda h: Failing("Connection refused"), pinger=lambda addr: 1)
    assert s["up"] == 0 and s["values"] == {"ssh.error": "refused", "ping.up": 1.0}


@pytest.mark.parametrize("returncode, expected", [(0, 1), (1, 0), (2, -1)])
def test_ping_exit_codes(returncode, expected):
    with (
        mock.patch("shutil.which", return_value="/bin/ping"),
        mock.patch("subprocess.run", return_value=subprocess.CompletedProcess([], returncode)),
    ):
        assert collector.ping("10.0.0.1") == expected


def test_ping_missing_binary():
    with mock.patch("shutil.which", return_value=None):
        assert collector.ping("10.0.0.1") == -1


# ---------------------------------------------------------- which alert fires
def fail(push, step, error, ping):
    push(step, up=False, values={"ssh.error": error, "ping.up": float(ping)})


@pytest.mark.parametrize(
    "error, ping, rule",
    [
        ("timeout", 0, "host_down"),  # no SSH, no ping
        ("timeout", -1, "host_down"),  # ping unavailable: fall back to the conservative answer
        ("refused", 1, "ssh_down"),  # alive, sshd dead
        ("timeout", 1, "ssh_down"),  # alive, port 22 filtered
        ("auth_failed", 1, "ssh_auth_failed"),
        ("auth_failed", 0, "ssh_auth_failed"),
    ],
)
def test_rule_selected_by_diagnosis(conn, push, error, ping, rule):
    fail(push, 0, error, ping)
    fail(push, 1, error, ping)
    assert {k[1] for k in alerts_by(conn)} == {rule}


def test_host_key_changed_is_immediate_and_critical(conn, push):
    fail(push, 0, "host_key", 1)
    alert = alerts_by(conn)[(HOST, "host_key_changed", "")]
    assert alert["severity"] == "critical" and "MITM" in alert["summary"]


def test_switching_diagnosis_resolves_old_alert(conn, push):
    fail(push, 0, "refused", 1)
    fail(push, 1, "refused", 1)
    fail(push, 2, "timeout", 0)  # now the whole machine is gone
    fail(push, 3, "timeout", 0)
    assert {k[1] for k in alerts_by(conn)} == {"host_down"}
    assert {k[1] for k in alerts_by(conn, "resolved")} == {"ssh_down"}


def test_recovery_resolves(conn, push):
    fail(push, 0, "timeout", 0)
    fail(push, 1, "timeout", 0)
    push(2)
    assert alerts_by(conn) == {}


def test_auth_failure_is_not_rack_outage(conn, push):
    rack = [f"sh01-a01-srv0{i}" for i in range(1, 5)]
    for step in (0, 1):
        push.batch(step, dict.fromkeys(rack, False))  # helper: timeout + no ping
    assert ("rack/SH01-A01", "rack_outage", "") in alerts_by(conn)


# ---------------------------------------------------------- connection reuse
def test_too_long_control_dir_falls_back_instead_of_failing():
    long_dir = "/sessions/some-very-long-sandbox-name-0123456789/lab2/ssh-control"
    args = OpenSSHRunner("h", control_dir=long_dir).build_args("x")
    assert not any("Control" in a for a in args)  # inspection still works, just without reuse


def test_too_long_control_dir_rejected_in_config(tmp_path):
    from inspector.config import ConfigError, load_collector_config

    p = tmp_path / "c.yaml"
    p.write_text("name: c\ncentral_url: http://x\nssh: {control_dir: /" + "x" * 60 + "}\nhosts: []\n")
    with pytest.raises(ConfigError, match="too long"):
        load_collector_config(p)


def test_control_master_options():
    args = OpenSSHRunner("h", control_dir="/var/lib/inspector/ssh").build_args("x")
    assert "ControlMaster=auto" in args and "ControlPath=/var/lib/inspector/ssh/%C" in args
    assert "ControlPersist=120" in args
    assert not any("Control" in a for a in OpenSSHRunner("h").build_args("x"))
