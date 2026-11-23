import subprocess
from unittest import mock

import pytest

from inspector.sshclient import OpenSSHRunner, SSHError


def test_openssh_args_lab_mode():
    args = OpenSSHRunner("10.1.1.11", 2222, "ops", key_file="/k/id").build_args("uptime")
    assert args[:3] == ["ssh", "-p", "2222"]
    assert "BatchMode=yes" in args and "StrictHostKeyChecking=no" in args
    assert args[-2:] == ["ops@10.1.1.11", "uptime"]
    assert args[args.index("-i") + 1] == "/k/id"


def test_openssh_args_strict_host_keys():
    args = OpenSSHRunner("h", known_hosts="/etc/kh").build_args("x")
    assert "StrictHostKeyChecking=yes" in args and "UserKnownHostsFile=/etc/kh" in args


def fake_run(returncode, stdout="", stderr=""):
    return mock.patch(
        "subprocess.run", return_value=subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)
    )


def test_openssh_remote_exit_code_is_not_an_error():
    # e.g. `systemctl is-active` returns 3 for a stopped service; output must still be used
    with fake_run(3, stdout="##SVC x\ninactive\n"):
        assert "inactive" in OpenSSHRunner("h").run("cmd")


def test_openssh_connection_failure():
    with (
        fake_run(255, stderr="ssh: connect to host h port 22: Connection refused"),
        pytest.raises(SSHError, match="Connection refused"),
    ):
        OpenSSHRunner("h").run("cmd")


def test_openssh_timeout():
    with (
        mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired("ssh", 20)),
        pytest.raises(SSHError, match="TimeoutExpired"),
    ):
        OpenSSHRunner("h").run("cmd")
