import subprocess
from unittest import mock

import pytest

from inspector.sshclient import OpenSSHRunner, SSHError


def test_openssh_trust_on_first_use_by_default():
    args = OpenSSHRunner("10.1.1.11", 2222, "ops", key_file="/k/id", known_hosts="/var/lib/x/known_hosts").build_args(
        "uptime"
    )
    assert args[:3] == ["ssh", "-p", "2222"]
    assert "BatchMode=yes" in args and "StrictHostKeyChecking=accept-new" in args
    assert "UserKnownHostsFile=/var/lib/x/known_hosts" in args
    assert "UserKnownHostsFile=/dev/null" not in args  # keys are remembered, so a changed key is detected
    assert args[-2:] == ["ops@10.1.1.11", "uptime"]
    assert args[args.index("-i") + 1] == "/k/id"


def test_openssh_strict_host_keys():
    args = OpenSSHRunner("h", known_hosts="/etc/kh", strict_host_keys=True).build_args("x")
    assert "StrictHostKeyChecking=yes" in args and "UserKnownHostsFile=/etc/kh" in args


def test_paramiko_trust_on_first_use_records_and_reuses_key(tmp_path):
    paramiko = pytest.importorskip("paramiko")
    from inspector.sshclient import trust_on_first_use_policy

    path = tmp_path / "known_hosts"
    key = paramiko.RSAKey.generate(2048)
    client = paramiko.SSHClient()
    trust_on_first_use_policy(str(path)).missing_host_key(client, "[10.1.1.11]:2201", key)
    saved = paramiko.HostKeys(str(path))
    assert saved.lookup("[10.1.1.11]:2201")[key.get_name()] == key
    assert client.get_host_keys().lookup("[10.1.1.11]:2201") is not None


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
