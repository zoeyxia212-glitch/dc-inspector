"""Run a command on a remote host over SSH.

Two interchangeable backends (choose with collector.ssh_client in config.yaml):
- SSHRunner        paramiko, pure Python, supports password or key
- OpenSSHRunner    the system `ssh` command, key-based only; reuses the machine's
                   ~/.ssh/config, agent and known_hosts, no extra Python dependency
"""

import logging
import subprocess

log = logging.getLogger(__name__)
# Unix socket paths are limited (108 bytes on Linux, 104 on macOS). ssh names the control
# socket <dir>/<40-char %C hash> and adds a 17-char temporary suffix while creating it.
SOCKET_PATH_LIMIT = 104
CONTROL_NAME_LEN = 1 + 40 + 17
_warned_dirs: set[str] = set()


def control_dir_usable(control_dir: str | None) -> bool:
    """A too-long ControlPath makes ssh fail outright, so reuse is skipped rather than break inspection."""
    if not control_dir:
        return False
    if len(control_dir.encode()) + CONTROL_NAME_LEN <= SOCKET_PATH_LIMIT:
        return True
    if control_dir not in _warned_dirs:
        _warned_dirs.add(control_dir)
        log.warning(
            "SSH connection reuse disabled: control_dir %r is too long for a Unix socket path "
            "(max %d characters); use a short path such as /run/inspector/ssh",
            control_dir,
            SOCKET_PATH_LIMIT - CONTROL_NAME_LEN,
        )
    return False


class SSHError(RuntimeError):
    pass


class OpenSSHRunner:
    def __init__(
        self,
        address: str,
        port: int = 22,
        username: str = "inspector",
        key_file: str | None = None,
        timeout: int = 10,
        known_hosts: str | None = None,
        control_dir: str | None = None,
        control_persist: int = 120,
    ):
        self.address = address
        self.port = port
        self.username = username
        self.key_file = key_file
        self.timeout = timeout
        self.known_hosts = known_hosts
        self.control_dir = control_dir  # reuse one SSH connection per host across rounds
        self.control_persist = control_persist

    def build_args(self, command: str) -> list[str]:
        args = [
            "ssh",
            "-p",
            str(self.port),
            "-o",
            "BatchMode=yes",  # never prompt for a password
            "-o",
            f"ConnectTimeout={self.timeout}",
            "-o",
            "LogLevel=ERROR",
        ]
        if self.known_hosts:
            args += ["-o", f"UserKnownHostsFile={self.known_hosts}", "-o", "StrictHostKeyChecking=yes"]
        else:
            # Lab mode: accept unknown host keys. Production should pass known_hosts.
            args += ["-o", "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=no"]
        if self.key_file:
            args += ["-i", self.key_file, "-o", "IdentitiesOnly=yes"]
        if control_dir_usable(self.control_dir):
            # ControlMaster: the first round opens a master connection, later rounds reuse it
            # (no TCP + key exchange + auth every 30 s). %C = hash of host/port/user.
            args += [
                "-o",
                "ControlMaster=auto",
                "-o",
                f"ControlPath={self.control_dir}/%C",
                "-o",
                f"ControlPersist={self.control_persist}",
            ]
        return [*args, f"{self.username}@{self.address}", command]

    def run(self, command: str) -> str:
        try:
            result = subprocess.run(self.build_args(command), capture_output=True, text=True, timeout=self.timeout + 10)
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise SSHError(f"{type(exc).__name__}: {exc}") from exc
        # 255 = ssh itself failed. Other codes come from the remote command (e.g. a stopped service).
        if result.returncode == 255:
            raise SSHError(result.stderr.strip() or "ssh failed")
        return result.stdout


class SSHRunner:
    def __init__(
        self,
        address: str,
        port: int = 22,
        username: str = "inspector",
        password: str | None = None,
        key_file: str | None = None,
        timeout: int = 10,
        known_hosts: str | None = None,
    ):
        self.address = address
        self.port = port
        self.username = username
        self.password = password
        self.key_file = key_file
        self.timeout = timeout
        self.known_hosts = known_hosts

    def run(self, command: str) -> str:
        import paramiko  # imported here so tests and the web app don't need it

        client = paramiko.SSHClient()
        if self.known_hosts:
            client.load_host_keys(self.known_hosts)
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            # Lab mode: accept unknown host keys. Production should pass known_hosts.
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # noqa: S507 - lab mode, documented
        try:
            client.connect(
                self.address,
                port=self.port,
                username=self.username,
                password=self.password,
                key_filename=self.key_file,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            _, stdout, _ = client.exec_command(command, timeout=self.timeout + 5)
            return stdout.read().decode("utf-8", errors="replace")
        except Exception as exc:  # paramiko raises many types; callers only need the message
            raise SSHError(f"{type(exc).__name__}: {exc}") from exc
        finally:
            client.close()
