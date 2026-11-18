"""Collector agent: config pull, store-and-forward, behaviour during central outages."""
import pytest

from inspector import agent
from inspector.agent import Agent, CentralError, Spool
from inspector.config import CollectorSettings, HostConfig

from testparsers import SAMPLE_OUTPUT


class FakeCentral:
    def __init__(self):
        self.up = True
        self.received = []
        self.config = {"interval_seconds": 15, "service_check": "pgrep -x {name} >/dev/null && echo active || echo inactive",
                       "checks": [{"name": "zombies", "command": "echo 3", "type": "number", "pattern": None, "timeout": 5}]}
        self.reject = False

    def get_config(self):
        if not self.up:
            raise CentralError("central unreachable")
        return self.config

    def send(self, payload):
        if self.reject:
            raise CentralError('HTTP 400: {"error": "bad host name"}')
        if not self.up:
            raise CentralError("central unreachable: timed out")
        self.received.append(payload)
        return {"accepted": len(payload["samples"])}


class Runner:
    commands = []

    def __init__(self, host):
        self.host = host

    def run(self, command):
        Runner.commands.append(command)
        if self.host.name == "dead":
            raise OSError("No route to host")
        return SAMPLE_OUTPUT


@pytest.fixture()
def make_agent(tmp_path):
    def _make(central, hosts=("h1", "h2")):
        settings = CollectorSettings(name="sh-north", central_url="http://central", spool_path=str(tmp_path / "spool.db"),
                                     hosts=[HostConfig(name=h, address=h, datacenter="SH01",
                                                       mounts=["/", "/data"], services=["nginx"]) for h in hosts])
        return Agent(settings, client=central, runner_factory=Runner)
    return _make


def test_normal_round(make_agent):
    central = FakeCentral()
    a = make_agent(central, hosts=("h1", "dead"))
    result = a.run_once()
    assert result == {"hosts": 2, "down": 1, "sent_batches": 1, "spooled": 0}
    payload = central.received[0]
    assert payload["collector"] == "sh-north" and payload["host_count"] == 2
    by_host = {s["host"]: s for s in payload["samples"]}
    assert by_host["h1"]["up"] == 1 and by_host["h1"]["values"]["check.zombies"] == 3.0
    assert by_host["dead"]["up"] == 0 and "No route" in by_host["dead"]["error"]


def test_uses_interval_and_checks_from_central(make_agent):
    central = FakeCentral()
    a = make_agent(central)
    a.refresh_config(force=True)
    assert a.interval == 15
    a.collect()
    assert "##CHK zombies" in Runner.commands[-1]


def test_outage_spools_then_delivers_in_order(make_agent):
    central = FakeCentral()
    a = make_agent(central)
    central.up = False
    for _ in range(3):
        assert a.run_once()["sent_batches"] == 0
    assert a.spool.count() == 3 and central.received == []
    central.up = True
    result = a.run_once()
    assert result["sent_batches"] == 4 and result["spooled"] == 0
    times = [s["collected_at"] for p in central.received for s in p["samples"]]
    assert times == sorted(times)                                   # oldest first


def test_spool_survives_restart(make_agent):
    central = FakeCentral()
    central.up = False
    make_agent(central).run_once()
    central.up = True
    restarted = make_agent(central)                                 # same spool file
    assert restarted.spool.count() == 1
    assert restarted.flush() == 1 and restarted.spool.count() == 0


def test_cached_config_used_when_central_down_at_start(make_agent):
    central = FakeCentral()
    make_agent(central).refresh_config(force=True)
    central.up = False
    restarted = make_agent(central)
    restarted.refresh_config(force=True)
    assert restarted.interval == 15


def test_rejected_data_is_dropped_not_retried_forever(make_agent):
    central = FakeCentral()
    central.reject = True
    a = make_agent(central)
    a.run_once()
    assert a.spool.count() == 0


def test_spool_cap_drops_oldest(tmp_path):
    spool = Spool(str(tmp_path / "s.db"), max_batches=3)
    for i in range(5):
        spool.add([{"n": i}])
    assert [b[0]["n"] for _, b in spool.oldest(10)] == [2, 3, 4]


def test_factory_picks_ssh_backend():
    from inspector.sshclient import OpenSSHRunner, SSHRunner
    host = HostConfig(name="a", address="a", datacenter="SH01")
    base = dict(name="c", central_url="http://x", hosts=[host])
    assert isinstance(agent.ssh_runner_factory(CollectorSettings(**base))(host), OpenSSHRunner)
    assert isinstance(agent.ssh_runner_factory(CollectorSettings(**base, ssh_client="paramiko"))(host), SSHRunner)
