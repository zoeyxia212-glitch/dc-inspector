from pathlib import Path

import pytest

from inspector.config import ConfigError, load_collector_config, load_server_config
from inspector.db import connect
from inspector.seed import seed

CONFIG = Path(__file__).resolve().parent.parent / "config"


def test_server_config():
    s = load_server_config(CONFIG / "server.yaml")
    assert len(s.rules) >= 10 and {c.name for c in s.checks} >= {"zombies", "uptime_s"}
    assert {c.type for c in s.channels} == {"email", "wecom", "dingtalk", "slack"}
    assert s.collector_config()["interval_seconds"] == 30


def test_collector_configs_cover_all_ten_hosts():
    north = load_collector_config(CONFIG / "collectors" / "sh-north.yaml")
    south = load_collector_config(CONFIG / "collectors" / "sh-south.yaml")
    names = [h.name for h in north.hosts + south.hosts]
    assert len(names) == len(set(names)) == 10
    assert north.ssh_client == "openssh" and north.hosts[0].key_file == "/keys/id_ed25519"


def test_collector_hosts_exist_in_inventory():
    conn = connect(":memory:")
    seed(conn)
    for site in ("sh-north", "sh-south"):
        for h in load_collector_config(CONFIG / "collectors" / f"{site}.yaml").hosts:
            row = conn.execute("SELECT status FROM devices WHERE hostname = ?", (h.name,)).fetchone()
            assert row and row["status"] == "online", h.name


def test_secret_from_environment(monkeypatch):
    monkeypatch.setenv("WECOM_WEBHOOK_URL", "https://qyapi.weixin.qq.com/x")
    s = load_server_config(CONFIG / "server.yaml")
    wecom = next(c for c in s.channels if c.type == "wecom")
    assert wecom.secret("webhook_url") == "https://qyapi.weixin.qq.com/x"


def test_errors(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_collector_config(tmp_path / "missing.yaml")
    bad = tmp_path / "c.yaml"
    bad.write_text(
        "name: x\ncentral_url: http://c\nhosts:\n  - {name: a, address: a, datacenter: SH01}\n"
        "  - {name: a, address: b, datacenter: SH01}\n"
    )
    with pytest.raises(ConfigError, match="Duplicate"):
        load_collector_config(bad)
    (tmp_path / "server.yaml").write_text("notifications:\n  channels:\n    - {name: x, type: pager}\n")
    (tmp_path / "rules.yaml").write_text("rules: []\n")
    with pytest.raises(ConfigError, match="type must be"):
        load_server_config(tmp_path / "server.yaml")


def test_host_key_policy_defaults(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text("name: c\ncentral_url: http://x\nspool_path: /var/lib/inspector/spool.db\nhosts: []\n")
    c = load_collector_config(p)
    assert c.host_key_policy == "tofu" and c.known_hosts == "/var/lib/inspector/known_hosts"
    p.write_text("name: c\ncentral_url: http://x\nssh: {known_hosts: /etc/kh}\nhosts: []\n")
    assert load_collector_config(p).host_key_policy == "strict"  # explicit file keeps its old meaning
    p.write_text("name: c\ncentral_url: http://x\nssh: {host_key_policy: yolo}\nhosts: []\n")
    with pytest.raises(ConfigError, match="host_key_policy"):
        load_collector_config(p)
