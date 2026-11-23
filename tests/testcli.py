"""Command line entry points, as an operator or Ansible would run them."""

import json

import pytest

from inspector import auth
from inspector.db import connect
from inspector.main import main


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "central.db"
    main(["init", "--db", str(path)])
    return path


def test_init_loads_inventory_once(db):
    assert connect(db).execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 360
    main(["init", "--db", str(db)])  # idempotent
    assert connect(db).execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 360


def test_create_user_from_environment(db, monkeypatch):
    monkeypatch.setenv("INSPECTOR_NEW_PASSWORD", "a-long-password-123")
    main(["create-user", "alice", "--role", "admin", "--db", str(db)])
    assert auth.authenticate(connect(db), "alice", "a-long-password-123")["role"] == "admin"


@pytest.mark.parametrize(
    "argv, message",
    [
        (["create-user"], "Usage"),
        (["add-collector"], "Usage"),
        (["backup"], "Usage"),
        (["import-devices"], "Usage"),
        (["agent"], "--config"),
    ],
)
def test_usage_errors(db, argv, message, capsys):
    with pytest.raises(SystemExit) as exit_:
        main([*argv, "--db", str(db)])
    assert message in str(exit_.value.code)


def test_weak_password_rejected(db, monkeypatch):
    monkeypatch.setenv("INSPECTOR_NEW_PASSWORD", "short")
    with pytest.raises(SystemExit, match="at least"):
        main(["create-user", "bob", "--db", str(db)])


def test_add_collector_prints_token_once(db, capsys):
    main(["add-collector", "sh-east", "--db", str(db)])
    token = capsys.readouterr().out.strip().splitlines()[-1]
    assert auth.collector_for_token(connect(db), token) == "sh-east"
    main(["gen-token"])
    given = capsys.readouterr().out.strip()
    main(["add-collector", "sh-west", "--token", given, "--db", str(db)])
    assert given not in capsys.readouterr().out  # a given token is never echoed
    assert auth.collector_for_token(connect(db), given) == "sh-west"


def test_add_collector_rejects_made_up_token(db):
    with pytest.raises(SystemExit, match="gen-token"):
        main(["add-collector", "sh-west", "--token", "w" * 30, "--db", str(db)])


def test_check_config(db, capsys):
    main(["check-config", "--db", str(db)])
    assert capsys.readouterr().out.startswith("OK:")


def test_report_command(db, tmp_path, monkeypatch):
    monkeypatch.setattr("inspector.main.REPORT_DIR", tmp_path / "reports")
    main(["report", "--hours", "1", "--db", str(db)])
    assert list((tmp_path / "reports").glob("*.html"))


def test_agent_needs_token(tmp_path, monkeypatch):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("name: c\ncentral_url: http://central\nhosts: []\n")
    monkeypatch.delenv("INSPECTOR_COLLECTOR_TOKEN", raising=False)
    with pytest.raises(SystemExit, match="token"):
        main(["agent", "--config", str(cfg)])


def test_collect_once_prints_json(tmp_path, capsys):
    cfg = tmp_path / "c.yaml"
    cfg.write_text("name: c\ncentral_url: http://central\nhosts: []\n")
    main(["collect-once", "--config", str(cfg)])
    assert json.loads(capsys.readouterr().out) == []


def test_config_error_is_reported_cleanly(tmp_path):
    with pytest.raises(SystemExit, match="Configuration error"):
        main(["collect-once", "--config", str(tmp_path / "missing.yaml")])
