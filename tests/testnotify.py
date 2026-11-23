import base64
import hashlib
import hmac
import json
import urllib.parse
from datetime import timedelta
from unittest import mock

import pytest
from conftest import T0, outbox

from inspector import notify
from inspector.config import Channel


def ch(type_, **settings):
    return Channel(name=f"test-{type_}", type=type_, settings=settings)


class FakeResponse:
    def __init__(self, body=b'{"errcode": 0, "errmsg": "ok"}'):
        self.body = body

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass


def sent_request(fn, channel, body=b'{"errcode": 0}'):
    with mock.patch("urllib.request.urlopen", return_value=FakeResponse(body)) as urlopen:
        fn(
            channel,
            "[CRITICAL] h1 service_down [nginx]",
            "[CRITICAL] h1 service_down [nginx]\nService nginx is not running\nLocation: SH01-A01 U2",
        )
    req = urlopen.call_args[0][0]
    return req.full_url, json.loads(req.data)


def test_wecom_markdown_payload():
    _url, payload = sent_request(
        notify.send_wecom, ch("wecom", webhook_url="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=K")
    )
    assert payload["msgtype"] == "markdown"
    assert payload["markdown"]["content"].startswith("**[CRITICAL] h1 service_down [nginx]**")
    assert "> Location: SH01-A01 U2" in payload["markdown"]["content"]


def test_dingtalk_signed_url():
    with mock.patch("time.time", return_value=1700000000.0):
        url, payload = sent_request(
            notify.send_dingtalk,
            ch("dingtalk", webhook_url="https://oapi.dingtalk.com/robot/send?access_token=T", secret="SEC"),
        )
    query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert query["timestamp"] == ["1700000000000"]
    expected = base64.b64encode(hmac.new(b"SEC", b"1700000000000\nSEC", hashlib.sha256).digest()).decode()
    assert query["sign"] == [expected]
    assert payload["markdown"]["title"].startswith("[CRITICAL]")


def test_wecom_errcode_is_a_failure():
    with pytest.raises(RuntimeError, match="93000"):
        sent_request(
            notify.send_wecom,
            ch("wecom", webhook_url="https://x"),
            b'{"errcode": 93000, "errmsg": "invalid webhook url"}',
        )


def test_slack_payload():
    _, payload = sent_request(notify.send_slack, ch("slack", webhook_url="https://hooks.slack.com/x"), b"ok")
    assert payload["text"].startswith("[CRITICAL]")


def test_webhook_from_environment(monkeypatch):
    monkeypatch.setenv("MY_HOOK", "https://from-env")
    url, _ = sent_request(notify.send_slack, ch("slack", webhook_url_env="MY_HOOK"), b"ok")
    assert url == "https://from-env"


def test_email(monkeypatch):
    monkeypatch.setenv("SMTP_PW", "s3cret")
    channel = ch(
        "email",
        host="smtp.example.com",
        port=587,
        username="u",
        password_env="SMTP_PW",
        **{"from": "inspector@example.com", "to": ["ops@example.com", "noc@example.com"]},
    )
    with mock.patch("smtplib.SMTP") as smtp:
        notify.send_email(channel, "subj", "body")
    server = smtp.return_value.__enter__.return_value
    server.starttls.assert_called_once()
    server.login.assert_called_once_with("u", "s3cret")
    msg = server.send_message.call_args[0][0]
    assert msg["To"] == "ops@example.com, noc@example.com" and msg["Subject"] == "subj"


# ---------------------------------------------------------- outbox delivery
def queue_one(conn, channel_name="all"):
    conn.execute(
        """INSERT INTO outbox (channel, event, subject, body, status, next_attempt_at, created_at)
                    VALUES (?, 'opened', 's', 'b', 'pending', '2026-11-18T00:00:00Z', '2026-11-18T00:00:00Z')""",
        (channel_name,),
    )


def test_delivery_success(conn, settings):
    queue_one(conn)
    calls = []
    stats = notify.deliver_pending(conn, settings.channels, T0, {"slack": lambda c, s, b: calls.append(s)})
    assert stats == {"sent": 1, "retry": 0, "failed": 0} and calls == ["s"]
    assert outbox(conn)[0]["status"] == "sent"


def test_retry_with_backoff_then_give_up(conn, settings):
    queue_one(conn)

    def broken(c, s, b):
        raise OSError("connection refused")

    now = T0
    for attempt in range(1, notify.MAX_ATTEMPTS):
        assert notify.deliver_pending(conn, settings.channels, now, {"slack": broken})["retry"] == 1
        row = outbox(conn)[0]
        assert row["attempts"] == attempt
        delay = notify.BASE_BACKOFF_SECONDS * 2 ** (attempt - 1)
        # not retried before the backoff has passed
        assert notify.deliver_pending(
            conn, settings.channels, now + timedelta(seconds=delay - 1), {"slack": broken}
        ) == {"sent": 0, "retry": 0, "failed": 0}
        now += timedelta(seconds=delay)
    assert notify.deliver_pending(conn, settings.channels, now, {"slack": broken})["failed"] == 1
    row = outbox(conn)[0]
    assert row["status"] == "failed" and "connection refused" in row["last_error"]


def test_unknown_channel_fails_immediately(conn, settings):
    queue_one(conn, "deleted-channel")
    assert notify.deliver_pending(conn, settings.channels, T0)["failed"] == 1


def test_datacenter_filter():
    channel = Channel(name="dc", type="slack", datacenters=["SH01"])
    assert notify.channel_matches(channel, {"severity": "critical", "datacenter": "SH01"})
    assert not notify.channel_matches(channel, {"severity": "critical", "datacenter": "SH07"})


def test_resolved_message_has_duration():
    event = {
        "event": "resolved",
        "host": "h",
        "rule": "cpu_high",
        "target": "",
        "severity": "critical",
        "opened_at": "2026-11-18T00:00:00Z",
        "resolved_at": "2026-11-18T00:12:00Z",
    }
    subject, body = notify.format_event(event, "SH01-A01 U2")
    assert subject == "[RESOLVED] h cpu_high" and "Duration: 12 min" in body
