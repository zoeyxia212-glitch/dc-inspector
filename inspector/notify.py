"""Alert notifications: routing, outbox with retries, and channel senders.

Flow: alert events -> enqueue() writes one outbox row per matching channel
(inside the ingest transaction) -> scheduler calls deliver_pending() which
sends with exponential backoff. A broken SMTP server or webhook never blocks
ingest, and nothing is lost if the server restarts.

Channels: email (SMTP), wecom (企业微信 group robot), dingtalk (钉钉 robot,
with optional HMAC signing), slack (incoming webhook; also Mattermost/Rocket.Chat).
"""
import base64
import hashlib
import hmac
import json
import logging
import smtplib
import sqlite3
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta
from email.message import EmailMessage

from inspector.config import Channel
from inspector.db import from_text, to_text, utcnow

log = logging.getLogger(__name__)
SEVERITY_RANK = {"warning": 1, "critical": 2}
MAX_ATTEMPTS = 6
BASE_BACKOFF_SECONDS = 30


# ------------------------------------------------------------------ formatting
def format_event(event: dict, location: str | None = None, public_url: str = "") -> tuple[str, str]:
    """(subject, body) in plain text; channels add their own markup."""
    target = f" [{event['target']}]" if event.get("target") else ""
    sev = event["severity"].upper()
    if event["event"] == "resolved":
        minutes = max(1, round((from_text(event["resolved_at"]) - from_text(event["opened_at"])).total_seconds() / 60))
        subject = f"[RESOLVED] {event['host']} {event['rule']}{target}"
        lines = [subject, f"Duration: {minutes} min", f"Location: {location or '-'}"]
    else:
        prefix = "[REMINDER] " if event["event"] == "reminder" else ""
        subject = f"{prefix}[{sev}] {event['host']} {event['rule']}{target}"
        lines = [subject, event["summary"], f"Location: {location or '-'}",
                 f"Opened: {event['opened_at']}"]
        if event["event"] == "reminder":
            lines.append("Still open and not acknowledged.")
    if public_url:
        lines.append(f"{public_url.rstrip('/')}/#monitor")
    return subject, "\n".join(lines)


def channel_matches(channel: Channel, event: dict) -> bool:
    if SEVERITY_RANK[event["severity"]] < SEVERITY_RANK[channel.min_severity]:
        return False
    if channel.datacenters and event.get("datacenter") not in channel.datacenters:
        return False
    return True


# ------------------------------------------------------------------ outbox
def enqueue(conn: sqlite3.Connection, events: list[dict], channels: list[Channel],
            location_of=None, now: datetime | None = None, public_url: str = "") -> int:
    now_text = to_text(now or utcnow())
    queued = 0
    for event in events:
        if event.get("silenced"):
            continue
        location = location_of(event["host"]) if location_of else None
        subject, body = format_event(event, location, public_url)
        for channel in channels:
            if channel_matches(channel, event):
                conn.execute(
                    """INSERT INTO outbox (channel, alert_id, event, subject, body, status,
                                           next_attempt_at, created_at)
                       VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)""",
                    (channel.name, event["id"], event["event"], subject, body, now_text, now_text))
                queued += 1
        if event["event"] in ("opened", "reminder"):
            conn.execute("UPDATE alerts SET last_notified_at = ? WHERE id = ?", (now_text, event["id"]))
    return queued


def enqueue_message(conn: sqlite3.Connection, channel: Channel, event: str, subject: str, body: str,
                    now: datetime | None = None) -> None:
    now_text = to_text(now or utcnow())
    conn.execute(
        """INSERT INTO outbox (channel, event, subject, body, status, next_attempt_at, created_at)
           VALUES (?, ?, ?, ?, 'pending', ?, ?)""", (channel.name, event, subject, body, now_text, now_text))


def deliver_pending(conn: sqlite3.Connection, channels: list[Channel], now: datetime | None = None,
                    senders: dict | None = None, limit: int = 50) -> dict:
    """Send due outbox rows. Returns counts. `senders` lets tests inject fakes."""
    now = now or utcnow()
    by_name = {c.name: c for c in channels}
    stats = {"sent": 0, "retry": 0, "failed": 0}
    rows = conn.execute(
        """SELECT * FROM outbox WHERE status = 'pending' AND next_attempt_at <= ?
           ORDER BY id LIMIT ?""", (to_text(now), limit)).fetchall()
    for row in rows:
        channel = by_name.get(row["channel"])
        try:
            if channel is None:
                raise RuntimeError(f"channel {row['channel']!r} no longer configured")
            sender = (senders or {}).get(channel.type) or SENDERS[channel.type]
            sender(channel, row["subject"], row["body"])
        except Exception as exc:
            attempts = row["attempts"] + 1
            if attempts >= MAX_ATTEMPTS or channel is None:
                conn.execute("UPDATE outbox SET status='failed', attempts=?, last_error=? WHERE id=?",
                             (attempts, str(exc)[:500], row["id"]))
                stats["failed"] += 1
                log.error("Notification %s via %s failed permanently: %s", row["id"], row["channel"], exc)
            else:
                delay = BASE_BACKOFF_SECONDS * 2 ** (attempts - 1)
                conn.execute("UPDATE outbox SET attempts=?, last_error=?, next_attempt_at=? WHERE id=?",
                             (attempts, str(exc)[:500], to_text(now + timedelta(seconds=delay)), row["id"]))
                stats["retry"] += 1
                log.warning("Notification %s via %s failed (attempt %d), retry in %ds: %s",
                            row["id"], row["channel"], attempts, delay, exc)
        else:
            conn.execute("UPDATE outbox SET status='sent', attempts=attempts+1, sent_at=? WHERE id=?",
                         (to_text(now), row["id"]))
            stats["sent"] += 1
    return stats


# ------------------------------------------------------------------ senders
def send_email(channel: Channel, subject: str, body: str) -> None:
    s = channel.settings
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = s["from"]
    msg["To"] = ", ".join(s["to"])
    msg.set_content(body)
    port = int(s.get("port", 587))
    smtp_cls = smtplib.SMTP_SSL if s.get("ssl") else smtplib.SMTP
    with smtp_cls(s["host"], port, timeout=10) as smtp:
        if s.get("starttls", not s.get("ssl")) and port != 25:
            smtp.starttls()
        if s.get("username"):
            smtp.login(s["username"], channel.secret("password") or "")
        smtp.send_message(msg)


def send_wecom(channel: Channel, subject: str, body: str) -> None:
    # 企业微信群机器人: https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=...
    payload = {"msgtype": "markdown", "markdown": {"content": _markdown(subject, body)}}
    _check_errcode(_post_json(channel.secret("webhook_url"), payload))


def send_dingtalk(channel: Channel, subject: str, body: str) -> None:
    # 钉钉机器人. If the robot uses "加签", sign = base64(HMAC-SHA256(secret, f"{ts}\n{secret}"))
    url = channel.secret("webhook_url")
    secret = channel.secret("secret")
    if secret:
        ts = str(int(time.time() * 1000))
        digest = hmac.new(secret.encode(), f"{ts}\n{secret}".encode(), hashlib.sha256).digest()
        sign = urllib.parse.quote_plus(base64.b64encode(digest))
        url = f"{url}&timestamp={ts}&sign={sign}"
    payload = {"msgtype": "markdown", "markdown": {"title": subject, "text": _markdown(subject, body)}}
    _check_errcode(_post_json(url, payload))


def send_slack(channel: Channel, subject: str, body: str) -> None:
    _post_json(channel.secret("webhook_url"), {"text": body})


SENDERS = {"email": send_email, "wecom": send_wecom, "dingtalk": send_dingtalk, "slack": send_slack}


def _markdown(subject: str, body: str) -> str:
    lines = body.splitlines()
    return "\n".join([f"**{subject}**"] + [f"> {line}" for line in lines[1:]])


def _post_json(url: str | None, payload: dict, timeout: int = 10) -> dict:
    if not url:
        raise RuntimeError("webhook URL not configured")
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        text = resp.read().decode("utf-8", "replace")
    try:
        return json.loads(text) if text.strip().startswith("{") else {}
    except json.JSONDecodeError:
        return {}


def _check_errcode(response: dict) -> None:
    # WeCom and DingTalk return HTTP 200 with errcode != 0 on failure (bad key, rate limit, ...)
    if response.get("errcode", 0) != 0:
        raise RuntimeError(f"errcode {response.get('errcode')}: {response.get('errmsg')}")
