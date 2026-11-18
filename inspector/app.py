"""Central web service: UI, JSON API for users, and the ingest API for collectors.

Dev:   python -m inspector.main server
Prod:  gunicorn -w 2 -b 0.0.0.0:8000 "inspector.app:create_app()"   (behind a TLS reverse proxy)
"""
import logging
import os
import secrets
from datetime import timedelta
from functools import wraps
from pathlib import Path

from flask import (Flask, abort, g, jsonify, redirect, render_template, request,
                   send_from_directory, session, url_for)

from inspector import __version__, alerts, auth, lookup
from inspector.config import DEFAULT_SERVER_CONFIG, REPORT_DIR, ServerSettings, load_server_config
from inspector.db import DEFAULT_DB_PATH, connect, from_text, init_schema, to_text, transaction, utcnow
from inspector.ingest import IngestError, ingest

log = logging.getLogger(__name__)


def create_app(db_path=DEFAULT_DB_PATH, conn=None, settings: ServerSettings | None = None,
               report_dir=REPORT_DIR, secret_key: str | None = None) -> Flask:
    app = Flask(__name__)
    settings = settings or load_server_config(DEFAULT_SERVER_CONFIG)
    report_dir = Path(report_dir)

    secret_key = secret_key or os.environ.get("INSPECTOR_SECRET_KEY")
    if not secret_key:
        log.warning("INSPECTOR_SECRET_KEY not set: using a random key (sessions end on restart)")
        secret_key = secrets.token_hex(32)
    app.config.update(
        SECRET_KEY=secret_key,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("INSPECTOR_SECURE_COOKIES", "0") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        MAX_CONTENT_LENGTH=8 * 1024 * 1024,
    )

    if conn is None:
        c = connect(db_path)
        init_schema(c)
        c.close()

    def db():
        if conn is not None:
            return conn
        if "conn" not in g:
            g.conn = connect(db_path)
        return g.conn

    @app.teardown_appcontext
    def close_db(_exc):
        c = g.pop("conn", None)
        if c is not None:
            c.close()

    def client_ip():
        return request.headers.get("X-Real-IP") or request.remote_addr

    def current_user():
        if "user" not in g:
            uid = session.get("uid")
            g.user = auth.get_user(db(), uid) if uid else None
        return g.user

    def require(role="viewer"):
        def deco(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                user = current_user()
                if user is None:
                    if request.path.startswith("/api/"):
                        return jsonify(error="Login required"), 401
                    return redirect(url_for("login_page"))
                if not auth.has_role(user["role"], role):
                    return jsonify(error=f"Requires role {role}"), 403
                if request.method in ("POST", "PATCH", "DELETE") and not request.is_json:
                    # JSON-only writes: a cross-site HTML form cannot send application/json (CSRF protection)
                    return jsonify(error="Content-Type must be application/json"), 415
                return fn(*args, **kwargs)
            return wrapper
        return deco

    def audit(action, detail=""):
        user = current_user()
        auth.audit(db(), user["username"] if user else None, action, detail, client_ip())

    def body():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            abort(400, "JSON object expected")
        return data

    @app.errorhandler(400)
    def bad_request(exc):
        return jsonify(error=getattr(exc, "description", "Bad request")), 400

    # ------------------------------------------------------------ pages / login
    @app.get("/login")
    def login_page():
        return render_template("login.html", error=None)

    @app.post("/login")
    def login():
        username = request.form.get("username", "").strip()
        try:
            # autocommit (no transaction): the failed-attempt counter must persist when this raises
            user = auth.authenticate(db(), username, request.form.get("password", ""))
        except auth.AuthError as exc:
            auth.audit(db(), username or None, "login_failed", str(exc), client_ip())
            return render_template("login.html", error=str(exc)), 401
        auth.audit(db(), username, "login", "", client_ip())
        session.clear()
        session.permanent = True
        session["uid"] = user["id"]
        return redirect(url_for("index"))

    @app.post("/logout")
    def logout():
        if current_user():
            audit("logout")
        session.clear()
        return redirect(url_for("login_page"))

    @app.get("/")
    @require()
    def index():
        return render_template("index.html", user=current_user(), version=__version__)

    @app.get("/health")
    def health():
        db().execute("SELECT 1")
        return jsonify(status="ok", version=__version__)

    @app.get("/api/v1/me")
    @require()
    def me():
        return jsonify(current_user())

    # ------------------------------------------------------------ device lookup
    @app.get("/api/v1/devices")
    @require()
    def search_devices():
        query = request.args.get("q", "").strip()
        if not query:
            return jsonify(error="Missing search term 'q'"), 400
        try:
            results = lookup.search(db(), query)
        except lookup.InvalidQuery as exc:
            return jsonify(error=str(exc)), 400
        audit("device_search", query)
        return jsonify(query=query, count=len(results), devices=results)

    @app.get("/api/v1/devices/<asset_id>")
    @require()
    def device_detail(asset_id):
        device = lookup.get_device_detail(db(), asset_id)
        if device is None:
            return jsonify(error=f"Device {asset_id} not found"), 404
        return jsonify(device)

    # ------------------------------------------------------------ monitoring
    @app.get("/api/v1/hosts")
    @require()
    def host_status():
        c = db()
        stale_before = to_text(utcnow() - timedelta(seconds=settings.interval_seconds * 3))
        rows = c.execute(
            """SELECT s.* FROM samples s
               JOIN (SELECT host, MAX(collected_at) AS t FROM samples GROUP BY host) latest
                 ON latest.host = s.host AND latest.t = s.collected_at
               ORDER BY s.host""").fetchall()
        open_counts = {r["host"]: r["n"] for r in c.execute(
            "SELECT host, COUNT(*) AS n FROM alerts WHERE status = 'open' GROUP BY host")}
        hosts = []
        for row in rows:
            values = {v["key"]: (v["num"] if v["num"] is not None else v["text"]) for v in c.execute(
                "SELECT key, num, text FROM sample_values WHERE sample_id = ?", (row["id"],))}
            hosts.append({
                "host": row["host"], "datacenter": row["datacenter"], "collector": row["collector"],
                "collected_at": row["collected_at"], "up": bool(row["up"]), "error": row["error"],
                "stale": row["collected_at"] < stale_before,
                "cpu": values.get("cpu.percent"), "mem": values.get("mem.percent"),
                "load_per_core": values.get("load.per_core"),
                "disks": {k[5:-8]: v for k, v in values.items() if k.startswith("disk.") and k.endswith(".percent")
                          and not k.endswith(".inode_percent")},
                "services_down": sorted(k[8:-3] for k, v in values.items()
                                        if k.startswith("service.") and k.endswith(".up") and v == 0),
                "checks": {k[6:]: v for k, v in values.items() if k.startswith("check.")},
                "open_alerts": open_counts.get(row["host"], 0),
                "location": lookup.get_location(c, row["host"]),
            })
        return jsonify(count=len(hosts), hosts=hosts)

    @app.get("/api/v1/alerts")
    @require()
    def list_alerts():
        status = request.args.get("status", "open")
        if status not in ("open", "resolved", "all"):
            return jsonify(error="status must be open, resolved or all"), 400
        where, params = ("", ()) if status == "all" else ("WHERE status = ?", (status,))
        c = db()
        rows = [dict(r) for r in c.execute(
            f"""SELECT * FROM alerts {where}
                ORDER BY status = 'resolved', acked_at IS NOT NULL,
                         CASE severity WHEN 'critical' THEN 0 ELSE 1 END, opened_at DESC
                LIMIT 300""", params)]
        for r in rows:
            r["location"] = lookup.get_location(c, r["host"])
        return jsonify(count=len(rows), alerts=rows)

    @app.post("/api/v1/alerts/<int:alert_id>/ack")
    @require("operator")
    def ack_alert(alert_id):
        note = str(body().get("note", ""))
        with transaction(db()):
            if not alerts.acknowledge(db(), alert_id, current_user()["username"], note):
                return jsonify(error="Alert not found, not open, or already acknowledged"), 409
            audit("alert_ack", f"alert {alert_id}: {note}")
        return jsonify(ok=True)

    @app.get("/api/v1/silences")
    @require()
    def list_silences():
        now = to_text(utcnow())
        rows = [dict(r) | {"active": r["starts_at"] <= now < r["ends_at"]} for r in db().execute(
            "SELECT * FROM silences WHERE ends_at > ? ORDER BY starts_at", (now,))]
        return jsonify(silences=rows)

    @app.post("/api/v1/silences")
    @require("operator")
    def create_silence():
        data = body()
        try:
            starts = from_text(data["starts_at"]) if data.get("starts_at") else utcnow()
            ends = starts + timedelta(minutes=int(data["duration_minutes"]))
            with transaction(db()):
                sid = alerts.add_silence(db(), str(data.get("host_pattern", "")), str(data.get("rule_pattern", "*")),
                                         starts, ends, str(data.get("reason", "")), current_user()["username"])
                audit("silence_create", f"#{sid} {data.get('host_pattern')} {data.get('rule_pattern', '*')} "
                                        f"{data.get('duration_minutes')}min: {data.get('reason')}")
        except (KeyError, ValueError, TypeError) as exc:
            return jsonify(error=f"Invalid silence: {exc}"), 400
        return jsonify(id=sid), 201

    @app.delete("/api/v1/silences/<int:silence_id>")
    @require("operator")
    def end_silence(silence_id):
        with transaction(db()):
            cur = db().execute("UPDATE silences SET ends_at = ? WHERE id = ? AND ends_at > ?",
                               (to_text(utcnow()), silence_id, to_text(utcnow())))
            if cur.rowcount == 0:
                return jsonify(error="No active or upcoming silence with that id"), 404
            audit("silence_end", f"#{silence_id}")
        return jsonify(ok=True)

    # ------------------------------------------------------------ reports
    @app.get("/api/v1/reports")
    @require()
    def list_reports():
        files = sorted(report_dir.glob("*.html"), reverse=True) if report_dir.exists() else []
        return jsonify(reports=[f.name for f in files])

    @app.get("/reports/<path:name>")
    @require()
    def get_report(name):
        if not name.endswith(".html") or "/" in name or "\\" in name:
            abort(404)
        return send_from_directory(report_dir, name)

    # ------------------------------------------------------------ admin
    @app.get("/api/v1/users")
    @require("admin")
    def list_users():
        rows = [dict(r) for r in db().execute(
            "SELECT username, role, active, locked_until, created_at, last_login_at FROM users ORDER BY username")]
        return jsonify(users=rows)

    @app.post("/api/v1/users")
    @require("admin")
    def create_user():
        data = body()
        try:
            with transaction(db()):
                auth.create_user(db(), str(data.get("username", "")), str(data.get("password", "")),
                                 str(data.get("role", "viewer")))
                audit("user_create", f"{data.get('username')} as {data.get('role', 'viewer')}")
        except auth.AuthError as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(ok=True), 201

    @app.patch("/api/v1/users/<username>")
    @require("admin")
    def update_user(username):
        data = body()
        try:
            with transaction(db()):
                auth.update_user(db(), username, role=data.get("role"),
                                 active=data.get("active") if isinstance(data.get("active"), bool) else None,
                                 password=data.get("password"))
                changes = ", ".join(f"{k}={'***' if k == 'password' else v}" for k, v in data.items())
                audit("user_update", f"{username}: {changes}")
        except auth.AuthError as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(ok=True)

    @app.get("/api/v1/collectors")
    @require()
    def list_collectors():
        stale_before = to_text(utcnow() - timedelta(seconds=settings.collector_stale_seconds))
        rows = [dict(r) | {"healthy": bool(r["last_seen_at"] and r["last_seen_at"] >= stale_before)}
                for r in db().execute(
                    "SELECT name, created_at, last_seen_at, last_ip, version, host_count, spooled FROM collectors ORDER BY name")]
        return jsonify(collectors=rows)

    @app.get("/api/v1/audit")
    @require("admin")
    def audit_log():
        limit = min(int(request.args.get("limit", 200)), 1000)
        rows = [dict(r) for r in db().execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))]
        return jsonify(entries=rows)

    # ------------------------------------------------------------ collector API (token auth)
    def collector_name():
        header = request.headers.get("Authorization", "")
        token = header[7:] if header.startswith("Bearer ") else None
        return auth.collector_for_token(db(), token)

    @app.get("/api/v1/collector/config")
    def collector_config():
        name = collector_name()
        if not name:
            return jsonify(error="Invalid collector token"), 401
        return jsonify(settings.collector_config())

    @app.post("/api/v1/ingest")
    def ingest_samples():
        name = collector_name()
        if not name:
            return jsonify(error="Invalid collector token"), 401
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict):
            return jsonify(error="JSON object expected"), 400
        try:
            result = ingest(db(), settings, name, payload)
        except IngestError as exc:
            return jsonify(error=str(exc)), 400
        db().execute("UPDATE collectors SET last_ip = ? WHERE name = ?", (client_ip(), name))
        return jsonify(result)

    return app
