"""Central web service: UI, JSON API for users, and the ingest API for collectors.

Dev:   python -m inspector.main server
Prod:  gunicorn -w 2 -b 0.0.0.0:8000 "inspector.app:create_app()"   (behind a TLS reverse proxy)
"""

import json
import logging
import os
import re
import secrets
import time
import uuid
from datetime import timedelta
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    Response,
    abort,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)

from inspector import __version__, alerts, auth, inventory, lookup, metrics, ops
from inspector.config import DEFAULT_SERVER_CONFIG, REPORT_DIR, ServerSettings, load_server_config
from inspector.db import (
    DEFAULT_DB_PATH,
    SCHEMA_VERSION,
    connect,
    from_text,
    init_schema,
    schema_version,
    to_text,
    transaction,
    utcnow,
)
from inspector.errors import InputError, int_arg
from inspector.ingest import IngestError, ingest
from inspector.logs import request_id_var

log = logging.getLogger(__name__)
access_log = logging.getLogger("inspector.access")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
OPENAPI_PATH = Path(__file__).resolve().parent / "openapi.yaml"
# Inline <script>/<style> are used by the single-page UI, hence 'unsafe-inline' for those two only.
CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)
DOCS_CSP = (
    "default-src 'self'; script-src 'self' https://unpkg.com 'unsafe-inline'; "
    "style-src 'self' https://unpkg.com 'unsafe-inline'; img-src 'self' data: https://unpkg.com; "
    "frame-ancestors 'none'; base-uri 'none'"
)


def create_app(
    db_path=DEFAULT_DB_PATH,
    conn=None,
    settings: ServerSettings | None = None,
    report_dir=REPORT_DIR,
    secret_key: str | None = None,
) -> Flask:
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
    login_limiter = auth.RateLimiter(
        int(os.environ.get("INSPECTOR_LOGIN_LIMIT", 10)), float(os.environ.get("INSPECTOR_LOGIN_WINDOW", 300))
    )

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
        """Session (browser) or personal API token (scripts: Authorization: Bearer dci_...)."""
        if "user" not in g:
            g.user, g.auth_method = None, None
            uid = session.get("uid")
            header = request.headers.get("Authorization", "")
            if uid:
                g.user, g.auth_method = auth.get_user(db(), uid), "session"
            elif header.startswith("Bearer " + auth.API_TOKEN_PREFIX):
                g.user, g.auth_method = auth.user_for_api_token(db(), header[7:]), "token"
        return g.user

    # ------------------------------------------------------------ request lifecycle
    @app.before_request
    def start_request():
        incoming = request.headers.get("X-Request-ID", "")
        g.request_id = incoming if REQUEST_ID_RE.match(incoming) else uuid.uuid4().hex
        g.request_token = request_id_var.set(g.request_id)
        g.started = time.perf_counter()

    @app.after_request
    def finish_request(response):
        response.headers["X-Request-ID"] = g.get("request_id", "")
        response.headers.setdefault("Content-Security-Policy", CSP)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        if app.config["SESSION_COOKIE_SECURE"]:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        user = g.get("user")
        level = logging.DEBUG if request.path.startswith(("/health", "/metrics")) else logging.INFO
        access_log.log(
            level,
            "%s %s %s",
            request.method,
            request.path,
            response.status_code,
            extra={
                "method": request.method,
                "path": request.path,
                "status": response.status_code,
                "duration_ms": round((time.perf_counter() - g.get("started", time.perf_counter())) * 1000, 1),
                "user": user["username"] if user else None,
                "ip": client_ip(),
            },
        )
        return response

    @app.teardown_request
    def end_request(_exc):
        token = g.pop("request_token", None)
        if token is not None:
            request_id_var.reset(token)

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
        if user and user.get("token_name"):
            detail = f"[token {user['token_name']}] {detail}"
        auth.audit(db(), user["username"] if user else None, action, detail, client_ip())

    def body():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            abort(400, "JSON object expected")
        return data

    @app.errorhandler(400)
    def bad_request(exc):
        return jsonify(error=getattr(exc, "description", "Bad request"), request_id=g.get("request_id")), 400

    @app.errorhandler(500)
    def server_error(exc):
        # Details go to the log (with the request ID), never to the client.
        log.error("Unhandled error", exc_info=getattr(exc, "original_exception", exc))
        return jsonify(error="Internal server error", request_id=g.get("request_id")), 500

    # ------------------------------------------------------------ pages / login
    @app.get("/login")
    def login_page():
        return render_template("login.html", error=None)

    @app.post("/login")
    def login():
        username = request.form.get("username", "").strip()
        if not login_limiter.allow(client_ip() or "unknown"):
            auth.audit(db(), username or None, "login_rate_limited", "", client_ip())
            error = "Too many sign-in attempts from your address. Wait a few minutes and try again."
            return render_template("login.html", error=error), 429
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

    # ------------------------------------------------------------ health (Kubernetes probes)
    @app.get("/health/live")
    def health_live():
        """Liveness: the process answers. Never touches dependencies, so a slow DB doesn't cause restarts."""
        return jsonify(status="ok", version=__version__)

    @app.get("/health/ready")
    @app.get("/health")
    def health_ready():
        """Readiness: can serve traffic (database reachable, schema up to date)."""
        checks = {}
        try:
            db().execute("SELECT 1")
            version = schema_version(db())
            checks["database"] = "ok"
            checks["schema"] = "ok" if version == SCHEMA_VERSION else f"version {version}, expected {SCHEMA_VERSION}"
        except Exception as exc:  # report, don't crash, so the probe gets a clear 503
            checks["database"] = f"error: {type(exc).__name__}"
        ready = all(v == "ok" for v in checks.values())
        return jsonify(status="ok" if ready else "unavailable", version=__version__, checks=checks), (
            200 if ready else 503
        )

    # ------------------------------------------------------------ API documentation
    @app.get("/api/v1/openapi.json")
    def openapi_spec():
        import yaml

        spec = yaml.safe_load(OPENAPI_PATH.read_text(encoding="utf-8"))
        spec["info"]["version"] = __version__
        return Response(json.dumps(spec), mimetype="application/json")

    @app.get("/api/docs")
    def api_docs():
        response = Response(render_template("apidocs.html"), mimetype="text/html")
        response.headers["Content-Security-Policy"] = DOCS_CSP
        return response

    # ------------------------------------------------------------ personal API tokens
    @app.get("/api/v1/tokens")
    @require()
    def list_tokens():
        user = current_user()
        everyone = request.args.get("all") == "1" and auth.has_role(user["role"], "admin")
        return jsonify(tokens=auth.list_api_tokens(db(), None if everyone else user["id"]))

    @app.post("/api/v1/tokens")
    @require()
    def create_token():
        if g.auth_method == "token":
            return jsonify(error="Create tokens from a signed-in browser session, not with another token"), 403
        data = body()
        try:
            with transaction(db()):
                created = auth.create_api_token(
                    db(),
                    current_user()["id"],
                    str(data.get("name", "")),
                    data.get("role") if isinstance(data.get("role"), str) else None,
                    int_arg(data.get("expires_days", 90), "expires_days", 1, auth.MAX_TOKEN_DAYS),
                )
                audit("token_create", f"{created['name']} ({created['role']}, expires {created['expires_at']})")
        except (auth.AuthError, InputError) as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(created), 201

    @app.delete("/api/v1/tokens/<int:token_id>")
    @require()
    def revoke_token(token_id):
        user = current_user()
        owner = None if auth.has_role(user["role"], "admin") else user["id"]
        with transaction(db()):
            if not auth.revoke_api_token(db(), token_id, owner):
                return jsonify(error="No active token with that id"), 404
            audit("token_revoke", f"#{token_id}")
        return jsonify(ok=True)

    @app.get("/metrics")
    def prometheus():
        """Self-monitoring for Prometheus. Bearer token if INSPECTOR_METRICS_TOKEN is set, else login."""
        token = os.environ.get("INSPECTOR_METRICS_TOKEN")
        header = request.headers.get("Authorization", "")
        if token:
            if not secrets.compare_digest(header, f"Bearer {token}"):
                return Response("unauthorized\n", status=401, mimetype="text/plain")
        elif current_user() is None:
            return Response("login or INSPECTOR_METRICS_TOKEN required\n", status=401, mimetype="text/plain")
        body_text = ops.prometheus_metrics(
            db(), settings.collector_stale_seconds, None if conn is not None else db_path
        )
        return Response(body_text, mimetype="text/plain; version=0.0.4")

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
        c = db()
        device = lookup.get_device_detail(c, asset_id)
        if device is None:
            return jsonify(error=f"Device {asset_id} not found"), 404
        snap = metrics.latest(c, settings.interval_seconds * 3, host=device["hostname"])
        device["monitoring"] = {
            "latest": snap[0] if snap else None,
            "alerts": [
                dict(r)
                for r in c.execute(
                    """SELECT id, rule, target, severity, summary, status, opened_at, resolved_at, acked_by, silenced
                   FROM alerts WHERE host = ? ORDER BY status = 'resolved', opened_at DESC LIMIT 20""",
                    (device["hostname"],),
                )
            ],
        }
        return jsonify(device)

    @app.get("/api/v1/racks/<code>")
    @require()
    def rack_view(code):
        rack = inventory.rack_elevation(db(), code)
        if rack is None:
            return jsonify(error=f"Rack {code} not found"), 404
        return jsonify(rack)

    @app.get("/api/v1/inventory/export.csv")
    @require()
    def export_inventory():
        audit("inventory_export")
        return Response(
            inventory.export_csv(db()),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=inventory.csv"},
        )

    @app.post("/api/v1/inventory/import")
    @require("admin")
    def import_inventory():
        data = body()
        text, dry_run = data.get("csv"), bool(data.get("dry_run", True))
        if not isinstance(text, str) or not text.strip():
            return jsonify(error="csv text is required"), 400
        result = inventory.import_csv(db(), text, dry_run=dry_run)
        if result.ok and not dry_run:
            audit(
                "inventory_import", f"created {result.created}, updated {result.updated}, unchanged {result.unchanged}"
            )
        return jsonify(result.to_dict()), (200 if result.ok else 422)

    # ------------------------------------------------------------ monitoring
    @app.get("/api/v1/hosts")
    @require()
    def host_status():
        hosts = metrics.latest(db(), settings.interval_seconds * 3)
        return jsonify(count=len(hosts), hosts=hosts)

    @app.get("/api/v1/hosts/<host>/history")
    @require()
    def host_history(host):
        keys = [k for k in request.args.get("keys", "cpu.percent,mem.percent").split(",") if k]
        try:
            hours = int_arg(request.args.get("hours", 24), "hours", 1, 744)
            series = metrics.history(db(), host, keys, hours)
        except InputError as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(host=host, hours=hours, series=series)

    @app.get("/api/v1/alerts")
    @require()
    def list_alerts():
        status = request.args.get("status", "open")
        if status not in ("open", "resolved", "all"):
            return jsonify(error="status must be open, resolved or all"), 400
        where, params = ("", ()) if status == "all" else ("WHERE status = ?", (status,))
        c = db()
        rows = [
            dict(r)
            for r in c.execute(
                f"""SELECT * FROM alerts {where}
                ORDER BY status = 'resolved', acked_at IS NOT NULL,
                         CASE severity WHEN 'critical' THEN 0 ELSE 1 END, opened_at DESC
                LIMIT 300""",
                params,
            )
        ]
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
        rows = [
            dict(r) | {"active": r["starts_at"] <= now < r["ends_at"]}
            for r in db().execute("SELECT * FROM silences WHERE ends_at > ? ORDER BY starts_at", (now,))
        ]
        return jsonify(silences=rows)

    @app.post("/api/v1/silences")
    @require("operator")
    def create_silence():
        data = body()
        try:
            try:
                starts = from_text(str(data["starts_at"])) if data.get("starts_at") else utcnow()
            except ValueError:
                raise InputError("starts_at must look like 2026-11-23T01:00:00Z") from None
            ends = starts + timedelta(minutes=int_arg(data.get("duration_minutes"), "duration_minutes", 1, 43200))
            with transaction(db()):
                sid = alerts.add_silence(
                    db(),
                    str(data.get("host_pattern", "")),
                    str(data.get("rule_pattern", "*")),
                    starts,
                    ends,
                    str(data.get("reason", "")),
                    current_user()["username"],
                )
                audit(
                    "silence_create",
                    f"#{sid} {data.get('host_pattern')} {data.get('rule_pattern', '*')} "
                    f"{data.get('duration_minutes')}min: {data.get('reason')}",
                )
        except InputError as exc:
            return jsonify(error=f"Invalid silence: {exc}"), 400
        return jsonify(id=sid), 201

    @app.delete("/api/v1/silences/<int:silence_id>")
    @require("operator")
    def end_silence(silence_id):
        with transaction(db()):
            cur = db().execute(
                "UPDATE silences SET ends_at = ? WHERE id = ? AND ends_at > ?",
                (to_text(utcnow()), silence_id, to_text(utcnow())),
            )
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
        rows = [
            dict(r)
            for r in db().execute(
                "SELECT username, role, active, locked_until, created_at, last_login_at FROM users ORDER BY username"
            )
        ]
        return jsonify(users=rows)

    @app.post("/api/v1/users")
    @require("admin")
    def create_user():
        data = body()
        try:
            with transaction(db()):
                auth.create_user(
                    db(), str(data.get("username", "")), str(data.get("password", "")), str(data.get("role", "viewer"))
                )
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
                auth.update_user(
                    db(),
                    username,
                    role=data.get("role"),
                    active=data.get("active") if isinstance(data.get("active"), bool) else None,
                    password=data.get("password"),
                )
                changes = ", ".join(f"{k}={'***' if k == 'password' else v}" for k, v in data.items())
                audit("user_update", f"{username}: {changes}")
        except auth.AuthError as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(ok=True)

    @app.get("/api/v1/collectors")
    @require()
    def list_collectors():
        stale_before = to_text(utcnow() - timedelta(seconds=settings.collector_stale_seconds))
        rows = [
            dict(r) | {"healthy": bool(r["last_seen_at"] and r["last_seen_at"] >= stale_before)}
            for r in db().execute(
                "SELECT name, created_at, last_seen_at, last_ip, version, host_count, spooled "
                "FROM collectors ORDER BY name"
            )
        ]
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
