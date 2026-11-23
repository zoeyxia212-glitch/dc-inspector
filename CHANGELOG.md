# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Personal API tokens for scripts: scoped to a role no higher than the owner's, always expiring,
  revocable, stored hashed, shown once; actions made with a token are audited with its name.
- OpenAPI 3 document at `/api/v1/openapi.json` and interactive docs at `/api/docs`; a contract
  test fails the build if a route is undocumented or a documented route does not exist.
- Structured JSON logs (`LOG_FORMAT=json`), a request ID on every request (`X-Request-ID`,
  propagated from load balancers) in logs and error responses, an access log per request.
- Kubernetes-style health probes: `/health/live` (process) and `/health/ready` (database and
  schema version).
- Security headers (CSP, frame denial, nosniff, no-referrer, HSTS behind TLS) and `no-store` on API
  responses; unhandled errors return a generic message with the request ID.
- Login rate limiting per client address, alongside per-account lockout.
- Kubernetes manifests (`deploy/kubernetes`, kustomize): restricted Pod Security, non-root,
  read-only root filesystem, probes, resource limits, default-deny NetworkPolicies, collector with
  unprivileged ping; static tests keep them consistent with the code.

## [2.1.0] - 2026-11-23

### Added
- Device page joins inventory and monitoring: live status, 24 h trend charts, alert history.
- Rack elevation view (42U) coloured by alert state.
- CMDB sync: validated, all-or-nothing CSV import (dry run by default) and CSV export.
- Rack-aware correlation: several hosts down in one rack raise one `rack_outage` alert naming the
  top-of-rack switch; host alerts are grouped under it.
- Failure diagnosis: SSH error classification plus ping gives `host_down`, `ssh_down`,
  `ssh_auth_failed` or `host_key_changed`.
- SSH connection reuse (OpenSSH ControlMaster): per-host SSH overhead 149 ms → 29 ms (measured).
- Prometheus `/metrics` endpoint for self-monitoring.
- Versioned schema migrations, applied in place on start.
- Online, verified database backups with retention, `verify-backup` restore drill, systemd timer.
- Load test script: 10,000 hosts, ~4,700 host-samples/s.
- Engineering standards: `pyproject.toml`, Ruff lint/format, mypy, coverage gate, CodeQL,
  pip-audit, Dependabot, image scan, release workflow publishing to GHCR with an SBOM,
  SECURITY / CONTRIBUTING / issue and PR templates, pre-commit, Makefile.

### Fixed
- Alerts never resolved when a rule referenced metrics that are absent after recovery: rule
  expressions now use three-valued (SQL-like) logic.
- A too-long SSH control socket path made ssh fail outright; it now falls back to a normal
  connection with a warning.
- CSV export could carry spreadsheet formulas (CSV injection); such cells are neutralised and
  rejected on import.
- Monitoring page ran several queries per host; it now uses a constant number of queries.
- Outbound requests accepted non-http(s) URLs from configuration; only http(s) is allowed now.

## [2.0.0] - 2026-11-18

### Added
- Multi-site architecture: one collector per site with store-and-forward spool, central ingest API
  with per-collector tokens and idempotent writes.
- Expression-based alert rules, centrally defined custom checks, acknowledgement, maintenance
  windows, reminders for unacknowledged critical alerts, outage-aware replay of spooled data.
- `collector_down` and `ingest_stalled` watchdog alerts.
- Email, WeCom, DingTalk (signed) and Slack notifications through a retried outbox.
- Roles (viewer / operator / admin), account lockout, audit log.
- Docker Compose topology with segmented site networks, Ansible roles, systemd units.

## [1.0.0] - 2026-11-18

### Added
- SSH inspection of CPU, memory, disk and services; threshold alerts; daily HTML report;
  device lookup by IP, rack or asset ID with port cabling.

[Unreleased]: https://github.com/zoeyxia212-glitch/dc-inspector/compare/v2.1.0...dev
[2.1.0]: https://github.com/zoeyxia212-glitch/dc-inspector/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/zoeyxia212-glitch/dc-inspector/releases/tag/v2.0.0
