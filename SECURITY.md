# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 2.1.x | yes |
| 2.0.x | security fixes only |
| < 2.0 | no |

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through
[GitHub Security Advisories](https://github.com/zoeyxia212-glitch/dc-inspector/security/advisories/new)
with steps to reproduce and the affected version. You will get an acknowledgement within 5 working
days, and a fix or mitigation plan once the issue is confirmed. Reporters are credited unless they
prefer otherwise.

## Security design

What the project already does, so reports can focus on gaps:

- **Inspected hosts**: agentless, read-only `inspector` account, SSH keys only, `no-pty` /
  no forwarding on the authorised key; host keys pinned with `known_hosts` in production.
- **Remote commands**: service names and mount paths are validated and shell-quoted; custom check
  commands can only be defined in the server config file, never through the UI or API.
- **Central API**: role-based access (viewer / operator / admin), hashed passwords, account lockout,
  generic login errors, JSON-only writes (CSRF), session cookies `HttpOnly` + `SameSite=Lax`
  (+ `Secure` behind TLS). Collector tokens are stored as SHA-256 hashes and can be rotated.
- **API tokens** for scripts: role never above the owner's, mandatory expiry (max 365 days),
  revocable, stored as SHA-256 hashes, cannot be used to mint further tokens.
- **HTTP hardening**: CSP, `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, HSTS behind TLS,
  `no-store` on API responses, generic 500 errors with a request ID, login rate limiting per address.
- **Kubernetes**: restricted Pod Security, non-root, read-only root filesystem, all capabilities
  dropped, default-deny NetworkPolicies.
- **Audit log** of logins, alert acknowledgements, maintenance windows, user and inventory changes.
- **Input handling**: ingest validates every field and rejects future timestamps; CSV import is
  validated and atomic; CSV export neutralises spreadsheet formulas (CSV injection).
- **Outbound requests**: only `http(s)` URLs are allowed for webhooks and the central URL.
- **Supply chain**: CodeQL, pip-audit, Dependabot and an image vulnerability scan run in CI;
  each release publishes an SPDX SBOM.

## Out of scope

Findings that need an already-compromised admin account or physical access to a collector, and
missing hardening on lab-only settings that are documented as such (e.g. `AutoAddPolicy` when no
`known_hosts` file is configured).
